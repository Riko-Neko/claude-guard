#!/usr/bin/env python3
"""Claude Guard: explicit safe entry, pinned upstream, inherited socket restriction.

Does not replace Claude, change Clash, decrypt TLS, or auto-enrol a new IP/node.
"""
import argparse
import base64
import contextlib
import datetime
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import selectors
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import traceback
import threading
import time
import urllib.parse
from collections import deque
import email.utils

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import system_filter
import environment_checks
RUNTIME = ROOT / "runtime"


class GuardError(Exception):
    pass

class TunRequired(GuardError):
    pass

class NetworkChanged(GuardError):
    pass

class ConnectivityError(GuardError):
    pass

class ApprovalRequired(GuardError):
    pass

def transient_error(error):
    return isinstance(error, (NetworkChanged, ConnectivityError, TunRequired,
                              OSError, http.client.HTTPException, subprocess.TimeoutExpired))

def enhanced(settings):
    return settings.get('protection_mode', 'enhanced') != 'proxy'


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=2)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def controller(settings, endpoint):
    conn = UnixHTTP(settings["controller_socket"])
    try:
        conn.request("GET", "/" + endpoint)
        r = conn.getresponse()
        if r.status != 200:
            raise ConnectivityError("Clash 本地接口不可用")
        return json.load(r)
    finally:
        conn.close()


def node_digest(node):
    return hashlib.sha256(json.dumps(node, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def selected_node(settings):
    # Ruby reads YAML without exposing credentials in command arguments or logs.
    code = ("require 'yaml';require 'json';c=YAML.load_file(ARGV[0]);"
            "p=c.fetch('proxies').find{|p|p['name']==ARGV[1]};abort('missing') unless p;puts JSON.generate(p)")
    r = subprocess.run(["/usr/bin/ruby", "-e", code, settings["source_config"], settings["expected_node"]],
                       capture_output=True, text=True, timeout=5)
    if r.returncode:
        raise GuardError("无法读取已批准节点；未启动 Claude")
    node = json.loads(r.stdout)
    if node_digest(node) != settings["node_sha256"]:
        raise ApprovalRequired("节点参数已改变，需要重新核验，不能自动批准")
    return node


def check_controller(settings):
    config = controller(settings, "configs")
    proxies = controller(settings, "proxies").get("proxies", {})
    if config.get("mode") != "rule":
        raise GuardError("Clash 不在规则模式")
    if not config.get("tun", {}).get("enable") and not settings.get('allow_system_proxy', False):
        raise TunRequired("TUN 未开启；如需仅使用系统代理，必须在向导中明确放行。")
    if proxies.get(settings.get("proxy_group", "AI"), {}).get("now") != settings["expected_node"]:
        raise GuardError("AI 组已切换，已关闭受保护连接")
    if config.get("mixed-port") != settings["base_proxy_port"]:
        raise GuardError("Clash 本地端口改变")
    return True


def sandbox_profile(port):
    # 'localhost' is the supported Seatbelt syntax, covering v4 and v6 loopback.
    # No other outbound sockets, UDP, DNS or Unix network sockets are allowed.
    return (f'(version 1)\n(allow default)\n(deny network*)\n'
            f'(allow network-outbound (remote tcp "localhost:{int(port)}"))\n'
            '(allow network-bind (local ip "localhost:*"))\n'
            '(allow network-inbound (local ip "localhost:*"))\n')


def running_claude():
    r = subprocess.run(["/bin/ps", "-axo", "pid=,comm="], capture_output=True, text=True, timeout=3)
    found = []
    for line in r.stdout.splitlines():
        row = line.strip().split(None, 1)
        if len(row) != 2:
            continue
        path = row[1]
        if ("/Claude.app/" in path or "/Claude/claude-code/" in path
                or Path(path).name == "claude"):
            found.append(int(row[0]))
    return found


def read_header(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        block = sock.recv(4096)
        if not block:
            raise GuardError("代理连接提前结束")
        data.extend(block)
        if len(data) > 65536:
            raise GuardError("代理请求头过长")
    header, rest = bytes(data).split(b"\r\n\r\n", 1)
    return header, rest


def authority(value):
    if value.startswith("["):
        match = re.fullmatch(r"\[([0-9a-fA-F:]+)\]:(\d+)", value)
    else:
        match = re.fullmatch(r"([a-zA-Z0-9._-]+):(\d+)", value)
    if not match or not 1 <= int(match[2]) <= 65535:
        raise GuardError("目标地址格式不受支持")
    return match[1].rstrip(".").lower(), int(match[2])


def public_target(host):
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return bool(re.fullmatch(r"[a-z0-9][a-z0-9._-]*", host))


class Gate:
    def __init__(self):
        self.lock = threading.RLock()
        self.enabled = False
        self.tripped = False
        self.revision = 0
        self.reason = "尚未检查通过"
        self.sockets = set()

    def open(self):
        with self.lock:
            if self.tripped:
                raise GuardError("连接已因异常锁闭，必须结束会话并重新检查")
            self.enabled = True
            self.reason = ""

    def add(self, sock):
        with self.lock:
            if not self.enabled:
                raise GuardError("网络闸门关闭")
            self.sockets.add(sock)

    def remove(self, sock):
        with self.lock:
            self.sockets.discard(sock)

    def close(self, reason):
        with self.lock:
            self.enabled = False
            self.reason = reason
            for sock in list(self.sockets):
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
            self.sockets.clear()

    def trip(self, reason):
        # Invalidating a preflight cannot be undone by a delayed successful probe.
        with self.lock:
            self.revision += 1
            self.tripped = True
            self.close(reason)

    def checkpoint(self):
        with self.lock:
            return self.revision

    def reopen(self, revision):
        # Only the explicit recovery path calls this after all baseline checks.
        # A new sleep/network event invalidates any in-flight successful probe.
        signals = {signal.SIGUSR1, signal.SIGUSR2, signal.SIGTERM, signal.SIGINT}
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            with self.lock:
                if revision != self.revision:
                    raise NetworkChanged('复查期间网络状态发生变化，请稍后重新检查。')
                self.tripped = False
                self.open()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, upstream, authorization, gate, emit, ssh_targets=None, port=0):
        self.upstream = upstream
        self.authorization = authorization
        self.gate = gate
        self.emit = emit
        self.ssh_targets = ssh_targets or {}
        super().__init__(("127.0.0.1", int(port)), ProxyHandler)


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client = self.request
        upstream = None
        established = False
        try:
            self.server.gate.add(client)
            client.settimeout(4)
            header, pending = read_header(client)
            lines = header.split(b"\r\n")
            method, target, version = lines[0].decode("ascii").split(" ")
            if version not in ("HTTP/1.0", "HTTP/1.1"):
                raise GuardError("不支持的代理协议")
            if method != "CONNECT":
                url = urllib.parse.urlsplit(target)
                host, port = (url.hostname or '').rstrip('.').lower(), url.port or 80
                if (url.scheme != 'http' or url.username or url.password or not public_target(host)
                        or method not in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS')):
                    raise GuardError("网页请求目标未获批准")
                upstream = socket.create_connection(self.server.upstream, 3)
                self.server.gate.add(upstream)
                kept = [line for line in lines[1:] if not line.lower().startswith((b'proxy-authorization:', b'proxy-connection:'))]
                request = b'\r\n'.join([lines[0], *kept,
                    ('Proxy-Authorization: Basic ' + self.server.authorization).encode()]) + b'\r\n\r\n'
                upstream.sendall(request)
                established = True
                self.server.emit("CONNECTION", host=host, port=port, route="pinned_node_http")
            else:
                host, port = authority(target)
            if method == 'CONNECT' and port == 22 and host in self.server.ssh_targets:
                upstream = socket.create_connection((self.server.ssh_targets[host], 22), 3)
                self.server.gate.add(upstream)
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                established = True
                self.server.emit("CONNECTION", host=host, port=port, route="approved_sdc_ssh")
            elif method == 'CONNECT':
                if not public_target(host):
                    raise GuardError("本机或私网目标未获批准")
                upstream = socket.create_connection(self.server.upstream, 3)
                self.server.gate.add(upstream)
                upstream.settimeout(5)
                request = (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                           f"Proxy-Authorization: Basic {self.server.authorization}\r\n\r\n").encode("ascii")
                upstream.sendall(request)
                response, extra = read_header(upstream)
                if response.split(b"\r\n", 1)[0].split(b" ")[1:2] != [b"200"]:
                    raise GuardError("已批准上游连接失败，不回退直连")
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + extra)
                established = True
                self.server.emit("CONNECTION", host=host, port=port, route="pinned_node")
            if pending:
                upstream.sendall(pending)
            client.settimeout(None)
            upstream.settimeout(None)
            with selectors.DefaultSelector() as selection:
                selection.register(client, selectors.EVENT_READ, upstream)
                selection.register(upstream, selectors.EVENT_READ, client)
                while self.server.gate.enabled:
                    for key, _ in selection.select(.5):
                        block = key.fileobj.recv(65536)
                        if not block:
                            return
                        key.data.sendall(block)
        except (OSError, ValueError, GuardError, IndexError):
            if not established:
                with contextlib.suppress(OSError):
                    client.sendall(b"HTTP/1.1 503 Guard blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    self.server.gate.remove(sock)
                    with contextlib.suppress(OSError):
                        sock.close()


class Session:
    def __init__(self, settings, event_callback=None):
        self.settings = settings
        self.gate = Gate()
        self.temp = None
        self.core = None
        self.proxy = None
        self.child = None
        self.core_port = None
        self.auth = None
        self.stop = threading.Event()
        self.failed = False
        self.callback = event_callback
        self.log = None
        self.lock = threading.RLock()
        self.probe_lock = threading.Lock()
        self.connection_times = deque()
        self.audit_warnings = set()
        self.clock_skew = None
        self.audit_stop = threading.Event()
        self.audit_wake = threading.Event()
        self.audit_thread = None
        self.resume_requested = threading.Event()
        self.auto_retry = False
        self.next_retry = 0
        self.approval_required = False

    def emit(self, kind, **fields):
        row = {"time": datetime.datetime.now().astimezone().isoformat(), "kind": kind, **fields}
        with self.lock:
            if kind == 'CONNECTION':
                self.connection_times.append(time.monotonic())
            if self.log:
                self.log.write(json.dumps(row, ensure_ascii=False) + "\n")
            if self.callback:
                self.callback(row)
            print(json.dumps(row, ensure_ascii=False), flush=True)

    def fail(self, reason, recoverable=False):
        # Close first. Only transient faults may retry the approved baseline.
        self.gate.trip(reason)
        self.auto_retry = recoverable and not self.approval_required and not self.stop.is_set()
        self.next_retry = time.monotonic() + 5
        if not self.failed:
            self.failed = True
            active = self.child is not None and self.child.poll() is None
            self.emit("BLOCKED" if active else "CHECK_FAILED", message=reason)

    def open_log(self):
        os.umask(0o077)
        RUNTIME.mkdir(parents=True, exist_ok=True)
        if self.log is None:
            self.log = (RUNTIME / (datetime.datetime.now().strftime("%Y%m%d-%H%M%S") + ".jsonl")).open("a", buffering=1)

    def start(self, create_gateway=True):
        self.open_log()
        check_controller(self.settings)
        node = selected_node(self.settings)
        self.temp = tempfile.TemporaryDirectory(prefix="claude-guard-")
        temp = Path(self.temp.name)
        for key in ("interface-name", "routing-mark", "dialer-proxy"):
            node.pop(key, None)
        node["name"] = "ApprovedNode"
        node["dialer-proxy"] = "LocalClash"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.core_port = sock.getsockname()[1]
        user, password = secrets.token_hex(8), secrets.token_hex(24)
        self.auth = base64.b64encode((user + ":" + password).encode()).decode()
        config = {"mixed-port": self.core_port, "allow-lan": False,
                  "bind-address": "127.0.0.1", "mode": "rule", "log-level": "silent",
                  "ipv6": True, "authentication": [user + ":" + password],
                  "proxies": [node, {"name": "LocalClash", "type": "http", "server": "127.0.0.1",
                                     "port": self.settings["base_proxy_port"]}],
                  "rules": ["MATCH,ApprovedNode"]}
        config_path = temp / "core.json"
        config_path.write_text(json.dumps(config))
        self.core = subprocess.Popen([self.settings["core_executable"], "-d", str(temp), "-f", str(config_path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.core.poll() is not None:
                raise GuardError("专用出口核心未能启动")
            try:
                with socket.create_connection(("127.0.0.1", self.core_port), .1):
                    break
            except OSError:
                time.sleep(.1)
        else:
            raise GuardError("专用出口核心启动超时")
        if create_gateway:
            self.proxy = Proxy(("127.0.0.1", self.core_port), self.auth, self.gate, self.emit,
                               port=self.settings.get('gateway_port', 0))
            threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        # The UI/app cannot use this path until both checks have passed.
        self.check_egress()
        check_controller(self.settings)
        self.gate.open()
        self.emit("PREFLIGHT_OK", ip=self.settings["expected_ip"], country=self.settings["expected_country"])

    def resolve_ssh_targets(self):
        approved = {}
        for name in self.settings.get("allow_local_ssh_hosts", []):
            try:
                result = subprocess.run(["/usr/bin/ssh", "-G", name], capture_output=True, text=True, timeout=2)
                host = next(line.split(" ", 1)[1] for line in result.stdout.splitlines() if line.startswith("hostname "))
                for address in socket.getaddrinfo(host, 22, type=socket.SOCK_STREAM):
                    ip = ipaddress.ip_address(address[4][0])
                    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
                        approved[host.lower()] = str(ip)
                        approved[name.lower()] = str(ip)
                        approved[str(ip)] = str(ip)
                        break
            except (OSError, StopIteration, ValueError, subprocess.TimeoutExpired):
                continue
        return approved

    def check_egress(self):
        with self.probe_lock:
            conn = http.client.HTTPSConnection("127.0.0.1", self.core_port, timeout=8,
                                               context=ssl.create_default_context())
            conn.set_tunnel("www.cloudflare.com", 443,
                            {"Proxy-Authorization": "Basic " + self.auth})
            try:
                sent_at=time.time()
                conn.request("GET", "/cdn-cgi/trace", headers={"Host": "www.cloudflare.com"})
                response = conn.getresponse()
                date=response.getheader('Date')
                if date:
                    try:self.clock_skew=email.utils.parsedate_to_datetime(date).timestamp()-(sent_at+time.time())/2
                    except (ValueError, TypeError, OverflowError):pass
                if response.status != 200:
                    raise ConnectivityError("出口探测服务未返回有效结果")
                data = response.read(16384).decode("ascii")
                trace = dict(line.split("=", 1) for line in data.splitlines() if "=" in line)
                try:
                    ipaddress.ip_address(trace.get('ip', ''))
                    if not re.fullmatch(r'[A-Z]{2}', trace.get('loc', '')):
                        raise ValueError('invalid country')
                except ValueError:
                    raise ConnectivityError('出口探测服务未返回有效结果')
                if (trace.get("ip") != self.settings["expected_ip"]
                        or trace.get("loc") != self.settings["expected_country"]):
                    self.approval_required = True
                    self.auto_retry = False
                    self.gate.trip('出口发生变化，等待人为批准')
                    self.emit('IP_CHANGED',ip=trace.get('ip'),country=trace.get('loc'),message='出口发生变化，受控连接已关闭。请退出 Claude，在向导中重新核验并明确批准。')
                    raise ApprovalRequired("出口不一致：检测到 " + str(trace.get("ip")) + " (" + str(trace.get("loc")) + ")；请重新核验并批准。")
                self.emit("EGRESS_OK", ip=trace["ip"], country=trace["loc"])
            finally:
                conn.close()

    def audit_environment(self):
        current=environment_checks.snapshot(self.settings.get('claude_app','/Applications/Claude.app'))
        config=controller(self.settings,'configs')
        with self.lock:
            now=time.monotonic()
            while self.connection_times and self.connection_times[0]<now-60:self.connection_times.popleft()
            count=len(self.connection_times)
        checks=environment_checks.evaluate(self.settings,current,config,self.clock_skew,count)
        environment_checks.write_report(RUNTIME/'environment-report.json',checks)
        present=set()
        for check in checks:
            if check['status']=='warning':
                key=(check['id'],check['message']);present.add(key)
                if key not in self.audit_warnings:
                    self.emit('ENVIRONMENT_WARNING',check=check['id'],message=check['message'])
        self.audit_warnings=present

    def start_audits(self):
        def worker():
            while not self.audit_stop.is_set():
                if self.failed:return
                try:self.audit_environment()
                except Exception:
                    environment_checks.write_report(RUNTIME/'environment-report.json',[{'id':'availability','status':'unverified','message':'本次环境检查未完成，不能沿用上次结果判断安全。'}])
                    self.emit('ENVIRONMENT_WARNING',check='availability',message='环境检查未完成，请查看检查结果；未将其视为通过。')
                self.audit_wake.wait(max(15,self.settings.get('environment_check_seconds',3600)))
                self.audit_wake.clear()
        self.audit_thread=threading.Thread(target=worker,daemon=True)
        self.audit_thread.start()

    def launch(self):
        if self.settings.get("protected_launch_enabled") is not True:
            raise GuardError("受控启动尚未启用")
        if enhanced(self.settings):
            try: self.filter_pid = system_filter.inspect(self.settings)
            except (OSError, ValueError, system_filter.FilterError) as exc: raise GuardError(str(exc))
        if not self.gate.enabled or self.failed:
            raise GuardError("代理检查未通过，未启动 Claude")
        if running_claude():
            raise GuardError("Claude 已从其他入口运行；请先完全退出再使用受控启动")
        app = Path(self.settings['claude_app'])
        info = plistlib.loads((app/'Contents/Info.plist').read_bytes())
        executable = app/'Contents/MacOS'/info['CFBundleExecutable']
        result = subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],capture_output=True,timeout=20)
        if result.returncode: raise GuardError('Claude 程序签名检查失败')
        if not self.gate.enabled or self.failed: raise GuardError('启动检查期间网络发生变化')
        proxy_url = 'http://127.0.0.1:' + str(self.proxy.server_address[1])
        env = os.environ.copy()
        for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):env[key]=proxy_url
        env['NO_PROXY']=env['no_proxy']='localhost,.localhost,127.0.0.1,127.0.0.0/8,0.0.0.0,::1,[::1],::,[::]'
        # Keep PATH, SSH_AUTH_SOCK and all SSH/browser configuration unchanged.
        args=[str(executable),'--proxy-server='+proxy_url,'--disable-quic']
        self.child=subprocess.Popen(args,env=env,start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.emit('RUNNING',message='指定代理出口已接入；不审查工具调用，不修改 SSH 或浏览器',pid=self.child.pid)

    def request_stop(self):
        # End the backend and release its session lock, even if Claude survives.
        # Its old proxy stays disconnected. Never terminate Claude or its tools.
        self.gate.trip('受控代理已关闭')
        self.auto_retry = False
        self.stop.set()

    def resume(self, automatic=False):
        if not self.failed or self.stop.is_set():
            return
        revision = self.gate.checkpoint()
        self.emit('RESUMING', message='正在重新检查连接，检查完成前保持暂停。', automatic=automatic)
        try:
            if self.approval_required:
                raise ApprovalRequired('出口或节点曾发生变化，请退出 Claude，重新核验并批准后再启动。')
            if self.child is None or self.child.poll() is not None:
                raise GuardError('Claude 已退出，请重新启动。')
            if self.core is None or self.core.poll() is not None:
                raise GuardError('连接服务已停止，请退出 Claude 后重新启动。')
            check_controller(self.settings)
            selected_node(self.settings)
            if enhanced(self.settings):
                system_filter.inspect(self.settings, self.filter_pid)
            self.check_egress()
            check_controller(self.settings)
            if self.stop.is_set():
                raise GuardError('连接恢复已取消。')
            self.gate.reopen(revision)
            self.failed = False
            self.auto_retry = False
            if self.audit_thread is not None and not self.audit_thread.is_alive():
                self.start_audits()
            self.audit_wake.set()
            self.emit('RESUMED', message='连接复查已通过，Claude 连接已恢复。', automatic=automatic)
        except Exception as exc:
            self.gate.trip('连接复查未通过')
            self.failed = True
            if isinstance(exc, ApprovalRequired):
                self.approval_required = True
            self.auto_retry = self.auto_retry and transient_error(exc) and not self.approval_required and not self.stop.is_set()
            self.next_retry = time.monotonic() + 5
            reason = str(exc) if isinstance(exc, (GuardError, system_filter.FilterError)) else 'VPN 连接复查未完成，请确认网络稳定后重试。'
            self.emit('RESUME_FAILED', message=reason, error_type=type(exc).__name__, automatic=automatic,
                      retrying=self.auto_retry)

    def watch(self, network_event=None):
        last_probe = time.monotonic()
        while not self.stop.wait(self.settings.get("health_interval_seconds", 1)):
            if self.child and self.child.poll() is not None:
                # Child helpers may still exist. Close their proxy too.
                self.gate.close("应用已退出")
                if self.child.returncode != 0:
                    self.fail("Claude 已异常退出；可能存在严格模式兼容性问题，保护未放宽")
                    return
                self.emit("IDLE", message="Claude 已退出，停止网络探测")
                return
            try:
                ui_pid = os.environ.get("CLAUDE_GUARD_UI_PID")
                if ui_pid:
                    try:
                        os.kill(int(ui_pid), 0)
                    except (OSError, ValueError):
                        self.request_stop()
                        self.emit('SESSION_ENDED', message='Guard 已退出，连接服务已结束。')
                        return
                if self.failed:
                    manual = self.resume_requested.is_set()
                    if manual or (self.auto_retry and time.monotonic() >= self.next_retry):
                        self.resume_requested.clear()
                        if network_event:
                            network_event.clear()
                        self.resume(automatic=not manual)
                        last_probe = time.monotonic()
                    continue
                if self.core.poll() is not None:
                    raise GuardError("专用出口进程停止")
                check_controller(self.settings)
                if hasattr(self, 'filter_pid'):
                    system_filter.inspect(self.settings, self.filter_pid)
                changed = bool(network_event and network_event.is_set())
                if changed:
                    network_event.clear()
                    # Close existing streams before revalidating a network change.
                    # Retry after a delay, with the gate closed through all checks.
                    reason = '电脑睡眠或唤醒' if '睡眠' in self.gate.reason else '系统网络发生切换'
                    raise NetworkChanged(reason + '，连接已暂停；网络恢复并通过复查后将自动恢复。')
                if time.monotonic() - last_probe >= self.settings.get("probe_interval_seconds", 5):
                    selected_node(self.settings)
                    self.check_egress()
                    last_probe = time.monotonic()
            except Exception as exc:
                self.emit('HEALTH_FAILED', error_type=type(exc).__name__)
                if isinstance(exc, ApprovalRequired):
                    self.approval_required = True
                recoverable = transient_error(exc)
                reason = str(exc) if isinstance(exc, GuardError) else '网络检查失败或超时，连接已暂停。'
                if recoverable and not isinstance(exc, NetworkChanged):
                    reason += ' 网络恢复并通过复查后将自动恢复。'
                self.fail(reason, recoverable=recoverable)

    def close(self):
        self.audit_stop.set()
        self.audit_wake.set()
        if self.audit_thread:self.audit_thread.join(timeout=12)
        self.stop.set()
        self.gate.close("Guard 已结束")
        if self.proxy:
            self.proxy.shutdown()
            self.proxy.server_close()
        if self.core and self.core.poll() is None:
            self.core.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.core.wait(3)
            if self.core.poll() is None:
                self.core.kill()
                self.core.wait()
        if self.temp:
            self.temp.cleanup()
        if self.log:
            self.log.close()
            self.log = None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["check", "launch"])
    parser.add_argument('--protection', choices=['proxy', 'enhanced'])
    args = parser.parse_args()
    os.umask(0o077)
    RUNTIME.mkdir(parents=True, exist_ok=True)
    lock = (RUNTIME / "session.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        print(json.dumps({"kind": "BLOCKED", "message": "另一个 Guard 会话正在运行"}, ensure_ascii=False), flush=True)
        return 1
    settings = json.loads((ROOT / "settings.json").read_text())
    if args.protection:
        settings['protection_mode'] = args.protection
    session = Session(settings)
    network_event = threading.Event()
    def network_changed(*_):
        session.gate.trip("系统网络发生变化")
        network_event.set()
    signal.signal(signal.SIGUSR1, network_changed)
    def power_changed(*_):
        session.gate.trip("电脑睡眠或唤醒")
        network_event.set()
    signal.signal(signal.SIGUSR2, power_changed)
    def dns_changed(*_):
        # DNS observations warn; unlike a route change, they do not close the gate.
        session.audit_wake.set()
    signal.signal(signal.SIGURG, dns_changed)
    def end(*_):
        session.request_stop()
    signal.signal(signal.SIGHUP, lambda *_: session.resume_requested.set())
    signal.signal(signal.SIGTERM, end)
    signal.signal(signal.SIGINT, end)
    try:
        session.open_log()
        if args.action == 'launch' and running_claude():
            raise GuardError('Claude 或 Claude Code 仍在运行。请完全退出后，再从 Guard 启动；重启 Guard 不会接管已有连接。')
        if args.action == 'launch' and enhanced(settings):
            try: session.filter_pid = system_filter.wait_ready(settings)
            except (OSError, ValueError, system_filter.FilterError) as exc: raise GuardError(str(exc))
        session.start(create_gateway=args.action == 'launch')
        session.start_audits()
        if args.action == "check":
            session.emit("CHECK_COMPLETE", message="仅检查完成，没有启动 Claude")
            return 0
        if network_event.is_set() or session.stop.is_set():
            raise GuardError("检查期间系统状态改变，禁止启动")
        session.launch()
        session.watch(network_event)
        return 1 if session.failed else 0
    except Exception as exc:
        # Record location and exception class without credentials or request data.
        frames=[{"file":Path(frame.filename).name,"line":frame.lineno,"function":frame.name}
                for frame in traceback.extract_tb(exc.__traceback__)]
        session.emit("CHECK_ERROR", error_type=type(exc).__name__, frames=frames)
        if isinstance(exc, GuardError):reason=str(exc)
        elif isinstance(exc, TimeoutError):reason="VPN 连接检查超时，请确认节点可用后重新检查。"
        elif isinstance(exc, (OSError, http.client.HTTPException)):
            reason="VPN 连接检查未完成，请检查当前节点后重试。"
        else:reason="连接检查遇到错误，请从菜单查看日志后重试。"
        session.fail(reason)
        return 1
    finally:
        try:
            session.close()
        finally:
            lock.close()


if __name__ == "__main__":
    raise SystemExit(main())
