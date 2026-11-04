"""Authenticated local transport over macOS networking; no VPN-client dependency."""
import contextlib
import hmac
import ipaddress
import re
import selectors
import socket
import socketserver
import struct
import subprocess
import threading
import urllib.parse


def current_path():
    result = subprocess.run(['/usr/sbin/scutil', '--proxy'], capture_output=True, text=True, timeout=5)
    if result.returncode or '<dictionary>' not in result.stdout:
        raise OSError('无法读取系统网络配置，请重试。')
    values = dict(re.findall(r'^\s*(\w+)\s*:\s*(.*?)\s*$', result.stdout, re.M))
    if any(values.get(k) == '1' for k in ('ProxyAutoConfigEnable', 'ProxyAutoDiscoveryEnable')):
        raise ValueError('当前使用自动代理脚本。请在系统或代理工具中选择明确的 HTTP／SOCKS5 代理，或使用系统 VPN 连接，再重新检测。')
    for prefix, kind in (('HTTPS', 'http'), ('HTTP', 'http'), ('SOCKS', 'socks5')):
        if values.get(prefix + 'Enable') == '1':
            host = values.get(prefix + 'Proxy', '')
            port = int(values.get(prefix + 'Port', '0'))
            if not host or not 1 <= port <= 65535:
                raise ValueError('系统代理地址无效，请检查网络设置。')
            return dict(kind=kind, host=host, port=port)
    return dict(kind='system')


def exact(sock, count):
    data = b''
    while len(data) < count:
        block = sock.recv(count - len(data))
        if not block:
            raise OSError('代理连接提前结束')
        data += block
    return data


def connect(path, host, port):
    import guard
    if path['kind'] == 'system':
        return socket.create_connection((host, port), 5)
    sock = socket.create_connection((path['host'], path['port']), 5)
    try:
        if path['kind'] == 'http':
            target = ('[' + host + ']' if ':' in host else host) + ':' + str(port)
            sock.sendall(('CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\n\r\n').encode('ascii'))
            header, extra = guard.read_header(sock)
            if header.split(b'\r\n', 1)[0].split(b' ')[1:2] != [b'200'] or extra:
                raise OSError('系统 HTTP 代理未接受连接；未改用直连。')
        elif path['kind'] == 'socks5':
            sock.sendall(b'\x05\x01\x00')
            if exact(sock, 2) != b'\x05\x00':
                raise OSError('SOCKS5 代理需要额外认证或未接受连接；未改用直连。')
            try:
                address = ipaddress.ip_address(host)
                encoded = bytes([1 if address.version == 4 else 4]) + address.packed
            except ValueError:
                name = host.encode('idna')
                if len(name) > 255:
                    raise ValueError('目标地址过长')
                encoded = b'\x03' + bytes([len(name)]) + name
            sock.sendall(b'\x05\x01\x00' + encoded + struct.pack('!H', port))
            reply = exact(sock, 4)
            if reply[:3] != b'\x05\x00\x00':
                raise OSError('SOCKS5 代理未接受连接；未改用直连。')
            sizes = {1: 4, 4: 16}
            length = exact(sock, 1)[0] if reply[3] == 3 else sizes.get(reply[3])
            if length is None:
                raise OSError('SOCKS5 返回格式无效')
            exact(sock, length + 2)
        else:
            raise ValueError('未知网络路径')
        return sock
    except Exception:
        sock.close()
        raise


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        import guard
        upstream = None
        established = False
        with self.server.lock:
            if self.server.closed:
                return
            self.server.sockets.add(self.request)
        try:
            self.request.settimeout(5)
            header, pending = guard.read_header(self.request)
            lines = header.split(b'\r\n')
            method, target, version = lines[0].decode('ascii').split(' ')
            credentials = [line.split(b':', 1)[1].strip() for line in lines[1:] if line.lower().startswith(b'proxy-authorization:')]
            if len(credentials) != 1 or not hmac.compare_digest(credentials[0], ('Basic '+self.server.authorization).encode()):
                raise OSError('本地代理认证未通过')
            if method == 'CONNECT':
                host, port = guard.authority(target)
            else:
                url = urllib.parse.urlsplit(target)
                if url.scheme != 'http' or url.username or url.password:
                    raise ValueError('无效网页代理请求')
                host, port = url.hostname, url.port or 80
            if not host or not guard.public_target(host):
                raise ValueError('目标未获批准')
            upstream = connect(self.server.path, host, port)
            with self.server.lock:
                if self.server.closed:
                    raise OSError('连接服务已停止')
                self.server.sockets.add(upstream)
            if method == 'CONNECT':
                self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            else:
                relative = urllib.parse.urlunsplit(('', '', url.path or '/', url.query, ''))
                kept = [line for line in lines[1:] if line and not line.lower().startswith((b'proxy-authorization:', b'proxy-connection:'))]
                upstream.sendall(b'\r\n'.join([(method+' '+relative+' '+version).encode(), *kept])+b'\r\n\r\n')
            established = True
            if pending:
                upstream.sendall(pending)
            upstream.settimeout(None)
            self.request.settimeout(None)
            with selectors.DefaultSelector() as selector:
                selector.register(self.request, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, self.request)
                while not self.server.closed:
                    for key, _ in selector.select(.5):
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        key.data.sendall(data)
        except (OSError, ValueError, guard.GuardError, IndexError):
            if not established:
                with contextlib.suppress(OSError):
                    self.request.sendall(b'HTTP/1.1 503 Guard blocked\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
        finally:
            for sock in (self.request, upstream):
                if sock:
                    with self.server.lock:
                        self.server.sockets.discard(sock)
                    with contextlib.suppress(OSError):
                        sock.close()


class Transport(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(self, path, authorization):
        self.path = dict(path)
        self.authorization = authorization
        self.lock = threading.Lock()
        self.sockets = set()
        self.closed = False
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def poll(self):
        return 0 if self.closed or not self.thread.is_alive() else None

    def terminate(self):
        self.closed = True
        with self.lock:
            for sock in list(self.sockets):
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
        self.shutdown()
        self.server_close()

    def wait(self, timeout=None):
        self.thread.join(timeout)
        return 0

    kill = terminate
