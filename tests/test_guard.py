"""All services are local fakes. This suite never launches Claude."""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("guard", ROOT / "src/guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.calls += 1
        header, pending = guard.read_header(self.request)
        self.server.headers.append(header)
        self.request.sendall(b"HTTP/1.1 200 OK\r\n\r\n" + pending)
        while True:
            try:
                block = self.request.recv(4096)
                if not block:
                    return
                self.request.sendall(block)
            except OSError:
                return


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    def __init__(self):
        super().__init__(("127.0.0.1", 0), EchoHandler)
        self.calls = 0
        self.headers = []
        self.lock = threading.Lock()


class ProxyTests(unittest.TestCase):
    def setUp(self):
        self.fake = EchoServer()
        threading.Thread(target=self.fake.serve_forever, daemon=True).start()
        self.gate = guard.Gate()
        self.events = []
        self.proxy = guard.Proxy(self.fake.server_address, "TEST_ONLY_CREDENTIAL", self.gate,
                                 lambda k, **v: self.events.append((k, v)))
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.clients = []

    def tearDown(self):
        self.gate.close("test finished")
        for client in self.clients:
            client.close()
        self.proxy.shutdown(); self.proxy.server_close()
        self.fake.shutdown(); self.fake.server_close()

    def connect(self, target="api.example.test:443", extra=b""):
        client = socket.create_connection(self.proxy.server_address, 2)
        client.settimeout(2)
        self.clients.append(client)
        client.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode() + extra)
        return client

    def test_closed_gate_never_contacts_upstream(self):
        client = self.connect()
        self.assertIn(b"503", client.recv(4096))
        self.assertEqual(self.fake.calls, 0)

    def test_open_gate_relays_opaque_bytes_to_only_fixed_upstream(self):
        self.gate.open()
        client = self.connect()
        self.assertIn(b"200", guard.read_header(client)[0])
        client.sendall(b"opaque-test-bytes")
        self.assertEqual(client.recv(4096), b"opaque-test-bytes")
        self.assertIn(b"Proxy-Authorization: Basic TEST_ONLY_CREDENTIAL", self.fake.headers[0])
        self.assertEqual(self.events[0][1]["route"], "pinned_node")

    def test_trip_closes_existing_tunnel_and_rejects_next(self):
        self.gate.open()
        client = self.connect()
        self.assertIn(b"200", guard.read_header(client)[0])
        self.gate.close("simulated failed check")
        self.assertEqual(client.recv(4096), b"")
        next_client = self.connect()
        self.assertIn(b"503", next_client.recv(4096))
        self.assertEqual(self.fake.calls, 1)

    def test_upstream_unavailable_does_not_try_target_directly(self):
        self.gate.open()
        self.proxy.upstream = ("127.0.0.1", 1)
        client = self.connect()
        self.assertIn(b"503", client.recv(4096))
        self.assertEqual(self.fake.calls, 0)

    def test_private_and_controller_targets_rejected(self):
        self.gate.open()
        for target in ["127.0.0.1:7897", "localhost:7897", "[::1]:7897", "10.0.0.1:443"]:
            with self.subTest(target=target):
                self.assertIn(b"503", self.connect(target).recv(4096))
        self.assertEqual(self.fake.calls, 0)

    def test_public_http_web_fetch_uses_only_fixed_upstream(self):
        self.gate.open()
        client = socket.create_connection(self.proxy.server_address, 2)
        self.clients.append(client)
        client.sendall(b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
        self.assertIn(b"200", client.recv(4096))
        self.assertEqual(self.fake.calls, 1)
        self.assertTrue(self.fake.headers[0].startswith(b'GET http://example.test/'))
        self.assertIn(b'Proxy-Authorization: Basic TEST_ONLY_CREDENTIAL', self.fake.headers[0])

    def test_http_private_destination_still_rejected_by_proxy(self):
        self.gate.open()
        client = socket.create_connection(self.proxy.server_address, 2)
        self.clients.append(client)
        client.sendall(b'GET http://127.0.0.1:7897/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')
        self.assertIn(b'503', client.recv(4096))
        self.assertEqual(self.fake.calls, 0)

    def test_approved_sdc_ssh_uses_only_pinned_tailscale_address(self):
        self.gate.open()
        self.proxy.ssh_targets = {"lab-host": "100.64.0.10"}
        client = socket.create_connection(self.proxy.server_address, 2)
        self.clients.append(client)
        local, peer = socket.socketpair()
        try:
            with mock.patch.object(guard.socket, "create_connection", return_value=local) as connect:
                client.sendall(b"CONNECT lab-host:22 HTTP/1.1\r\nHost: lab-host:22\r\n\r\n")
                self.assertIn(b"200", guard.read_header(client)[0])
                connect.assert_called_once_with(("100.64.0.10", 22), 3)
                client.sendall(b"SSH-2.0-harmless-test\r\n")
                peer.settimeout(2)
                self.assertEqual(peer.recv(4096), b"SSH-2.0-harmless-test\r\n")
            self.assertEqual(self.fake.calls, 0)
            self.assertEqual(self.events[0][1]["route"], "approved_sdc_ssh")
        finally:
            self.gate.close("test finished")
            peer.close()

    def test_failed_state_never_auto_reopens(self):
        session = guard.Session({})
        session.gate = self.gate
        session.gate.open()
        session.fail("simulated anomaly")
        self.assertTrue(session.failed)
        self.assertFalse(session.gate.enabled)
        self.assertIn(b"503", self.connect().recv(4096))

    def test_invalidated_preflight_cannot_reopen_gate_on_late_success(self):
        session = guard.Session({})
        session.gate = self.gate
        # A sleep/network event can arrive while an egress check is in flight.
        session.fail("simulated sleep during preflight")
        with self.assertRaises(guard.GuardError):
            session.gate.open()
        self.assertIn(b"503", self.connect().recv(4096))
        self.assertEqual(self.fake.calls, 0)


class StateTests(unittest.TestCase):
    def setUp(self):
        self.settings = {"expected_node": "approved", "base_proxy_port": 7897}

    def check_with(self, config, selection):
        with mock.patch.object(guard, "controller", side_effect=[config, {"proxies": {"AI": {"now": selection}}}]):
            return guard.check_controller(self.settings)

    def test_good_state_and_bad_tun_mode_node(self):
        good = {"mode": "rule", "tun": {"enable": True}, "mixed-port": 7897}
        self.assertTrue(self.check_with(good, "approved"))
        for config, node in [({**good, "mode": "global"}, "approved"),
                             ({**good, "tun": {"enable": False}}, "approved"), (good, "other")]:
            with self.assertRaises(guard.GuardError):
                self.check_with(config, node)

    def test_unapproved_node_parameters_fail(self):
        settings = {"source_config": "FAKE", "expected_node": "approved", "node_sha256": "bad"}
        with mock.patch.object(guard.subprocess, "run", return_value=mock.Mock(returncode=0, stdout='{"name":"approved"}')):
            with self.assertRaises(guard.GuardError):
                guard.selected_node(settings)

    def test_closed_session_cannot_launch(self):
        session = guard.Session({})
        with mock.patch.object(guard.subprocess, "Popen") as launch:
            with self.assertRaises(guard.GuardError):
                session.launch()
            launch.assert_not_called()

    def test_disabled_protected_launch_never_spawns_claude_even_with_open_gate(self):
        session = guard.Session({"protected_launch_enabled": False})
        session.gate.open()
        with mock.patch.object(guard.subprocess, "Popen") as launch:
            with self.assertRaises(guard.GuardError):
                session.launch()
            launch.assert_not_called()

    def test_unverified_system_filter_never_falls_back_to_old_launcher(self):
        session = guard.Session({"protected_launch_enabled": True,
                                 "requested_protection_backend": "system_network_filter"})
        session.gate.open()
        with mock.patch.object(guard.subprocess, "Popen") as launch:
            with self.assertRaises(guard.GuardError):
                session.launch()
            launch.assert_not_called()

    def test_egress_change_is_not_auto_approved(self):
        session = guard.Session({"expected_ip": "192.0.2.1", "expected_country": "TW"}, lambda *_: None)
        session.core_port = 12345; session.auth = "TEST"
        connection = mock.Mock()
        connection.getresponse.return_value.status = 200
        connection.getresponse.return_value.read.return_value = b"ip=192.0.2.2\nloc=TW\n"
        with mock.patch.object(guard.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaises(guard.GuardError):
                session.check_egress()
        self.assertFalse(session.gate.enabled)

    def test_network_change_closes_gate_and_latches(self):
        session = guard.Session({"health_interval_seconds": .01, "probe_interval_seconds": 60})
        session.core = mock.Mock(); session.core.poll.return_value = None
        session.gate.open()
        event = threading.Event(); event.set()
        with mock.patch.object(guard, "check_controller", return_value=True):
            thread = threading.Thread(target=session.watch, args=(event,))
            thread.start()
            for _ in range(100):
                if session.failed: break
                time.sleep(.01)
            session.stop.set(); thread.join(2)
        self.assertTrue(session.failed)
        self.assertFalse(session.gate.enabled)

    def test_child_crash_is_reported_as_blocked_not_successful_exit(self):
        session = guard.Session({"health_interval_seconds": .001})
        session.child = mock.Mock(returncode=65)
        session.child.poll.return_value = 65
        session.gate.open()
        session.watch()
        self.assertTrue(session.failed)
        self.assertFalse(session.gate.enabled)


class NativeRestrictionTests(unittest.TestCase):
    """Use real system enforcement against harmless local socket probes."""
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="guard-native-test-")
        p = Path(cls.temp.name)
        code = r'''#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
int main(int c,char**v){if(!strcmp(v[1],"child")){pid_t p=fork();if(p==0){execl(v[0],v[0],"tcp4",v[2],NULL);_exit(98);}int status;waitpid(p,&status,0);return WEXITSTATUS(status);}
int type=!strcmp(v[1],"udp")?SOCK_DGRAM:SOCK_STREAM;
int af=!strcmp(v[1],"tcp6")?AF_INET6:(!strcmp(v[1],"unix")?AF_UNIX:AF_INET);
int s=socket(af,type,0);int r=-1;
if(af==AF_UNIX){struct sockaddr_un a={0};a.sun_family=AF_UNIX;strncpy(a.sun_path,v[2],sizeof(a.sun_path)-1);r=connect(s,(void*)&a,sizeof(a));}
else if(af==AF_INET6){struct sockaddr_in6 a={0};a.sin6_family=AF_INET6;a.sin6_port=htons(atoi(v[2]));inet_pton(AF_INET6,"::1",&a.sin6_addr);r=connect(s,(void*)&a,sizeof(a));}
else{struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(atoi(v[2]));inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);r=type==SOCK_DGRAM?sendto(s,"test",4,0,(void*)&a,sizeof(a)):connect(s,(void*)&a,sizeof(a));}
close(s);return r>=0?0:13;}'''
        (p / "probe.c").write_text(code)
        cls.probe = p / "probe"
        subprocess.run(["/usr/bin/cc", str(p / "probe.c"), "-o", str(cls.probe)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_allowed_gateway_and_denied_tcp_ipv6_udp_unix_and_descendant(self):
        sockets = []
        def listener(af=socket.AF_INET, kind=socket.SOCK_STREAM):
            s = socket.socket(af, kind); sockets.append(s)
            s.bind(("::1" if af==socket.AF_INET6 else "127.0.0.1", 0))
            if kind==socket.SOCK_STREAM:s.listen(8)
            return s.getsockname()[1]
        approved, other = listener(), listener()
        ipv6, udp = listener(socket.AF_INET6), listener(kind=socket.SOCK_DGRAM)
        unix = socket.socket(socket.AF_UNIX); sockets.append(unix)
        path = str(Path(self.temp.name) / "controller.sock")
        unix.bind(path); unix.listen(8)
        profile = guard.sandbox_profile(approved)
        try:
            tests = [("tcp4", str(approved), 0), ("tcp4", str(other), 13),
                     ("tcp6", str(ipv6), 13), ("udp", str(udp), 13),
                     ("unix", path, 13), ("child", str(other), 13)]
            for kind, target, expected in tests:
                with self.subTest(kind=kind, target=target):
                    result = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile,
                                             str(self.probe), kind, target], capture_output=True, timeout=3)
                    self.assertEqual(result.returncode, expected, result.stderr.decode())
        finally:
            for sock in sockets:sock.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
