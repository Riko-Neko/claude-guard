"""Local fakes only; never contacts a public host or launches Claude."""
import base64
from pathlib import Path
import socket
import socketserver
import sys
import threading
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'tools'))
import guard
import network_transport as nt
import configure_vpn


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(4096)
            if not data:return
            self.request.sendall(data)


class NetworkTransportTests(unittest.TestCase):
    def test_detection_without_clash_and_proxy_precedence(self):
        for text,expected in [('<dictionary> {}',{'kind':'system'}),
             ('<dictionary> {\nHTTPSEnable : 1\nHTTPSProxy : 127.0.0.1\nHTTPSPort : 8080\n}',{'kind':'http','host':'127.0.0.1','port':8080}),
             ('<dictionary> {\nSOCKSEnable : 1\nSOCKSProxy : localhost\nSOCKSPort : 1080\n}',{'kind':'socks5','host':'localhost','port':1080})]:
            with mock.patch.object(nt.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=text)):
                self.assertEqual(nt.current_path(),expected)
        with mock.patch.object(nt.subprocess,'run',return_value=mock.Mock(returncode=0,stdout='<dictionary> {\nProxyAutoConfigEnable : 1\n}')):
            with self.assertRaises(ValueError):nt.current_path()

    def test_generic_discovery_does_not_touch_clash_or_save(self):
        session=mock.Mock();session.detected={'ip':'1.1.1.1','loc':'JP'}
        with mock.patch.object(guard,'running_claude',return_value=[]),mock.patch.object(nt,'current_path',return_value={'kind':'system'}),mock.patch.object(guard,'controller',side_effect=AssertionError('Clash accessed')),mock.patch.object(configure_vpn,'DiscoverySession',return_value=session),mock.patch.object(configure_vpn.environment_checks,'snapshot',return_value={}):
            settings=configure_vpn.detect()
        self.assertEqual(settings['transport_kind'],'system');self.assertEqual(settings['expected_ip'],'1.1.1.1')
        self.assertNotIn('core_executable',settings);self.assertFalse(settings['protected_launch_enabled'])

    def test_pinned_system_proxy_failure_never_retries_direct(self):
        sock=mock.Mock();sock.recv.return_value=b'HTTP/1.1 407 Denied\r\n\r\n'
        with mock.patch.object(nt.socket,'create_connection',return_value=sock) as dial:
            with self.assertRaises(OSError):nt.connect({'kind':'http','host':'proxy.test','port':8080},'api.test',443)
            dial.assert_called_once_with(('proxy.test',8080),5)
            sock.close.assert_called_once()

    def test_system_path_uses_os_route_and_changed_proxy_is_not_silently_accepted(self):
        with mock.patch.object(nt.socket,'create_connection') as dial:
            nt.connect({'kind':'system'},'api.example.test',443)
            dial.assert_called_once_with(('api.example.test',443),5)
        with mock.patch.object(nt,'current_path',return_value={'kind':'http','host':'localhost','port':8080}),mock.patch.object(guard,'controller',side_effect=AssertionError('Clash accessed')):
            with self.assertRaises(guard.NetworkChanged):
                guard.check_controller({'transport_kind':'system','network_path':{'kind':'system'}})

    def test_generic_status_has_no_clash_or_tun_requirement(self):
        import network_status
        with mock.patch.object(guard,'controller',side_effect=AssertionError('Clash accessed')):
            report=network_status.read_status({'transport_kind':'system'})
        self.assertEqual(report['transport_kind'],'system')
        self.assertIsNone(report['tun'])

    def test_socks5_remote_dns_and_rejected_auth(self):
        sock=mock.Mock();sock.recv.side_effect=[b'\x05\x00',b'\x05\x00\x00\x01',b'\x00'*6]
        with mock.patch.object(nt.socket,'create_connection',return_value=sock):
            self.assertIs(nt.connect({'kind':'socks5','host':'proxy.test','port':1080},'api.test',443),sock)
        self.assertEqual(sock.sendall.call_args_list[1].args[0],b'\x05\x01\x00\x03\x08api.test\x01\xbb')
        sock=mock.Mock();sock.recv.return_value=b'\x05\x02'
        with mock.patch.object(nt.socket,'create_connection',return_value=sock) as dial:
            with self.assertRaises(OSError):nt.connect({'kind':'socks5','host':'proxy.test','port':1080},'api.test',443)
            self.assertEqual(dial.call_count,1)

    def test_local_relay_authentication_forwarding_and_gate_disconnect(self):
        echo=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo);echo.daemon_threads=True
        threading.Thread(target=echo.serve_forever,daemon=True).start()
        transport=nt.Transport({'kind':'system'},'fixture')
        gate=guard.Gate();gate.open()
        proxy=guard.Proxy(transport.server_address,'fixture',gate,lambda *a,**k:None)
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        try:
            with mock.patch.object(nt,'connect',side_effect=lambda *a:socket.create_connection(echo.server_address,2)) as dial:
                client=socket.create_connection(proxy.server_address,2);client.settimeout(2)
                client.sendall(b'CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test\r\n\r\n')
                self.assertIn(b'200',guard.read_header(client)[0]);client.sendall(b'opaque TLS fixture');self.assertEqual(client.recv(1024),b'opaque TLS fixture')
                gate.trip('fixture route change');self.assertEqual(client.recv(1024),b'');client.close()
                bad=socket.create_connection(transport.server_address,2);bad.settimeout(2)
                bad.sendall(b'CONNECT api.example.test:443 HTTP/1.1\r\n\r\n');self.assertIn(b'503',bad.recv(1024));bad.close()
                self.assertEqual(dial.call_count,1)
        finally:
            gate.close('finished');proxy.shutdown();proxy.server_close();transport.terminate();echo.shutdown();echo.server_close()

    def test_session_uses_own_transport_and_verifies_egress_before_open(self):
        settings={'transport_kind':'system','network_path':{'kind':'system'},'expected_ip':'1.1.1.1','expected_country':'JP'}
        session=guard.Session(settings);session.open_log=mock.Mock();session.emit=mock.Mock()
        with mock.patch.object(nt,'current_path',return_value={'kind':'system'}),mock.patch.object(session,'check_egress',side_effect=lambda:self.assertFalse(session.gate.enabled)),mock.patch.object(guard,'controller',side_effect=AssertionError('Clash accessed')),mock.patch.object(guard.subprocess,'Popen',side_effect=AssertionError('External core launched')):
            try:
                session.start(create_gateway=False);self.assertTrue(session.gate.enabled);self.assertTrue(session.domain_route())
            finally:session.close()
        session=guard.Session(settings);session.open_log=mock.Mock();session.emit=mock.Mock()
        with mock.patch.object(nt,'current_path',return_value={'kind':'system'}),mock.patch.object(session,'check_egress',side_effect=guard.ApprovalRequired('changed')):
            try:
                with self.assertRaises(guard.ApprovalRequired):session.start(False)
                self.assertFalse(session.gate.enabled)
            finally:session.close()


if __name__=='__main__':unittest.main()
