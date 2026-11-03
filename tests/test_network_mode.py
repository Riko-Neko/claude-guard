"""Local mode observations and warning-only runtime TUN policy; no real network."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'tools'))
import guard
import environment_checks as env
import network_status

class NetworkModeTests(unittest.TestCase):
    def setUp(self):
        self.settings={'base_proxy_port':7897,'expected_node':'fixture','expected_ip':'8.8.8.8','expected_country':'TW'}
        self.config={'mode':'rule','tun':{'enable':False},'mixed-port':7897}
        self.groups={'proxies':{'AI':{'now':'fixture'}}}

    def test_tun_change_does_not_block_runtime_or_require_saved_override(self):
        session=guard.Session(self.settings);session.gate.open()
        with mock.patch.object(guard,'controller',side_effect=[self.config,self.groups]):
            guard.check_controller(self.settings)
        self.assertTrue(session.gate.enabled)
        self.assertFalse(session.failed)

    def test_other_controller_failures_still_block(self):
        for config,groups in [({**self.config,'mode':'direct'},self.groups),({**self.config,'mixed-port':9999},self.groups),(self.config,{'proxies':{'AI':{'now':'other'}}})]:
            with self.subTest(config=config,groups=groups),mock.patch.object(guard,'controller',side_effect=[config,groups]):
                with self.assertRaises(guard.GuardError):guard.check_controller(self.settings)

    def test_tun_change_publishes_status_without_touching_gate_or_client(self):
        session=guard.Session(self.settings);session.gate.open();session.emit=mock.Mock()
        with mock.patch.object(guard,'controller',side_effect=[{**self.config,'tun':{'enable':True}},self.groups,self.config,self.groups]),mock.patch.object(guard.subprocess,'Popen') as launch:
            session.check_config();session.check_config()
        self.assertTrue(session.gate.enabled);self.assertFalse(session.failed);launch.assert_not_called()
        self.assertEqual([call.kwargs['report']['mode'] for call in session.emit.call_args_list],['tun','proxy'])

    def test_unknown_mode_is_never_reported_as_tun_or_a_system_proxy(self):
        for config in ({},{'tun':{}},{'tun':{'enable':'true'}},{'tun':None}):
            self.assertEqual(env.network_mode(config,True)['mode'],'unknown')
            self.assertIsNone(env.network_mode(config)['tun'])
        self.assertEqual(env.network_mode(self.config,True)['mode'],'system_proxy')
        self.assertEqual(env.network_mode({**self.config,'tun':{'enable':True}},True)['mode'],'tun')

    def test_local_status_reader_only_reads_controller_and_system_proxy(self):
        with mock.patch.object(guard,'controller',return_value=self.config) as controller,mock.patch.object(env,'command',return_value='<dictionary> {\nHTTPSEnable : 1\n}') as command:
            report=network_status.read_status(self.settings)
        controller.assert_called_once_with(self.settings,'configs')
        command.assert_called_once_with(['/usr/sbin/scutil','--proxy'])
        self.assertEqual(report['mode'],'system_proxy')
        with mock.patch.object(guard,'controller',side_effect=TimeoutError),mock.patch.object(env,'command',side_effect=OSError):
            self.assertEqual(network_status.read_status(self.settings)['mode'],'unknown')

    def test_system_proxy_parser_does_not_infer_success_from_missing_output(self):
        self.assertIsNone(env.system_proxy_enabled(''))
        self.assertFalse(env.system_proxy_enabled('<dictionary> { HTTPEnable : 0 }'))
        self.assertTrue(env.system_proxy_enabled('<dictionary> { SOCKSEnable : 1 }'))

    def test_initial_setup_keeps_explicit_system_proxy_choice(self):
        with mock.patch.object(guard,'controller',side_effect=[self.config,self.groups]):
            with self.assertRaises(guard.TunRequired):guard.check_controller(self.settings,require_tun=True)
        with mock.patch.object(guard,'controller',side_effect=[self.config,self.groups]):
            self.assertTrue(guard.check_controller({**self.settings,'allow_system_proxy':True},require_tun=True))

if __name__=='__main__':unittest.main()
