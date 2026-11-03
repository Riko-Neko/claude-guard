"""GUI setup contract; no dialogs, actual VPN, system changes or Claude launch."""
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import gui_setup as ui
import configure_vpn as vpn

class GUISetupTests(unittest.TestCase):
    def setUp(self):
        for name,value in [('record_setup',None),('load_resume',None),('save_progress',None),('clear_progress',None)]:
            patch=mock.patch.object(ui,name,return_value=value)
            patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(ui,'CANCEL_REQUESTED',False);patch.start();self.addCleanup(patch.stop)

    def test_group_picker_uses_current_embedded_callback(self):
        picker=mock.Mock(return_value='Subscription')
        proxies={'proxies':{'Subscription':{'now':'Fixture'}}}
        session=mock.Mock();session.detected={'ip':'1.1.1.1','loc':'TW'}
        with mock.patch.object(vpn.guard,'running_claude',return_value=[]),mock.patch.object(vpn.guard,'controller',side_effect=[proxies,{'mixed-port':7897}]),mock.patch.object(vpn.subprocess,'check_output',return_value='{"name":"Fixture","type":"test"}'),mock.patch.object(vpn,'DiscoverySession',return_value=session),mock.patch.object(vpn,'choose_group',side_effect=AssertionError('Legacy dialog must not be imported')),mock.patch.object(vpn.environment_checks,'snapshot',return_value={}):
            settings=vpn.detect(choose_group_callback=picker)
        picker.assert_called_once_with(['Subscription'])
        self.assertEqual(settings['proxy_group'],'Subscription')

    def test_group_cancel_does_not_retry_or_save(self):
        with mock.patch.object(ui.guard,'running_claude',return_value=[]),mock.patch.object(ui,'phase'),mock.patch.object(ui,'dialog'),mock.patch.object(vpn,'detect',side_effect=ui.Cancelled()) as detect,mock.patch.object(vpn,'save') as save:
            with self.assertRaises(ui.Cancelled):ui.main('proxy')
        self.assertEqual(detect.call_count,1);save.assert_not_called()

    def test_cancel_confirmation_never_saves_or_installs(self):
        detected={'proxy_group':'AI','expected_node':'Fixture','expected_ip':'203.0.113.1','expected_country':'TW'}
        with mock.patch.object(ui.guard,'running_claude',return_value=[]), mock.patch.object(ui,'phase'), mock.patch.object(ui,'dialog',side_effect=[None,ui.Cancelled()]), mock.patch.object(vpn,'detect',return_value=detected), mock.patch.object(vpn,'save') as save, mock.patch.object(ui,'run') as run:
            with self.assertRaises(ui.Cancelled):ui.main()
            save.assert_not_called();run.assert_not_called()

    def test_missing_vpn_offers_retry_before_confirmation(self):
        detected={'proxy_group':'AI','expected_node':'Fixture','expected_ip':'203.0.113.1','expected_country':'TW'}
        with mock.patch.object(ui.guard,'running_claude',return_value=[]),mock.patch.object(ui,'phase'),mock.patch.object(ui,'dialog',side_effect=[None,None,ui.Cancelled()]) as dialog,mock.patch.object(vpn,'detect',side_effect=[RuntimeError('off'),detected]) as detect,mock.patch.object(vpn,'save') as save:
            with self.assertRaises(ui.Cancelled):ui.main()
            self.assertEqual(detect.call_count,2);self.assertEqual(dialog.call_args_list[1].args[0],'VPN 检测未通过');save.assert_not_called()

    def test_active_client_never_detects_or_installs(self):
        with mock.patch.object(ui.guard,'running_claude',return_value=[1]),mock.patch.object(ui,'dialog'),mock.patch.object(vpn,'detect') as detect,mock.patch.object(ui,'run') as run:
            ui.main();detect.assert_not_called();run.assert_not_called()

    def test_discovery_checks_tun_and_pins_detected_values_without_saving(self):
        proxies={'proxies':{'AI':{'now':'Fixture'}}}
        session=mock.Mock();session.detected={'ip':'1.1.1.1','loc':'TW'}
        with mock.patch.object(vpn.guard,'running_claude',return_value=[]),mock.patch.object(vpn.guard,'controller',side_effect=[proxies,{'mixed-port':7897}]),mock.patch.object(vpn.subprocess,'check_output',return_value='{"name":"Fixture","type":"test"}'),mock.patch.object(vpn,'DiscoverySession',return_value=session),mock.patch.object(vpn,'save') as save:
            result=vpn.detect()
        self.assertEqual(result['expected_ip'],'1.1.1.1');self.assertEqual(result['expected_country'],'TW')
        self.assertFalse(result['protected_launch_enabled']);session.start.assert_called_once_with(create_gateway=False);session.close.assert_called_once();save.assert_not_called()

    def test_invalid_admin_request_preserves_specific_failure_in_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'runtime').mkdir()
            process=mock.Mock(args=['fixture'],stdout=iter(['GUARD_SETUP_AUTH_REQUEST_INVALID\n']))
            process.wait.return_value=1
            with mock.patch.object(ui,'ROOT',root),mock.patch.object(ui.subprocess,'Popen',return_value=process):
                with self.assertRaisesRegex(RuntimeError,'授权请求未能建立'):
                    ui.run('tools/ensure_lulu.py')

if __name__=='__main__':unittest.main()
