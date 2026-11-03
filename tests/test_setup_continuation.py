"""Replay the enhanced setup flow with temporary settings and no system operations."""
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import gui_setup as ui
import configure_vpn as vpn
import ensure_lulu

class ContinuationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);(self.root/'runtime').mkdir()
        for module,name,value in [(ui,'ROOT',self.root),(vpn,'ROOT',self.root),(ui,'CANCEL_REQUESTED',False),(ui,'EMBEDDED',False)]:
            patch=mock.patch.object(module,name,value);patch.start();self.addCleanup(patch.stop)
        for module,name,value in [(ui,'record_setup',None),(ui,'phase',None),(ui,'dialog',None),(ui.guard,'running_claude',[])]:
            patch=mock.patch.object(module,name,return_value=value);patch.start();self.addCleanup(patch.stop)
        self.settings={'proxy_group':'AI','expected_node':'Fixture','expected_ip':'203.0.113.1','expected_country':'TW','node_sha256':'fixture','configured':True,'protected_launch_enabled':False}

    def test_policy_failure_retries_without_vpn_discovery_or_confirmations(self):
        with mock.patch.object(vpn,'detect',return_value=self.settings) as detect,mock.patch.object(ui,'run') as run,mock.patch.object(ui,'apply_policy',side_effect=[RuntimeError('prepare failed'),None]) as apply:
            with self.assertRaisesRegex(RuntimeError,'prepare failed'):ui.main('enhanced')
            self.assertEqual(json.loads((self.root/'runtime/setup-progress.json').read_text())['stage'],'policy')
            ui.main('enhanced')
        self.assertEqual(detect.call_count,1)
        self.assertEqual(apply.call_count,2)
        self.assertFalse((self.root/'runtime/setup-progress.json').exists())
        self.assertEqual([c.args[0] for c in run.call_args_list],['src/guard.py','tools/ensure_lulu.py','src/guard.py','tools/ensure_lulu.py','tests/verify_lulu_flow.py','tools/enable_user_trial.py','tools/refresh_lulu_ui.py'])

    def test_validation_retry_never_reapplies_rules_or_reinstalls_dependency(self):
        attempt=0
        def operation(script,*args):
            nonlocal attempt
            if script=='tests/verify_lulu_flow.py':
                attempt+=1
                if attempt==1:raise RuntimeError('verification failed')
        with mock.patch.object(vpn,'detect',return_value=self.settings) as detect,mock.patch.object(ui,'run',side_effect=operation) as run,mock.patch.object(ui,'apply_policy') as apply:
            with self.assertRaisesRegex(RuntimeError,'verification failed'):ui.main('enhanced')
            ui.main('enhanced')
        self.assertEqual(detect.call_count,1);apply.assert_called_once()
        self.assertEqual(sum(c.args[0]=='tools/ensure_lulu.py' for c in run.call_args_list),1)

    def test_enable_resume_does_not_repeat_redundant_network_or_filter_setup(self):
        self.settings.update(protection_mode='enhanced',environment_check_seconds=3600)
        vpn.save(self.settings);ui.save_progress(self.settings,'enable')
        with mock.patch.object(vpn,'detect') as detect,mock.patch.object(ui,'run') as run,mock.patch.object(ui,'apply_policy') as apply:
            ui.main('enhanced')
        detect.assert_not_called();apply.assert_not_called()
        self.assertEqual([c.args[0] for c in run.call_args_list],['tools/enable_user_trial.py','tools/refresh_lulu_ui.py'])

    def test_connection_failure_on_resume_never_applies_or_enables_protection(self):
        self.settings.update(protection_mode='enhanced',environment_check_seconds=3600)
        vpn.save(self.settings);ui.save_progress(self.settings,'policy')
        with mock.patch.object(vpn,'detect') as detect,mock.patch.object(ui,'run',side_effect=RuntimeError('exit changed')) as run,mock.patch.object(ui,'apply_policy') as apply:
            with self.assertRaisesRegex(RuntimeError,'exit changed'):ui.main('enhanced')
        detect.assert_not_called();apply.assert_not_called();self.assertEqual(run.call_count,1)

    def test_changed_baseline_or_mode_never_resumes_old_approval(self):
        self.settings.update(protection_mode='enhanced',environment_check_seconds=3600)
        vpn.save(self.settings);ui.save_progress(self.settings,'policy')
        self.assertIsNotNone(ui.load_resume('enhanced'))
        self.assertIsNone(ui.load_resume('proxy'))
        self.settings['expected_ip']='203.0.113.2';vpn.save(self.settings)
        self.assertIsNone(ui.load_resume('enhanced'))

    def test_cancel_after_apply_finishes_transaction_but_does_not_begin_verification(self):
        def apply():ui.request_cancel()
        with mock.patch.object(ui,'run') as run,mock.patch.object(ui,'apply_policy',side_effect=apply):
            with self.assertRaises(ui.Cancelled):ui.finish_enhanced(self.settings,'policy')
        self.assertEqual(json.loads((self.root/'runtime/setup-progress.json').read_text())['stage'],'validation')
        self.assertEqual([c.args[0] for c in run.call_args_list],['tools/ensure_lulu.py'])

    def test_ready_lulu_skips_opening_official_onboarding(self):
        base=self.root/'LuLu';base.mkdir();(base/'rules.plist').write_bytes(b'fixture')
        (base/'preferences.plist').write_bytes(plistlib.dumps({'installTime':'completed'}))
        state='* * VBG97UB4TA com.objective-see.lulu.extension (4.5.6/4.5.6) LuLu [activated enabled]'
        self.assertTrue(ensure_lulu.dependency_ready(state,base))
        self.assertFalse(ensure_lulu.dependency_ready('',base))
        (base/'preferences.plist').write_bytes(plistlib.dumps({}))
        self.assertFalse(ensure_lulu.dependency_ready(state,base))

    def test_ready_dependency_main_never_opens_lulu_or_requests_admin_again(self):
        base=self.root/'LuLu';base.mkdir()
        (base/'rules.plist').write_bytes(b'fixture')
        (base/'preferences.plist').write_bytes(plistlib.dumps({'installTime':'completed'}))
        receipt=self.root/'receipt.json';receipt.write_text(json.dumps({'owner_id':'fixture'}))
        marker=self.root/'installation-id';marker.write_text('fixture')
        (self.root/'Library/Caches').mkdir(parents=True)
        real_path=Path
        mapped_paths={'/Library/Objective-See/LuLu':base,'/Library/Objective-See/LuLu/preferences.plist':base/'preferences.plist','/Library/Application Support/Claude Guard/installation.json':receipt,'/Library/Application Support/Claude Guard/package-installation-id':marker}
        def mapped(value):return mapped_paths.get(str(value),real_path(value))
        fake_path=mock.Mock(side_effect=mapped);fake_path.home.return_value=self.root
        state='* * VBG97UB4TA com.objective-see.lulu.extension (4.5.6/4.5.6) LuLu [activated enabled]'
        app=self.root/'LuLu.app';app.mkdir()
        with mock.patch.object(ensure_lulu,'APP',app),mock.patch.object(ensure_lulu,'Path',fake_path),mock.patch.object(ensure_lulu,'verify'),mock.patch.object(ensure_lulu,'plan_preparation',return_value=None),mock.patch.object(ensure_lulu.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=state)) as run,mock.patch.object(ensure_lulu,'authorize') as authorize,mock.patch.object(ensure_lulu.subprocess,'check_output') as processes,mock.patch('builtins.print'):
            ensure_lulu.main()
        self.assertEqual(run.call_count,1)
        self.assertEqual(run.call_args.args[0],['/usr/bin/systemextensionsctl','list'])
        authorize.assert_not_called();processes.assert_not_called()

    def test_cancellation_unblocks_pending_user_confirmation(self):
        import io
        ui.CANCEL_REQUESTED=True
        with mock.patch.object(ui.sys,'stdin',io.StringIO('')),mock.patch('builtins.print'):
            with self.assertRaises(ui.Cancelled):ui.ui_request('Confirm','',('Cancel','Continue'))

if __name__=='__main__':unittest.main()
