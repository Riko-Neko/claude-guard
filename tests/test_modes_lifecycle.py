"""Mode separation and shutdown contracts; all system actions are mocked."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'tools'))
import guard
import gui_setup
import lifecycle
import admin_authorization

class ModesTests(unittest.TestCase):
    def test_proxy_launch_never_queries_filter(self):
        with tempfile.TemporaryDirectory() as temp:
            app=Path(temp)/'Fixture.app'
            (app/'Contents/MacOS').mkdir(parents=True)
            (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'Fixture'}))
            session=guard.Session({'protected_launch_enabled':True,'protection_mode':'proxy','claude_app':str(app)})
            session.gate.open()
            session.proxy=mock.Mock(server_address=('127.0.0.1',47831))
            with mock.patch.object(guard.system_filter,'inspect') as filtering, mock.patch.object(guard,'running_claude',return_value=[]), mock.patch.object(guard.subprocess,'run',return_value=mock.Mock(returncode=0)), mock.patch.object(guard.subprocess,'Popen',return_value=mock.Mock(pid=7)) as launch:
                session.launch()
            filtering.assert_not_called()
            self.assertFalse(hasattr(session,'filter_pid'))
            self.assertIn('--proxy-server=http://127.0.0.1:47831',launch.call_args.args[0])

    def test_basic_setup_never_installs_or_probes_lulu(self):
        settings={'proxy_group':'AI','expected_node':'test','expected_ip':'203.0.113.1','expected_country':'TW'}
        with mock.patch.object(gui_setup,'load_resume',return_value=None),mock.patch.object(gui_setup,'clear_progress'),mock.patch.object(gui_setup.guard,'running_claude',return_value=[]),mock.patch.object(gui_setup,'dialog'),mock.patch.object(gui_setup,'phase'),mock.patch.object(gui_setup.configure_vpn,'detect',return_value=settings),mock.patch.object(gui_setup.configure_vpn,'save') as save,mock.patch.object(gui_setup,'run') as run:
            gui_setup.main('proxy')
        self.assertEqual(save.call_args.args[0]['protection_mode'],'proxy')
        self.assertEqual(run.call_args_list,[mock.call('src/guard.py','check'),mock.call('tools/enable_user_trial.py')])

    def test_legacy_settings_retain_enhanced_protection(self):
        self.assertTrue(guard.enhanced({}))
        self.assertFalse(guard.enhanced({'protection_mode':'proxy'}))

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.app=self.root/'LuLu.app';self.app.mkdir()
        (self.root/'installation-id').write_text('fixture-owner')
        for name,value in [('ROOT',self.root),('APP',self.app)]:
            patch=mock.patch.object(lifecycle,name,value);patch.start();self.addCleanup(patch.stop)
        for target,value in [('managed',True),('verify',None)]:
            patch=mock.patch.object(lifecycle,target,return_value=value);patch.start();self.addCleanup(patch.stop)

    def test_active_claude_prevents_all_filter_operations(self):
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[123]),mock.patch.object(lifecycle.subprocess,'run') as run:
            with self.assertRaisesRegex(RuntimeError,'退出 Claude'):lifecycle.perform('quit')
            run.assert_not_called()

    def test_quit_calls_official_interface_then_checks_it_stopped(self):
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'extension_active',side_effect=[True,False]),mock.patch.object(lifecycle.subprocess,'run') as run,mock.patch.object(lifecycle,'authorize') as admin:
            lifecycle.perform('quit')
        self.assertEqual(run.call_args.args[0],[str(self.app/'Contents/MacOS/LuLu'),'-quit'])
        admin.assert_not_called()

    def test_quit_failure_never_reports_success(self):
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'extension_active',return_value=True),mock.patch.object(lifecycle.subprocess,'run'),mock.patch.object(lifecycle.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'尚未停止'):lifecycle.perform('quit')

    def test_cancellation_does_not_delete_data_or_claim_uninstall(self):
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'authorize',side_effect=RuntimeError('cancelled')),mock.patch.object(lifecycle,'extension_active',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'cancelled'):lifecycle.perform('uninstall')
        self.assertTrue(self.app.exists())

    def test_uninstall_authorizes_owned_cleanup_only_after_deactivation(self):
        def remove(_command,_reason):self.app.rmdir()
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'authorize',side_effect=remove) as admin,mock.patch.object(lifecycle,'extension_active',return_value=False):
            lifecycle.perform('uninstall')
        self.assertIn('uninstall_cleanup.py',admin.call_args.args[0])
        self.assertIn('--owner-id fixture-owner',admin.call_args.args[0])
        self.assertNotIn('rm ',admin.call_args.args[0])

    def test_extension_authorization_finishes_before_any_destructive_uninstall(self):
        events=[]
        def run(command,**kwargs):
            events.append('deactivate')
            self.assertEqual(command,[str(self.app/'Contents/MacOS/LuLu'),'-quit'])
            return mock.Mock(returncode=0,stdout='',stderr='')
        def remove(command,reason):
            self.assertEqual(events,['deactivate'],'Do not run destructive uninstall before the separate extension authorization')
            events.append('cleanup');self.app.rmdir()
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'extension_active',side_effect=[True,False,False,False]),mock.patch.object(lifecycle.subprocess,'run',side_effect=run),mock.patch.object(lifecycle,'authorize',side_effect=remove),mock.patch.object(lifecycle.time,'sleep'):
            lifecycle.perform('uninstall')
        self.assertEqual(events,['deactivate','cleanup'])

    def test_denied_extension_authorization_preserves_app_and_skips_cleanup(self):
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'extension_active',return_value=True),mock.patch.object(lifecycle.subprocess,'run',return_value=mock.Mock(returncode=0,stdout='',stderr='')),mock.patch.object(lifecycle,'authorize') as cleanup,mock.patch.object(lifecycle.time,'sleep'):
            with self.assertRaises(RuntimeError):lifecycle.perform('uninstall')
        cleanup.assert_not_called();self.assertTrue(self.app.exists())

    def test_unmanaged_quit_does_not_touch_lulu(self):
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'managed',return_value=False),mock.patch.object(lifecycle.subprocess,'run') as run:
            lifecycle.perform('quit')
        run.assert_not_called()

    def test_missing_vendor_app_does_not_claim_it_was_retained_or_remove_guard(self):
        self.app.rmdir()
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'extension_active',return_value=True),mock.patch.object(lifecycle,'authorize') as admin:
            with self.assertRaisesRegex(RuntimeError,'应用已缺失'):lifecycle.perform('uninstall')
        admin.assert_not_called()

    def test_unowned_orphan_extension_is_not_silently_reported_as_uninstalled(self):
        self.app.rmdir()
        with mock.patch.object(lifecycle.guard,'running_claude',return_value=[]),mock.patch.object(lifecycle,'managed',return_value=False),mock.patch.object(lifecycle,'extension_active',return_value=True),mock.patch.object(lifecycle,'authorize') as admin:
            with self.assertRaisesRegex(RuntimeError,'管理记录'):lifecycle.perform('uninstall')
        admin.assert_not_called()

    def test_unreadable_extension_state_is_failure(self):
        with mock.patch.object(lifecycle.subprocess,'run',return_value=mock.Mock(returncode=1)):
            with self.assertRaises(RuntimeError):lifecycle.extension_active()

class AuthorizationTests(unittest.TestCase):
    def test_interactive_authorization_does_not_supply_partial_credentials(self):
        with mock.patch.object(admin_authorization.subprocess,'run',return_value=mock.Mock(returncode=0)) as run:
            admin_authorization.authorize('/official/tool','配置网络保护')
        script=run.call_args.args[0][-1]
        self.assertNotIn('user name ',script)
        self.assertIn('with administrator privileges',script)
        self.assertIn('with prompt',script)
        self.assertIn('Claude Guard',script)
        self.assertNotIn('password ',script)

    def test_invalid_request_is_not_reported_as_unfinished_user_approval(self):
        result=mock.Mock(returncode=1,stderr='0:253: execution error: 授权失败。 (-50)')
        with mock.patch.object(admin_authorization.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(admin_authorization.AuthorizationError,'授权请求未能建立') as raised:
                admin_authorization.authorize('/fixture/tool','配置网络保护')
        self.assertIs(raised.exception.result,result)

    def test_generated_script_compiles_without_requesting_authorization(self):
        # osacompile only parses/compiles; it never executes the admin request.
        with mock.patch.object(admin_authorization.subprocess,'run',return_value=mock.Mock(returncode=0)) as run:
            admin_authorization.authorize('/usr/bin/true','应用 Claude 网络保护规则')
        script=run.call_args.args[0][-1]
        import subprocess
        with tempfile.TemporaryDirectory() as temp:
            result=subprocess.run(['/usr/bin/osacompile','-o',str(Path(temp)/'request.scpt'),'-e',script],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)


class OwnershipTests(unittest.TestCase):
    def check_owner(self,receipt,settings,marker=None):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'settings.json').write_text(json.dumps(settings))
            if marker:(root/'installation-id').write_text(marker)
            file=mock.Mock()
            file.is_file.return_value=True;file.is_symlink.return_value=False
            file.stat.return_value=mock.Mock(st_uid=0,st_mode=0o100644)
            file.read_text.return_value=json.dumps(receipt)
            with mock.patch.object(lifecycle,'ROOT',root),mock.patch.object(lifecycle,'RECEIPT',file):return lifecycle.managed()
    def test_fresh_standard_install_does_not_inherit_legacy_filter(self):
        self.assertFalse(self.check_owner({'scope':'claude'},{'configured':False,'protected_launch_enabled':False}))
        self.assertFalse(self.check_owner({'scope':'claude'},{'configured':True,'protected_launch_enabled':True,'protection_mode':'proxy'}))
    def test_current_enhanced_legacy_profile_can_still_release_its_filter(self):
        self.assertTrue(self.check_owner({'scope':'claude'},{'configured':True,'protected_launch_enabled':True,'protection_mode':'enhanced'}))
    def test_filter_owner_must_match_installation_generation(self):
        self.assertFalse(self.check_owner({'scope':'claude','owner_id':'old'},{},'current'))
        self.assertTrue(self.check_owner({'scope':'claude','owner_id':'current'},{},'current'))

if __name__=='__main__':unittest.main()
