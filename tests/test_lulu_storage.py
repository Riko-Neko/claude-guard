"""Incomplete first-run storage recovery, without touching system files or services."""
import datetime
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import ensure_lulu

class StorageFlowTests(unittest.TestCase):
    def test_completed_onboarding_missing_rules_enters_recovery_not_welcome_wait(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);base=root/'LuLu';base.mkdir()
            (base/'preferences.plist').write_bytes(plistlib.dumps({'installTime':datetime.datetime(2026,11,3)}))
            receipt=root/'receipt.json';receipt.write_text(json.dumps({'owner_id':'fixture'}))
            marker=root/'installation-id';marker.write_text('fixture')
            (root/'Library/Caches').mkdir(parents=True)
            app=root/'LuLu.app';app.mkdir()
            mappings={'/Library/Objective-See/LuLu':base,'/Library/Objective-See/LuLu/preferences.plist':base/'preferences.plist','/Library/Application Support/Claude Guard/installation.json':receipt,'/Library/Application Support/Claude Guard/package-installation-id':marker}
            real_path=Path
            fake_path=mock.Mock(side_effect=lambda value:mappings.get(str(value),real_path(value)));fake_path.home.return_value=root
            state='* * VBG97UB4TA com.objective-see.lulu.extension (4.5.6/4.5.6) LuLu [activated enabled]'
            def recover():
                (base/'rules.plist').write_bytes(b'official-provider-output')
            with mock.patch.object(ensure_lulu,'APP',app),mock.patch.object(ensure_lulu,'Path',fake_path),mock.patch.object(ensure_lulu,'verify'),mock.patch.object(ensure_lulu,'plan_preparation',return_value=None),mock.patch.object(ensure_lulu.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=state)),mock.patch.object(ensure_lulu.subprocess,'check_output',return_value=str(app/'Contents/MacOS/LuLu')),mock.patch.object(ensure_lulu.time,'monotonic',side_effect=[0,10,11,16,17]),mock.patch.object(ensure_lulu.time,'sleep'),mock.patch.object(ensure_lulu,'recover_missing_rules',create=True,side_effect=recover) as recovery,mock.patch('builtins.print'):
                ensure_lulu.main()
            recovery.assert_called_once()
            self.assertTrue((base/'rules.plist').is_file())


import os
import recover_lulu_storage as repair

class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.state=self.root/'Guard';self.state.mkdir()
        self.base=self.root/'LuLu';self.base.mkdir();self.app=self.root/'LuLu.app';(self.app/'Contents').mkdir(parents=True)
        (self.app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString':'4.5.6'}))
        self.marker=self.state/'package-installation-id';self.marker.write_text('fixture');os.utime(self.marker,(1000,1000))
        self.receipt={'scope':'claude','owner_id':'fixture','phase':'dependency_installed_pending_configuration'}
        self.prefs={'installTime':datetime.datetime.fromtimestamp(1010,datetime.timezone.utc).replace(tzinfo=None)}
        self.write()
        for name,value in [('STATE',self.state),('BASE',self.base),('APP',self.app)]:
            patch=mock.patch.object(repair,name,value);patch.start();self.addCleanup(patch.stop)
        for name,value in [('trusted_state',None)]:
            patch=mock.patch.object(repair,name,return_value=value);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(repair,'trusted',side_effect=lambda path:path.read_bytes());patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(repair,'processes',return_value=['7 /Library/SystemExtensions/x/com.objective-see.lulu.extension']);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(repair.time,'time',return_value=1100);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(repair.subprocess,'check_output',return_value='03:20');patch.start();self.addCleanup(patch.stop)
        state='VBG97UB4TA com.objective-see.lulu.extension (4.5.6/4.5.6) [activated enabled]'
        patch=mock.patch.object(repair.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=state,stderr='TeamIdentifier=VBG97UB4TA'));patch.start();self.addCleanup(patch.stop)

    def write(self):
        (self.state/'installation.json').write_text(json.dumps(self.receipt))
        (self.base/'preferences.plist').write_bytes(plistlib.dumps(self.prefs))

    def test_exact_fresh_install_orphan_state_is_eligible(self):
        plan=repair.preflight();self.assertEqual(plan[:2],(7,'/Library/SystemExtensions/x/com.objective-see.lulu.extension'))

    def test_existing_rules_are_not_replaced_or_restarted(self):
        (self.base/'rules.plist').write_bytes(b'preserve')
        with mock.patch.object(repair.os,'geteuid',return_value=0),mock.patch.object(repair.os,'kill') as stop:
            result=repair.recover()
        self.assertFalse(result['restarted']);stop.assert_not_called()
        self.assertEqual((self.base/'rules.plist').read_bytes(),b'preserve')

    def test_existing_enrolled_profile_never_gets_reset(self):
        self.receipt['phase']='claude_rules_written_pending_live_tests';self.write()
        with self.assertRaisesRegex(RuntimeError,'不能自动重建'):repair.preflight()

    def test_old_or_custom_preferences_never_get_reset(self):
        self.prefs['installTime']=datetime.datetime.fromtimestamp(900,datetime.timezone.utc).replace(tzinfo=None);self.write()
        with self.assertRaisesRegex(RuntimeError,'既有 LuLu 设置'):repair.preflight()
        self.prefs['installTime']=datetime.datetime.fromtimestamp(1010,datetime.timezone.utc).replace(tzinfo=None);self.prefs['currentProfile']='custom';self.write()
        with self.assertRaisesRegex(RuntimeError,'自定义'):repair.preflight()

    def test_claude_running_always_prevents_service_restart(self):
        with mock.patch.object(repair,'processes',return_value=['7 /Library/SystemExtensions/x/com.objective-see.lulu.extension','8 /Applications/Claude.app/Contents/MacOS/Claude']),mock.patch.object(repair.os,'geteuid',return_value=0),mock.patch.object(repair.os,'kill') as stop:
            with self.assertRaisesRegex(RuntimeError,'退出 Claude'):repair.recover()
        stop.assert_not_called()

    def test_service_started_this_install_never_gets_restarted_repeatedly(self):
        with mock.patch.object(repair.subprocess,'check_output',return_value='00:30'):
            with self.assertRaisesRegex(RuntimeError,'并非安装前'):repair.preflight()

    def test_success_requires_new_provider_and_official_rule_archive(self):
        before=(self.base/'preferences.plist').read_bytes()
        def restart(pid,sig):
            (self.base/'rules.plist').write_bytes(plistlib.dumps({'$archiver':'NSKeyedArchiver'}))
        with mock.patch.object(repair.os,'geteuid',return_value=0),mock.patch.object(repair.os,'kill',side_effect=restart) as stop,mock.patch.object(repair,'processes',side_effect=[['7 /Library/SystemExtensions/x/com.objective-see.lulu.extension'],['7 /Library/SystemExtensions/x/com.objective-see.lulu.extension'],['9 /Library/SystemExtensions/x/com.objective-see.lulu.extension']]),mock.patch.object(repair.time,'sleep'):
            result=repair.recover()
        self.assertTrue(result['restarted']);self.assertTrue(result['rules_present']);stop.assert_called_once()
        self.assertEqual((self.base/'preferences.plist').read_bytes(),before)


    def test_service_restart_without_rule_output_is_not_success(self):
        with mock.patch.object(repair.os,'geteuid',return_value=0),mock.patch.object(repair.os,'kill') as stop,mock.patch.object(repair.time,'monotonic',side_effect=[0,31]):
            with self.assertRaisesRegex(RuntimeError,'仍未保存规则文件'):repair.recover()
        stop.assert_called_once()
        self.assertFalse((self.base/'rules.plist').exists())

if __name__=='__main__':unittest.main()
