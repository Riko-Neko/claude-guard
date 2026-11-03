"""Replay incomplete dependency preparation without touching system files."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import plistlib
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import initialize_filter
import admin_authorization

class RecoveryTests(unittest.TestCase):
    def test_missing_rules_preserves_preferences_and_allows_official_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'LuLu';target.mkdir()
            data=plistlib.dumps({'installTime':'previous-install','passiveMode':True})
            (target/'preferences.plist').write_bytes(data)
            real_path=Path
            def mapped(value):return target if str(value)=='/Library/Objective-See/LuLu' else real_path(value)
            with mock.patch.object(initialize_filter,'Path',side_effect=mapped),mock.patch.object(initialize_filter.os,'geteuid',return_value=0),mock.patch.object(initialize_filter.subprocess,'check_output',return_value=''),mock.patch.object(initialize_filter.subprocess,'run',return_value=mock.Mock(stderr='TeamIdentifier=VBG97UB4TA')):
                initialize_filter.main()
            self.assertEqual((target/'preferences.plist').read_bytes(),data)
            self.assertFalse((target/'rules.plist').exists())

    def test_active_provider_missing_preferences_can_reenter_official_onboarding(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'LuLu';target.mkdir()
            (target/'rules.plist').write_bytes(b'existing rules')
            real_path=Path
            def mapped(value):
                return target if str(value)=='/Library/Objective-See/LuLu' else real_path(value)
            with mock.patch.object(initialize_filter,'Path',side_effect=mapped),mock.patch.object(initialize_filter.os,'geteuid',return_value=0),mock.patch.object(initialize_filter.subprocess,'check_output',return_value='7 /Library/SystemExtensions/example/com.objective-see.lulu.extension'),mock.patch.object(initialize_filter.subprocess,'run',return_value=mock.Mock(stderr='TeamIdentifier=VBG97UB4TA')):
                initialize_filter.main()
            self.assertFalse((target/'preferences.plist').exists(),'Do not overwrite live provider settings; let official onboarding recover them')
            self.assertEqual((target/'rules.plist').read_bytes(),b'existing rules')

    def test_live_provider_with_missing_directory_gets_storage_restored(self):
        with tempfile.TemporaryDirectory() as temp:
            target=Path(temp)/'LuLu'
            real_path=Path
            def mapped(value):return target if str(value)=='/Library/Objective-See/LuLu' else real_path(value)
            with mock.patch.object(initialize_filter,'Path',side_effect=mapped),mock.patch.object(initialize_filter.os,'geteuid',return_value=0),mock.patch.object(initialize_filter.subprocess,'check_output',return_value='7 /Library/SystemExtensions/example/com.objective-see.lulu.extension'),mock.patch.object(initialize_filter.subprocess,'run',return_value=mock.Mock(stderr='TeamIdentifier=VBG97UB4TA')):
                initialize_filter.main()
            self.assertTrue(target.is_dir(),'The official provider needs its directory to persist cached preferences and rules')
            self.assertFalse((target/'preferences.plist').exists(),'Do not replace live provider settings')
            self.assertFalse((target/'rules.plist').exists(),'The official provider must save its own rule archive')

    def test_authorization_failure_retains_operation_diagnostic(self):
        result=subprocess.CompletedProcess([],1,'','GUARD_SETUP_RESTART_REQUIRED')
        with mock.patch.object(admin_authorization.subprocess,'run',return_value=result):
            with self.assertRaises(RuntimeError) as raised:admin_authorization.authorize('fixture','fixture')
        self.assertIs(getattr(raised.exception,'result',None),result)


import lifecycle
class DetachedUninstallTests(unittest.TestCase):
    def test_waits_for_guard_exit_before_component_or_app_removal(self):
        with tempfile.TemporaryDirectory() as temp:
            ready=Path(temp)/'ready.json';events=[];alive=iter([True,True,False])
            bundle=mock.Mock();bundle.__str__=mock.Mock(return_value='/Applications/Claude Guard.app');bundle.exists.return_value=False
            def running(pid):
                value=next(alive);events.append('alive' if value else 'exited');return value
            with mock.patch.object(lifecycle.os,'getppid',return_value=73),mock.patch.object(lifecycle,'preflight_uninstall'),mock.patch.object(lifecycle,'parent_running',side_effect=running),mock.patch.object(lifecycle.time,'sleep'),mock.patch.object(lifecycle,'perform',side_effect=lambda action:events.append('filter')),mock.patch.object(lifecycle.subprocess,'run',side_effect=lambda *a,**k:(events.append('trash') or mock.Mock(returncode=0))):
                lifecycle.uninstall_after_exit(73,ready,bundle)
            self.assertEqual(events,['alive','alive','exited','filter','trash'])
            self.assertIn('true',ready.read_text())

    def test_failed_filter_removal_leaves_guard_app_intact(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle=mock.Mock();bundle.__str__=mock.Mock(return_value='/Applications/Claude Guard.app')
            with mock.patch.object(lifecycle.os,'getppid',return_value=73),mock.patch.object(lifecycle,'preflight_uninstall'),mock.patch.object(lifecycle,'parent_running',return_value=False),mock.patch.object(lifecycle,'perform',side_effect=RuntimeError('filter failed')),mock.patch.object(lifecycle.subprocess,'run') as trash:
                with self.assertRaisesRegex(RuntimeError,'filter failed'):lifecycle.uninstall_after_exit(73,Path(temp)/'ready.json',bundle)
            trash.assert_not_called()

    def test_timeout_never_changes_components(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle=mock.Mock();bundle.__str__=mock.Mock(return_value='/Applications/Claude Guard.app')
            with mock.patch.object(lifecycle.os,'getppid',return_value=73),mock.patch.object(lifecycle,'preflight_uninstall'),mock.patch.object(lifecycle,'parent_running',return_value=True),mock.patch.object(lifecycle.time,'monotonic',side_effect=[0,31]),mock.patch.object(lifecycle,'perform') as filtering:
                with self.assertRaisesRegex(RuntimeError,'尚未退出'):lifecycle.uninstall_after_exit(73,Path(temp)/'ready.json',bundle)
            filtering.assert_not_called()


    def test_helper_survives_requesting_process_exit(self):
        # A real, separate parent/child handoff. Only temporary sentinel files
        # are written; component removal and Finder are both replaced.
        import json
        import time
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);ready=base/'ready.json';completed=base/'completed'
            code="""import sys,os
from pathlib import Path
from unittest import mock
sys.path.insert(0,TOOLS)
import lifecycle
bundle=mock.Mock();bundle.__str__=mock.Mock(return_value='/Applications/Claude Guard.app');bundle.exists.return_value=False
with mock.patch.object(lifecycle,'preflight_uninstall'),mock.patch.object(lifecycle,'perform',side_effect=lambda action:(Path(COMPLETED).write_text('filter'),None)[1]),mock.patch.object(lifecycle.subprocess,'run',return_value=mock.Mock(returncode=0)):
 lifecycle.uninstall_after_exit(os.getppid(),Path(READY),bundle)
Path(COMPLETED).write_text('finished-after-parent-exit')
""".replace('TOOLS',repr(str(ROOT/'tools'))).replace('COMPLETED',repr(str(completed))).replace('READY',repr(str(ready)))
            launcher=base/'parent.py'
            launcher.write_text(f'''import subprocess,sys,time
from pathlib import Path
subprocess.Popen([sys.executable,"-c",{code!r}],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
for _ in range(100):
 if Path({str(ready)!r}).exists():sys.exit(0)
 time.sleep(.05)
sys.exit(1)
''')
            result=subprocess.run([sys.executable,str(launcher)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                if completed.exists() and completed.read_text()=='finished-after-parent-exit':break
                time.sleep(.05)
            self.assertEqual(completed.read_text(),'finished-after-parent-exit')

if __name__=='__main__':unittest.main()
