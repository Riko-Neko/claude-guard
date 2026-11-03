"""Replay install entry and residual macOS removal states without launching LuLu."""
from pathlib import Path
import sys
import json
import plistlib
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import ensure_lulu as installer

PENDING='VBG97UB4TA com.objective-see.lulu.extension (4.5.6/4.5.6) LuLu [terminated waiting to uninstall on reboot]'
ENABLED='* * VBG97UB4TA com.objective-see.lulu.extension (4.5.6/4.5.6) LuLu [activated enabled]'

class StartupTests(unittest.TestCase):
    def test_pending_removal_is_observation_and_never_prevents_activation(self):
        with mock.patch.object(installer.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=PENDING)) as run:
            state=installer.extension_state()
        self.assertEqual(state.stdout,PENDING)
        self.assertEqual(run.call_args.args[0],['/usr/bin/systemextensionsctl','list'])

    def run_visible_launch(self,existing,initial_state="",activation=True):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);base=root/'LuLu';base.mkdir()
            prefs=base/'preferences.plist';prefs.write_bytes(plistlib.dumps({'installTime':'completed'} if existing else {}))
            (root/'Library/Caches').mkdir(parents=True)
            receipt=root/'receipt.json';receipt.write_text(json.dumps({'owner_id':'fixture'}))
            marker=root/'id';marker.write_text('fixture')
            app=root/'LuLu.app';app.mkdir()
            mapping={'/Library/Objective-See/LuLu':base,'/Library/Objective-See/LuLu/preferences.plist':prefs,'/Library/Application Support/Claude Guard/installation.json':receipt,'/Library/Application Support/Claude Guard/package-installation-id':marker}
            real_path=Path
            fake=mock.Mock(side_effect=lambda value:mapping.get(str(value),real_path(value)));fake.home.return_value=root
            launched=False;before=[]
            def operation(command,**kwargs):
                nonlocal launched
                if command[0]=='/usr/bin/open':
                    self.assertEqual(command,['/usr/bin/open','-a',str(app)])
                    before.append(plistlib.loads(prefs.read_bytes()))
                    launched=True
                    if not existing:prefs.write_bytes(plistlib.dumps({'installTime':'official-completion'}))
                    (base/'rules.plist').write_bytes(b'official-rules')
                    return mock.Mock(returncode=0)
                return mock.Mock(returncode=0,stdout=(initial_state+'\n'+ENABLED) if launched and activation else initial_state)
            with mock.patch.object(installer,'Path',fake),mock.patch.object(installer,'APP',app),mock.patch.object(installer,'verify'),mock.patch.object(installer,'plan_preparation',return_value=None),mock.patch.object(installer.subprocess,'run',side_effect=operation),mock.patch.object(installer.subprocess,'check_output',return_value=''),mock.patch.object(installer,'authorize') as authorization,mock.patch('builtins.print') as output:
                if activation:installer.main()
                else:
                    with mock.patch.object(installer.time,'monotonic',side_effect=[0,181]),self.assertRaises(SystemExit) as failure:installer.main()
                    self.assertEqual(failure.exception.code,'GUARD_SETUP_ACTIVATION_MISSING')
            authorization.assert_not_called()
            self.assertEqual(len(before),1)
            self.assertEqual(bool(before[0].get('installTime')),existing)
            messages=[call.args[0] for call in output.call_args_list]
            self.assertIn('正在重新启用已有网络保护…' if existing else '请在 LuLu 安装引导中完成设置…',messages)

    def test_first_run_is_foreground_and_completion_marker_is_not_preseeded(self):
        self.run_visible_launch(False)

    def test_existing_preferences_are_preserved_and_labeled_reactivation(self):
        self.run_visible_launch(True)

    def test_pending_only_before_launch_can_become_enabled_without_reboot(self):
        self.run_visible_launch(True,PENDING)

    def test_old_pending_entry_beside_new_enabled_entry_is_not_a_reboot_requirement(self):
        self.run_visible_launch(False,PENDING)

    def test_timeout_with_only_old_pending_record_is_not_a_reboot_verdict(self):
        self.run_visible_launch(True,PENDING,activation=False)

if __name__=='__main__':unittest.main()
