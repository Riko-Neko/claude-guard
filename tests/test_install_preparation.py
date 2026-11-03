"""Automatic old-install preparation; temporary files and mocked system actions only."""
from pathlib import Path
import json
import plistlib
import tempfile
import sys
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
import install_preparation as prep
import admin_authorization

class PreparationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.state=self.root/'Guard';self.state.mkdir()
        self.app=self.root/'LuLu.app';self.app.mkdir();self.data=self.root/'LuLu';self.data.mkdir()
        self.receipt={'scope':'claude','owner_id':'old','phase':'dependency_installed_pending_configuration'}
        self.write();(self.state/'package-installation-id').write_text('new')
        for name,value in [('STATE',self.state),('APP',self.app),('DATA',self.data)]:
            patch=mock.patch.object(prep.cleanup,name,value);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(prep.cleanup,'trusted',side_effect=lambda path:path.read_bytes());patch.start();self.addCleanup(patch.stop)
    def write(self):
        (self.state/'installation.json').write_text(json.dumps(self.receipt))
    def test_previous_guard_install_is_selected(self):
        self.assertEqual(prep.plan_preparation(),{'owner':'new','previous_owner':'old'})
    def test_current_attempt_and_unowned_components_are_preserved(self):
        for change in [{'owner_id':'new'},{'scope':'other'},{'phase':'component_removed'}]:
            before=dict(self.receipt);self.receipt.update(change);self.write()
            self.assertIsNone(prep.plan_preparation());self.receipt=before
    def test_custom_preferences_are_not_automatically_reset(self):
        (self.data/'preferences.plist').write_bytes(plistlib.dumps({'currentProfile':'custom'}))
        with self.assertRaisesRegex(RuntimeError,'自定义'):prep.plan_preparation()
    def test_service_must_stop_before_any_file_cleanup(self):
        with mock.patch.object(prep.cleanup,'assert_claude_closed'),mock.patch.object(prep.subprocess,'run',return_value=mock.Mock(returncode=0)),mock.patch.object(prep.cleanup,'stopped_state',side_effect=RuntimeError('still running')),mock.patch.object(prep.time,'sleep'),mock.patch.object(admin_authorization,'authorize') as authorize:
            with self.assertRaisesRegex(RuntimeError,'未清理任何配置'):prep.prepare_previous({'owner':'new','previous_owner':'old'})
        authorize.assert_not_called();self.assertTrue(self.data.is_dir())
    def test_completed_stop_stages_only_the_owned_cleanup_helper(self):
        with mock.patch.object(prep.cleanup,'assert_claude_closed'),mock.patch.object(prep.subprocess,'run',return_value=mock.Mock(returncode=0)) as stop,mock.patch.object(prep.cleanup,'stopped_state',return_value=True),mock.patch.object(admin_authorization,'authorize') as authorize:
            prep.prepare_previous({'owner':'new','previous_owner':'old'})
        self.assertEqual(stop.call_args.args[0],[str(self.app/'Contents/MacOS/LuLu'),'-quit'])
        self.assertIn('--previous-owner old',authorize.call_args.args[0])
        self.assertNotIn('rm ',authorize.call_args.args[0])
    def test_running_claude_prevents_even_official_stop(self):
        with mock.patch.object(prep.cleanup,'assert_claude_closed',side_effect=RuntimeError('Claude running')),mock.patch.object(prep.subprocess,'run') as stop:
            with self.assertRaises(RuntimeError):prep.prepare_previous({'owner':'new','previous_owner':'old'})
        stop.assert_not_called()

if __name__=='__main__':unittest.main()
