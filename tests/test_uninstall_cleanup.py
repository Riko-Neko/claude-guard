"""Uninstall transactions against temporary fixtures; never changes system state."""
import json
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import uninstall_cleanup as cleanup

class CleanupTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.app=self.root/'LuLu.app';(self.app/'Contents').mkdir(parents=True)
        (self.app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleShortVersionString':'4.5.6'}))
        self.data=self.root/'LuLu';self.data.mkdir();(self.data/'rules.plist').write_bytes(b'original rules')
        self.state=self.root/'Guard';self.state.mkdir()
        (self.state/'installation.json').write_text(json.dumps({'scope':'claude','owner_id':'fixture','phase':'dependency_installed_pending_configuration'}))
        (self.state/'package-installation-id').write_text('fixture')
        for name,value in [('APP',self.app),('DATA',self.data),('STATE',self.state)]:
            patch=mock.patch.object(cleanup,name,value);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(cleanup,'trusted_directory');patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(cleanup.os,'geteuid',return_value=0);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(cleanup,'trusted',side_effect=lambda path:path.read_bytes());patch.start();self.addCleanup(patch.stop)

    def test_missing_system_approval_preserves_every_file_and_never_calls_uninstall(self):
        with mock.patch.object(cleanup,'stopped_state',side_effect=RuntimeError('extension still active')),mock.patch.object(cleanup.subprocess,'run') as vendor:
            with self.assertRaisesRegex(RuntimeError,'still active'):cleanup.finalize('fixture')
        vendor.assert_not_called();self.assertTrue(self.app.exists());self.assertTrue(self.data.exists())
        self.assertFalse((self.state/'removed-components').exists())

    def test_signed_vendor_cleanup_failure_is_finalized_with_recoverable_leftovers(self):
        with mock.patch.object(cleanup,'stopped_state',return_value=False),mock.patch.object(cleanup.subprocess,'run',return_value=mock.Mock(returncode=255,stdout='vendor XPC unavailable',stderr='TeamIdentifier=VBG97UB4TA')):
            report=cleanup.finalize('fixture')
        self.assertFalse(self.app.exists());self.assertFalse(self.data.exists())
        archive=Path(report['archive'])
        self.assertTrue((archive/'LuLu.app').is_dir())
        self.assertEqual((archive/'LuLu/rules.plist').read_bytes(),b'original rules')
        self.assertEqual(json.loads((self.state/'installation.json').read_text())['phase'],'component_removed')

    def test_different_installation_cannot_cleanup_another_components_files(self):
        with mock.patch.object(cleanup,'stopped_state') as stopped:
            with self.assertRaisesRegex(RuntimeError,'管理记录不匹配'):cleanup.finalize('different-owner')
        stopped.assert_not_called();self.assertTrue(self.app.exists());self.assertTrue(self.data.exists())

    def test_pending_reboot_is_preserved_as_a_separate_result(self):
        with mock.patch.object(cleanup,'stopped_state',return_value=True),mock.patch.object(cleanup.subprocess,'run',return_value=mock.Mock(returncode=0,stdout='',stderr='TeamIdentifier=VBG97UB4TA')):
            report=cleanup.finalize('fixture')
        self.assertTrue(report['pending_reboot'])

    def test_pending_reboot_requires_provider_to_have_stopped(self):
        line='VBG97UB4TA com.objective-see.lulu.extension [terminated waiting to uninstall on reboot]'
        with mock.patch.object(cleanup.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=line)),mock.patch.object(cleanup.subprocess,'check_output',return_value='/Library/SystemExtensions/x/com.objective-see.lulu.extension\n'):
            with self.assertRaisesRegex(RuntimeError,'仍未停止'):cleanup.stopped_state()
        with mock.patch.object(cleanup.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=line)),mock.patch.object(cleanup.subprocess,'check_output',return_value=''):
            self.assertTrue(cleanup.stopped_state())

    def test_disabled_but_registered_extension_is_not_removed(self):
        line='VBG97UB4TA com.objective-see.lulu.extension [activated disabled]'
        with mock.patch.object(cleanup.subprocess,'run',return_value=mock.Mock(returncode=0,stdout=line)),mock.patch.object(cleanup.subprocess,'check_output',return_value=''):
            with self.assertRaises(RuntimeError):cleanup.stopped_state()


    def test_install_preparation_archives_previous_guard_data_and_preserves_official_app(self):
        (self.state/'package-installation-id').write_text('new-install')
        with mock.patch.object(cleanup,'stopped_state',return_value=True),mock.patch.object(cleanup.subprocess,'run',return_value=mock.Mock(returncode=0,stderr='TeamIdentifier=VBG97UB4TA')) as vendor:
            report=cleanup.finalize('new-install','fixture',for_install=True)
        self.assertTrue(self.app.is_dir());self.assertFalse(self.data.exists())
        self.assertEqual((Path(report['archive'])/'LuLu/rules.plist').read_bytes(),b'original rules')
        self.assertEqual(report['phase'],'install_prepared')
        self.assertFalse(any('-uninstall' in call.args[0] for call in vendor.call_args_list))

    def test_install_preparation_cannot_take_over_unknown_previous_owner(self):
        (self.state/'package-installation-id').write_text('new-install')
        with mock.patch.object(cleanup,'stopped_state') as stopped:
            with self.assertRaises(RuntimeError):cleanup.finalize('new-install','different-owner',for_install=True)
        stopped.assert_not_called();self.assertTrue(self.data.exists())

if __name__=='__main__':unittest.main()
