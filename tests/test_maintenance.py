"""Maintenance decisions only: no real process, network, or rules mutations."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('maintenance',ROOT/'tools/check_lulu_maintenance.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MaintenanceTests(unittest.TestCase):
    def test_existing_claude_or_code_prevents_maintenance(self):
        self.assertFalse(m.evaluate([123],'')['maintenance_allowed'])
    def test_guard_session_prevents_maintenance(self):
        self.assertFalse(m.evaluate([],'',True)['maintenance_allowed'])
    def test_pending_uninstall_requires_activation_not_mandatory_reboot(self):
        result=m.evaluate([],'VBG97UB4TA com.objective-see.lulu.extension [terminated waiting to uninstall on reboot]')
        self.assertFalse(result['maintenance_allowed']);self.assertFalse(result['requires_reboot']);self.assertTrue(result['reactivation_needed'])
    def test_unrelated_extension_does_not_trigger_reboot(self):
        self.assertTrue(m.evaluate([],'other.example.extension [terminated waiting to uninstall on reboot]')['maintenance_allowed'])
    def test_old_pending_removal_does_not_block_new_enabled_extension(self):
        output='VBG97UB4TA com.objective-see.lulu.extension (4.5.3) [terminated waiting to uninstall on reboot]\n*\t*\tVBG97UB4TA com.objective-see.lulu.extension (4.5.6) [activated enabled]'
        result=m.evaluate([],output)
        self.assertTrue(result['maintenance_allowed'])
        self.assertFalse(result['requires_reboot'])
        self.assertTrue(result['cleanup_reboot_pending'])
        self.assertFalse(result['launch_allowed'])
    def test_pending_removal_allows_official_reactivation_attempt_only(self):
        result=m.evaluate([],'VBG97UB4TA com.objective-see.lulu.extension [terminated waiting to uninstall on reboot]')
        self.assertTrue(result['official_reactivation_allowed'])
        self.assertFalse(result['maintenance_allowed'])
    def test_unreadable_extension_state_refuses_maintenance(self):
        self.assertFalse(m.evaluate([],'',query_ok=False)['maintenance_allowed'])
    def test_maintenance_permission_never_grants_real_launch(self):
        result=m.evaluate([],'');self.assertTrue(result['maintenance_allowed']);self.assertFalse(result['launch_allowed'])
if __name__=='__main__':unittest.main(verbosity=2)
