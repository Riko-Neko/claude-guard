"""Safety gates for the privileged maintenance entry; no system writes/reloads."""
import importlib.util
from pathlib import Path
import plistlib
import json
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('setup',ROOT/'tools/lulu_setup.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
class SetupTests(unittest.TestCase):
    def test_apply_without_admin_never_reads_plan_or_changes_system(self):
        with mock.patch.object(s.os,'geteuid',return_value=501),mock.patch.object(s,'atomic') as write,mock.patch.object(s.os,'kill') as kill:
            with self.assertRaises(s.PolicyError):s.apply('/does-not-exist',True)
            write.assert_not_called();kill.assert_not_called()
    def test_missing_explicit_maintenance_restart_flag_never_reads_plan(self):
        with mock.patch.object(s.os,'geteuid',return_value=0),mock.patch.object(s,'atomic') as write,mock.patch.object(s.os,'kill') as kill:
            with self.assertRaises(s.PolicyError):s.apply('/does-not-exist',False)
            write.assert_not_called();kill.assert_not_called()
    def test_existing_global_security_policy_not_silently_disabled(self):
        for p in [{'useAllowList':True},{'useBlockList':True},{'blockMode':True},{'currentProfile':'custom'}]:
            with self.subTest(p=p),self.assertRaises(s.PolicyError):s.preferences(plistlib.dumps(p))
    def test_preference_transform_preserves_unrelated_values(self):
        before={'custom-key':{'future':[1,2,3]},'allowApple':True,'allowInstalled':True}
        after=plistlib.loads(s.preferences(plistlib.dumps(before)))
        for key,value in before.items():self.assertEqual(after[key],value)
        self.assertTrue(after['noIconMode']);self.assertTrue(after['allowLocalHost']);self.assertFalse(after['allowDNS'])
        self.assertTrue(after['passiveMode']);self.assertEqual(after['passiveModeAction'],0)
    def test_unknown_scope_is_not_accepted(self):
        with self.assertRaises(s.PolicyError):s.protected_paths('arbitrary',501)

    def test_prepare_uses_real_user_despite_installer_sudo_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            plan=Path(temp)/'plan.json'
            with mock.patch.dict(s.os.environ,{'SUDO_UID':'0'}),mock.patch.object(s.os,'getuid',return_value=501),mock.patch.object(s.os,'geteuid',return_value=501),mock.patch.object(s,'check_app'),mock.patch.object(s,'check_idle'),mock.patch.object(s,'read_fixed',side_effect=[b'fixture',plistlib.dumps({})]),mock.patch.object(s,'candidate_rules',return_value=(b'candidate',4)),mock.patch.object(s,'protected_paths',return_value=['/fixture/*']):
                s.prepare(plan,'claude')
            self.assertEqual(json.loads(plan.read_text())['uid'],501)

    def test_prepare_as_root_is_rejected_even_with_sudo_user(self):
        with mock.patch.dict(s.os.environ,{'SUDO_UID':'501'}),mock.patch.object(s.os,'getuid',return_value=0),mock.patch.object(s.os,'geteuid',return_value=0),mock.patch.object(s,'check_app') as check:
            with self.assertRaisesRegex(s.PolicyError,'not root'):s.prepare('/not-used','claude')
            check.assert_not_called()

    def test_changed_plan_is_identified_before_any_system_write_or_reload(self):
        with tempfile.TemporaryDirectory() as temp:
            plan=Path(temp)/'plan.json'
            plan.write_text(json.dumps({'uid':501,'schema':1,'scope':'claude','protected_paths':['/fixture/*'],'gateway_port':47831,'lulu_version':'4.5.6','rules_before_sha256':s.digest(b'old'),'preferences_before_sha256':s.digest(b'old')}))
            with mock.patch.object(s.os,'geteuid',return_value=0),mock.patch.object(s,'caller_uid',return_value=501),mock.patch.object(s,'protected_paths',return_value=['/fixture/*']),mock.patch.object(s,'check_app'),mock.patch.object(s,'check_idle'),mock.patch.object(s,'read_fixed',side_effect=[b'new',b'old']),mock.patch.object(s,'atomic') as write,mock.patch.object(s.os,'kill') as reload:
                with self.assertRaises(s.StalePlanError):s.apply(plan,True)
            write.assert_not_called();reload.assert_not_called()
if __name__=='__main__':unittest.main(verbosity=2)
