"""Installation completion replay: temporary files and fake helpers only."""
import importlib.util
import json
import os
import runpy
import shutil
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import gui_setup as ui
import guard
from admin_authorization import AuthorizationError

class PolicyContinuationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);(self.root/'runtime').mkdir()
        for folder,names in ui.STAGED_FILES.items():
            (self.root/folder).mkdir()
            for name in names:(self.root/folder/name).write_text('# fixture')
        for name,value in [('ROOT',self.root),('CANCEL_REQUESTED',False)]:
            patch=mock.patch.object(ui,name,value);patch.start();self.addCleanup(patch.stop)
        for name in ['phase','record_setup']:
            patch=mock.patch.object(ui,name);patch.start();self.addCleanup(patch.stop)

    def prepare(self,script,*args):
        if script=='tools/lulu_setup.py':
            (self.root/'runtime/lulu-clean-install-plan.json').write_text('{}')

    def test_stale_plan_is_reprepared_inside_same_setup_without_reinstalling(self):
        result=mock.Mock(returncode=1,stdout='',stderr='execution error: {"code":"GUARD_POLICY_STALE_PLAN"} (1)')
        with mock.patch.object(ui,'run',side_effect=self.prepare) as run,mock.patch.object(ui,'authorize',side_effect=[AuthorizationError('stale',result),mock.Mock(returncode=0)]),mock.patch.object(ui.time,'sleep'):
            ui.apply_policy()
        self.assertEqual(sum(c.args[0]=='tools/lulu_setup.py' for c in run.call_args_list),2)
        self.assertFalse(any(c.args[0]=='tools/ensure_lulu.py' for c in run.call_args_list))

    def test_unknown_authorization_error_is_logged_and_not_blindly_retried(self):
        result=mock.Mock(returncode=1,stdout='fixture output',stderr='fixture administrative error')
        with mock.patch.object(ui,'run',side_effect=self.prepare),mock.patch.object(ui,'authorize',side_effect=AuthorizationError('failed',result)) as authorize:
            with self.assertRaises(AuthorizationError):ui.apply_policy()
        authorize.assert_called_once()
        self.assertIn('fixture administrative error',(self.root/'runtime/gui-install.log').read_text())

    def test_cancelled_authorization_is_not_retried(self):
        result=mock.Mock(returncode=1,stdout='',stderr='User canceled. (-128)')
        with mock.patch.object(ui,'run',side_effect=self.prepare),mock.patch.object(ui,'authorize',side_effect=AuthorizationError('cancelled',result)) as authorize:
            with self.assertRaises(ui.Cancelled):ui.apply_policy()
        authorize.assert_called_once()

    def test_stale_plan_retry_is_bounded(self):
        result=mock.Mock(returncode=1,stdout='',stderr='GUARD_POLICY_STALE_PLAN')
        with mock.patch.object(ui,'run',side_effect=self.prepare),mock.patch.object(ui,'authorize',side_effect=AuthorizationError('stale',result)) as authorize,mock.patch.object(ui.time,'sleep'):
            with self.assertRaises(AuthorizationError):ui.apply_policy()
        self.assertEqual(authorize.call_count,3)

class GatewayCompletionTests(unittest.TestCase):
    def replay(self, responses):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name);(root/'tools').mkdir()
        helper=root/'tools/enable_user_trial.py';shutil.copyfile(ROOT/'tools/enable_user_trial.py',helper)
        path=root/'settings.json';path.write_text(json.dumps({'protection_mode':'proxy','expected_ip':'192.0.2.1','expected_country':'TW','protected_launch_enabled':False}))
        session=mock.Mock();session.proxy.server_address=('127.0.0.1',1)
        conn=mock.Mock();conn.getresponse.side_effect=responses
        patches=[mock.patch.object(guard,'Session',return_value=session),mock.patch.object(guard,'running_claude',return_value=[]),mock.patch.object(guard.http.client,'HTTPSConnection',return_value=conn),mock.patch('time.sleep')]
        for patch in patches:patch.start();self.addCleanup(patch.stop)
        return helper,path,session,conn

    def response(self,ip='192.0.2.1'):
        response=mock.Mock(status=200);response.read.return_value=('ip='+ip+'\nloc=TW\n').encode();return response

    def test_one_gateway_timeout_recovers_without_restarting_setup(self):
        helper,path,session,conn=self.replay([TimeoutError('fixture timeout'),self.response()])
        runpy.run_path(str(helper),run_name='__main__')
        self.assertTrue(json.loads(path.read_text())['protected_launch_enabled'])
        self.assertEqual(conn.getresponse.call_count,2)
        self.assertEqual(session.close.call_count,2)

    def test_changed_exit_never_retries_or_enables_launch(self):
        helper,path,session,conn=self.replay([self.response('192.0.2.2')])
        with self.assertRaises(guard.GuardError):runpy.run_path(str(helper),run_name='__main__')
        self.assertFalse(json.loads(path.read_text())['protected_launch_enabled'])
        self.assertEqual(conn.getresponse.call_count,1)

    def test_repeated_timeouts_remain_disabled_after_bounded_retries(self):
        helper,path,session,conn=self.replay([TimeoutError(),TimeoutError(),TimeoutError()])
        with self.assertRaises(TimeoutError):runpy.run_path(str(helper),run_name='__main__')
        self.assertFalse(json.loads(path.read_text())['protected_launch_enabled'])
        self.assertEqual(conn.getresponse.call_count,3)

    def enhanced_report(self,path):
        settings=json.loads(path.read_text());settings['protection_mode']='enhanced';path.write_text(json.dumps(settings))
        runtime=path.parent/'runtime';runtime.mkdir()
        receipt=path.parent/'receipt.json';receipt.write_text('{}');os.utime(receipt,(1,1))
        report=runtime/'lulu-live-acceptance.json'
        report.write_text(json.dumps({'all_passed':True,'loopback_explicit_exception':True,'provider_readiness_confirmed':True}))
        patch=mock.patch.object(guard.system_filter,'RECEIPT',receipt);patch.start();self.addCleanup(patch.stop)
        return receipt,report

    def test_filter_disappearing_after_gateway_check_never_enables_launch(self):
        helper,path,session,conn=self.replay([self.response()]);self.enhanced_report(path)
        with mock.patch.object(guard.system_filter,'inspect',side_effect=[42,guard.system_filter.FilterError('stopped')]):
            with self.assertRaises(guard.system_filter.FilterError):runpy.run_path(str(helper),run_name='__main__')
        self.assertFalse(json.loads(path.read_text())['protected_launch_enabled'])
        self.assertEqual(conn.getresponse.call_count,1)

    def test_outdated_filter_acceptance_never_creates_proxy_or_enables_launch(self):
        helper,path,session,conn=self.replay([self.response()]);receipt,report=self.enhanced_report(path)
        os.utime(report,(0,0))
        with self.assertRaises(guard.GuardError):runpy.run_path(str(helper),run_name='__main__')
        session.start.assert_not_called()
        self.assertFalse(json.loads(path.read_text())['protected_launch_enabled'])

if __name__=='__main__':unittest.main()
