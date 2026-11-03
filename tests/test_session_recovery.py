"""Replay paused/sleep sessions with fakes; never use installed apps/network."""
import importlib.util
import os
from pathlib import Path
import threading
import tempfile
import fcntl
import json
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('guard_recovery',ROOT/'src/guard.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

class RecoveryTests(unittest.TestCase):
    def session(self, enhanced=False):
        s=g.Session({'protection_mode':'enhanced' if enhanced else 'proxy','health_interval_seconds':.001})
        s.child=mock.Mock();s.child.poll.return_value=None
        s.core=mock.Mock();s.core.poll.return_value=None
        s.emit=mock.Mock();s.gate.open();s.fail('电脑睡眠或网络发生变化',recoverable=True)
        return s

    def test_failed_session_releases_itself_if_guard_ui_has_gone(self):
        s=self.session()
        with mock.patch.dict(os.environ,{'CLAUDE_GUARD_UI_PID':'99999'}),mock.patch.object(g.os,'kill',side_effect=ProcessLookupError):
            worker=threading.Thread(target=s.watch);worker.start();worker.join(.15)
            ended=not worker.is_alive()
            s.stop.set();worker.join(1)
        self.assertTrue(ended,'Paused orphan holds session.lock forever after Guard exits')
        self.assertFalse(s.gate.enabled)
        s.child.terminate.assert_not_called()

    def test_explicit_resume_rechecks_same_baseline_without_restarting_client(self):
        s=self.session(True);s.filter_pid=123
        s.audit_thread=mock.Mock();s.audit_thread.is_alive.return_value=False
        with mock.patch.object(g,'check_controller') as config,mock.patch.object(g,'selected_node') as node,mock.patch.object(s,'check_egress') as egress,mock.patch.object(g.system_filter,'inspect') as filtering,mock.patch.object(g.subprocess,'Popen') as launch:
            with mock.patch.object(s,'start_audits') as audits:
                s.resume()
                audits.assert_called_once()
        self.assertTrue(s.gate.enabled);self.assertFalse(s.failed)
        config.assert_called();node.assert_called_once();egress.assert_called_once()
        filtering.assert_called_once_with(s.settings,123);launch.assert_not_called()
        s.child.terminate.assert_not_called()

    def test_resume_with_changed_ip_remains_closed(self):
        s=self.session()
        with mock.patch.object(g,'check_controller'),mock.patch.object(g,'selected_node'),mock.patch.object(s,'check_egress',side_effect=g.GuardError('出口不一致')):
            s.resume()
        self.assertTrue(s.failed);self.assertFalse(s.gate.enabled)
        self.assertEqual(s.emit.call_args.args[0],'RESUME_FAILED')

    def test_new_sleep_or_network_event_during_recheck_cannot_reopen_gate(self):
        s=self.session()
        with mock.patch.object(g,'check_controller'),mock.patch.object(g,'selected_node'),mock.patch.object(s,'check_egress',side_effect=lambda:s.gate.trip('another sleep')):
            s.resume()
        self.assertTrue(s.failed);self.assertFalse(s.gate.enabled)

    def test_stop_request_ends_backend_even_with_live_client(self):
        s=self.session();s.request_stop()
        self.assertTrue(s.stop.is_set());self.assertFalse(s.gate.enabled)
        s.child.terminate.assert_not_called();s.child.kill.assert_not_called()

    def test_stop_during_recheck_cannot_reopen_gate(self):
        s=self.session()
        with mock.patch.object(g,'check_controller'),mock.patch.object(g,'selected_node'),mock.patch.object(s,'check_egress',side_effect=s.request_stop):
            s.resume()
        self.assertTrue(s.stop.is_set());self.assertFalse(s.gate.enabled)

    def test_enhanced_filter_failure_never_resumes(self):
        s=self.session(True);s.filter_pid=123
        with mock.patch.object(g,'check_controller'),mock.patch.object(g,'selected_node'),mock.patch.object(g.system_filter,'inspect',side_effect=g.system_filter.FilterError('not enabled')),mock.patch.object(s,'check_egress') as probe:
            s.resume()
        probe.assert_not_called();self.assertFalse(s.gate.enabled)

    def test_auto_recovery_waits_for_retry_deadline(self):
        s=self.session()
        s.stop.wait=mock.Mock(side_effect=[False,True])
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(g.time,'monotonic',return_value=s.next_retry-1),mock.patch.object(s,'resume') as resume,mock.patch.object(g,'check_controller') as controller:
            s.watch(threading.Event())
        resume.assert_not_called();controller.assert_not_called()
        self.assertFalse(s.gate.enabled)

    def test_network_restored_automatically_resumes_after_full_checks(self):
        s=self.session();s.stop.wait=mock.Mock(side_effect=[False,True])
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(g.time,'monotonic',return_value=s.next_retry),mock.patch.object(g,'check_controller') as config,mock.patch.object(g,'selected_node') as node,mock.patch.object(s,'check_egress') as egress:
            s.watch(threading.Event())
        self.assertTrue(s.gate.enabled);self.assertFalse(s.failed)
        config.assert_called();node.assert_called_once();egress.assert_called_once()
        self.assertTrue(s.emit.call_args.kwargs['automatic'])

    def test_failed_auto_retry_stays_closed_and_schedules_next_attempt(self):
        s=self.session()
        with mock.patch.object(g.time,'monotonic',return_value=100),mock.patch.object(g,'check_controller',side_effect=TimeoutError):
            s.resume(automatic=True)
        self.assertFalse(s.gate.enabled);self.assertTrue(s.auto_retry)
        self.assertEqual(s.next_retry,105)
        self.assertTrue(s.emit.call_args.kwargs['automatic'])

    def test_observed_ip_change_requires_approval_even_if_original_ip_returns(self):
        s=self.session();s.settings.update(expected_ip='192.0.2.1',expected_country='TW')
        s.core_port=1;s.auth='fixture'
        conn=mock.Mock();conn.getresponse.return_value.status=200
        conn.getresponse.return_value.getheader.return_value=None
        conn.getresponse.return_value.read.return_value=b'ip=192.0.2.2\nloc=TW\n'
        with mock.patch.object(g.http.client,'HTTPSConnection',return_value=conn):
            with self.assertRaises(g.GuardError):s.check_egress()
        self.assertTrue(s.approval_required)
        with mock.patch.object(s,'check_egress') as probe:
            s.resume(automatic=True)
            s.resume()
        probe.assert_not_called();self.assertFalse(s.gate.enabled)
        self.assertFalse(s.auto_retry)

    def test_nontransient_failure_does_not_schedule_auto_recovery(self):
        s=self.session();s.fail('节点参数变化',recoverable=False)
        self.assertFalse(s.auto_retry)

    def test_real_timeout_path_automatically_recovers_on_next_successful_check(self):
        s=self.session();s.failed=False;s.auto_retry=False
        s.gate.reopen(s.gate.checkpoint())
        clock={'now':0,'ticks':0}
        def tick(_):
            clock['now']+=5;clock['ticks']+=1
            return clock['ticks']>=3
        s.stop.wait=mock.Mock(side_effect=tick)
        with mock.patch.dict(os.environ,{},clear=True),mock.patch.object(g.time,'monotonic',side_effect=lambda:clock['now']),mock.patch.object(g,'check_controller',side_effect=[TimeoutError(),True,True]),mock.patch.object(g,'selected_node'),mock.patch.object(s,'check_egress') as probe:
            s.watch(threading.Event())
        self.assertFalse(s.failed);self.assertTrue(s.gate.enabled)
        probe.assert_called_once()
        self.assertEqual(s.emit.call_args.args[0],'RESUMED')

    def test_invalid_probe_response_is_not_mistaken_for_a_changed_ip(self):
        s=self.session();s.settings.update(expected_ip='192.0.2.1',expected_country='TW')
        s.core_port=1;s.auth='fixture'
        conn=mock.Mock();conn.getresponse.return_value.status=200
        conn.getresponse.return_value.getheader.return_value=None
        conn.getresponse.return_value.read.return_value=b'upstream temporarily unavailable'
        with mock.patch.object(g.http.client,'HTTPSConnection',return_value=conn):
            with self.assertRaises(g.ConnectivityError):s.check_egress()
        self.assertFalse(s.approval_required)

    def test_node_parameter_change_stops_auto_retry_and_requires_approval(self):
        s=self.session()
        with mock.patch.object(g,'check_controller'),mock.patch.object(g,'selected_node',side_effect=g.ApprovalRequired('node changed')):
            s.resume(automatic=True)
        self.assertTrue(s.approval_required);self.assertFalse(s.auto_retry)
        self.assertFalse(s.gate.enabled)

    def test_existing_claude_is_reported_before_slow_filter_probe(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'settings.json').write_text(json.dumps({'protection_mode':'enhanced'}))
            with mock.patch.object(g,'ROOT',root),mock.patch.object(g,'RUNTIME',root/'runtime'),mock.patch.object(g.sys,'argv',['guard.py','launch']),mock.patch.object(g,'running_claude',return_value=[123]),mock.patch.object(g.system_filter,'wait_ready') as probe,mock.patch.object(g.Session,'start') as start:
                self.assertEqual(g.main(),1)
            probe.assert_not_called();start.assert_not_called()
            rows=[json.loads(line) for file in (root/'runtime').glob('*.jsonl') for line in file.read_text().splitlines()]
            self.assertIn('仍在运行',rows[-1]['message'])

    def test_real_backend_signals_recover_then_release_session_lock(self):
        # A separate Python fixture exercises main()'s actual signal handlers and
        # lock ownership. Every app/core/probe operation inside it is a fake.
        script='''
import sys,json,os
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,sys.argv[1]);import guard as g
root=Path(sys.argv[2]);g.ROOT=root;g.RUNTIME=root/'runtime'
g.running_claude=lambda:[]
g.check_controller=lambda _:True
g.selected_node=lambda _:{}
def start(self,create_gateway=True):
    self.core=SimpleNamespace(poll=lambda:None,terminate=lambda:None,wait=lambda *a:None)
    self.gate.open()
def launch(self):
    self.child=SimpleNamespace(poll=lambda:None,pid=0)
    self.emit('RUNNING')
g.Session.start=start;g.Session.launch=launch
g.Session.check_egress=lambda _:None
g.Session.start_audits=lambda _:None
sys.argv=['guard.py','launch'];raise SystemExit(g.main())
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'settings.json').write_text(json.dumps({'protection_mode':'proxy','health_interval_seconds':.01,'probe_interval_seconds':3600}))
            env={**os.environ,'CLAUDE_GUARD_UI_PID':str(os.getpid())}
            worker=subprocess.Popen([sys.executable,'-u','-c',script,str(ROOT/'src'),directory],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            consumed=0
            def until(kind):
                nonlocal consumed
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    for file in (root/'runtime').glob('*.jsonl'):
                        lines=file.read_text().splitlines(keepends=True)
                        while consumed<len(lines) and lines[consumed].endswith('\n'):
                            row=json.loads(lines[consumed]);consumed+=1
                            if row['kind']==kind:return
                    time.sleep(.005)
                self.fail('Fixture did not reach '+kind)
            try:
                until('RUNNING')
                worker.send_signal(signal.SIGUSR2);until('BLOCKED')
                worker.send_signal(signal.SIGHUP);until('RESUMED')
                worker.send_signal(signal.SIGUSR1);until('BLOCKED')
                worker.terminate();worker.wait(timeout=3)
                with (root/'runtime/session.lock').open('a') as lock:
                    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                if worker.poll() is None:worker.kill();worker.wait()
                worker.stdout.close();worker.stderr.close()

if __name__=='__main__':unittest.main(verbosity=2)
