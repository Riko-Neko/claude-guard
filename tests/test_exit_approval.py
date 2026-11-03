"""Explicit exit approval using fake probes and temporary settings, never Claude."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('approval_guard',ROOT/'src/guard.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

class ExitApprovalTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);patch=mock.patch.object(g,'ROOT',self.root);patch.start();self.addCleanup(patch.stop)
        self.settings={'protection_mode':'enhanced','expected_ip':'8.8.8.8','expected_country':'TW','node_sha256':'fixture','expected_node':'Fixture'}
        self.path=self.root/'settings.json';self.path.write_text(json.dumps(self.settings))
        self.session=g.Session(self.settings);self.session.filter_pid=42
        self.session.core=mock.Mock();self.session.core.poll.return_value=None
        self.session.pending_exit={'id':'fixture-proposal','ip':'1.1.1.1','country':'TW'}
        self.session.approval_required=True;self.session.failed=True
        self.session.gate.trip('fixture changed exit');self.session.emit=mock.Mock()
        self.command={'action':'approve_ip','proposal_id':'fixture-proposal','ip':'1.1.1.1'}
        for name in ('check_controller','selected_node'):
            patch=mock.patch.object(g,name);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(g.system_filter,'inspect',return_value=42);patch.start();self.addCleanup(patch.stop)

    def test_matching_click_rechecks_before_saving_only_new_ip(self):
        def check(**kwargs):
            self.assertFalse(self.session.gate.enabled)
            self.assertEqual(json.loads(self.path.read_text())['expected_ip'],'8.8.8.8')
            self.assertEqual(kwargs,{'expected_ip':'1.1.1.1'})
        with mock.patch.object(self.session,'check_egress',side_effect=check) as probe,mock.patch.object(g.subprocess,'Popen') as launch:
            self.assertTrue(self.session.approve_exit(self.command))
        probe.assert_called_once();launch.assert_not_called()
        saved=json.loads(self.path.read_text());self.assertEqual(saved['expected_ip'],'1.1.1.1')
        for key in self.settings:
            if key!='expected_ip':self.assertEqual(saved[key],self.settings[key])
        self.assertTrue(self.session.gate.enabled);self.assertFalse(self.session.approval_required)

    def test_stale_click_cannot_approve_a_different_candidate(self):
        for field,value in [('proposal_id','older-proposal'),('ip','9.9.9.9')]:
            with mock.patch.object(self.session,'check_egress') as probe:
                self.assertFalse(self.session.approve_exit({**self.command,field:value}))
            probe.assert_not_called()
        self.assertEqual(json.loads(self.path.read_text()),self.settings)
        self.assertFalse(self.session.gate.enabled)

    def test_country_change_requires_full_reconfiguration(self):
        self.session.pending_exit['country']='US'
        with mock.patch.object(self.session,'check_egress') as probe:
            self.assertFalse(self.session.approve_exit(self.command))
        probe.assert_not_called();self.assertFalse(self.session.gate.enabled)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)

    def test_new_network_event_during_confirmation_does_not_write_or_reopen(self):
        with mock.patch.object(self.session,'check_egress',side_effect=lambda **_:self.session.gate.trip('new route')):
            self.assertFalse(self.session.approve_exit(self.command))
        self.assertEqual(json.loads(self.path.read_text()),self.settings);self.assertFalse(self.session.gate.enabled)

    def test_changed_configuration_or_filter_failure_does_not_get_overwritten(self):
        self.path.write_text(json.dumps({**self.settings,'expected_node':'Different'}))
        with mock.patch.object(self.session,'check_egress'):
            self.assertFalse(self.session.approve_exit(self.command))
        self.assertEqual(json.loads(self.path.read_text())['expected_node'],'Different')
        self.assertFalse(self.session.gate.enabled)

    def test_filter_failure_cannot_save_or_resume_a_confirmed_ip(self):
        with mock.patch.object(g.system_filter,'inspect',side_effect=g.system_filter.FilterError('fixture unavailable')),mock.patch.object(self.session,'check_egress') as probe:
            self.assertFalse(self.session.approve_exit(self.command))
        probe.assert_not_called();self.assertFalse(self.session.gate.enabled)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)

    def test_filter_stops_during_probe_remains_closed(self):
        with mock.patch.object(g.system_filter,'inspect',side_effect=[42,g.system_filter.FilterError('stopped during probe')]),mock.patch.object(self.session,'check_egress') as probe:
            self.assertFalse(self.session.approve_exit(self.command))
        probe.assert_called_once();self.assertFalse(self.session.gate.enabled)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)

    def test_new_exit_during_confirmation_keeps_new_proposal_and_old_baseline(self):
        response=mock.Mock();response.status=200;response.getheader.return_value=None
        response.read.return_value=b'ip=9.9.9.9\nloc=TW\n'
        connection=mock.Mock();connection.getresponse.return_value=response
        self.session.core_port=12345;self.session.auth='FIXTURE';self.session.interactive_action='launch'
        with mock.patch.object(g.http.client,'HTTPSConnection',return_value=connection):
            self.assertFalse(self.session.approve_exit(self.command))
        self.assertEqual(self.session.pending_exit['ip'],'9.9.9.9')
        self.assertNotEqual(self.session.pending_exit['id'],self.command['proposal_id'])
        self.assertFalse(self.session.emit.call_args.kwargs['requires_reconfigure'])
        self.assertFalse(self.session.gate.enabled)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)

    def test_main_holds_initial_changed_exit_for_consent_and_check_never_launches(self):
        for action in ('check','launch'):
            with self.subTest(action=action):
                session=g.Session(dict(self.settings,protection_mode='proxy',health_interval_seconds=.001))
                self.path.write_text(json.dumps(session.settings))
                session.core=self.session.core;session.emit=mock.Mock()
                session.stop.wait=mock.Mock(side_effect=[False,True])
                session.pending_exit=dict(self.session.pending_exit)
                session.commands.put(self.command)
                def preflight(**_):
                    self.assertFalse(session.gate.enabled)
                    self.assertEqual(json.loads(self.path.read_text())['expected_ip'],'8.8.8.8')
                    raise g.ApprovalRequired('fixture new IP')
                with mock.patch.object(g,'RUNTIME',self.root/'runtime'),mock.patch.object(g,'Session',return_value=session),mock.patch.object(g.sys,'argv',['guard.py',action,'--interactive-approval']),mock.patch.object(g.threading.Thread,'start'),mock.patch.object(g,'running_claude',return_value=[]),mock.patch.object(session,'start',side_effect=preflight),mock.patch.object(session,'enable_reputation'),mock.patch.object(session,'check_egress'),mock.patch.object(session,'start_audits'),mock.patch.object(session,'launch') as launch,mock.patch.object(session,'close'),mock.patch.object(session,'open_log'),mock.patch.object(g.signal,'signal'),mock.patch.dict(os.environ,{},clear=True):
                    self.assertEqual(g.main(),0)
                self.assertEqual(json.loads(self.path.read_text())['expected_ip'],'1.1.1.1')
                if action=='check':launch.assert_not_called()
                else:launch.assert_called_once()

    def test_input_queues_consent_but_does_not_approve_by_itself(self):
        self.session.read_commands(io.StringIO(json.dumps(self.command)+'\n'))
        self.assertEqual(self.session.commands.qsize(),1)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)
        self.assertFalse(self.session.gate.enabled)

    def test_pending_exit_never_recovers_or_launches_without_consent(self):
        self.session.interactive_action='launch'
        self.session.stop.wait=mock.Mock(side_effect=[False,True])
        with mock.patch.object(self.session,'launch') as launch,mock.patch.object(self.session,'resume') as resume:
            self.session.watch()
        launch.assert_not_called();resume.assert_not_called()
        self.assertFalse(self.session.gate.enabled)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)

    def test_reputation_uses_only_private_proxy_and_never_changes_the_gate(self):
        self.session.core_port=12345;self.session.auth='FIXTURE'
        connection=mock.Mock();connection.request.side_effect=TimeoutError('fixture')
        with mock.patch.object(g.http.client,'HTTPSConnection',return_value=connection) as connect:
            with self.assertRaises(TimeoutError):self.session.reputation_json('api.ipquery.io','/8.8.8.8?format=json')
        self.assertEqual(connect.call_args.args[:2],('127.0.0.1',12345))
        connection.set_tunnel.assert_called_once_with('api.ipquery.io',443,{'Proxy-Authorization':'Basic FIXTURE'})
        self.assertFalse(self.session.gate.enabled)
        self.assertEqual(json.loads(self.path.read_text()),self.settings)

    def test_unknown_provider_is_rejected_before_any_connection(self):
        with mock.patch.object(g.http.client,'HTTPSConnection') as connect:
            with self.assertRaises(g.GuardError):self.session.reputation_json('untrusted.example','/')
        connect.assert_not_called()

if __name__=='__main__':unittest.main()
