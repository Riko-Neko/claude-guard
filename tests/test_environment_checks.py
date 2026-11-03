"""Environment observations and warning policy. No real service or account access."""
from collections import deque
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import subprocess
import shutil
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'tools'))
import guard
import environment_checks as env
import leak_wizard

class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.baseline=dict(os='26.5',architecture='arm64',timezone='Asia/Taipei',utc_offset_minutes=480,languages='zh-Hans',claude_version='1.0',dns_resolvers=['127.0.0.1'])
        self.settings={'environment_baseline':self.baseline}
    def check(self,current=None,**kw):return {row['id']:row for row in env.evaluate(self.settings,current or self.baseline,{'tun':{'enable':True}},**kw)}
    def test_dns_and_webrtc_never_claim_complete_clearance(self):
        result=self.check(clock_skew=0)
        self.assertEqual(result['dns']['status'],'unverified')
        self.assertEqual(result['webrtc']['status'],'unverified')
    def test_dns_change_warns_without_claiming_proven_leak(self):
        current={**self.baseline,'dns_resolvers':['8.8.8.8']}
        result=self.check(current)
        self.assertEqual(result['dns']['status'],'warning')
        self.assertIn('不等同于',result['dns']['message'])
    def test_clock_or_timezone_change_warns(self):
        self.assertEqual(self.check(clock_skew=180)['time']['status'],'warning')
        self.assertEqual(self.check({**self.baseline,'timezone':'Asia/Hong_Kong'})['time']['status'],'warning')
    def test_missing_network_clock_is_unverified(self):self.assertEqual(self.check()['time']['status'],'unverified')
    def test_version_and_connection_rate_warn_without_content_review(self):
        self.assertEqual(self.check({**self.baseline,'claude_version':'2.0'})['environment']['status'],'warning')
        self.assertEqual(self.check(connections=601)['environment']['status'],'warning')
    def test_local_ice_no_public_address_is_not_a_pass(self):self.assertEqual(leak_wizard.classify(['192.168.0.1','test.local'],'1.1.1.1')['status'],'unverified')
    def test_local_ice_public_ipv6_bypass_warns(self):
        result=leak_wizard.classify(['1.1.1.1','2606:4700:4700::1111'],'1.1.1.1')
        self.assertEqual(result['status'],'warning')
        self.assertIn('非 Claude',result['scope'])
    def test_matching_local_ice_result_is_browser_observation_only(self):self.assertEqual(leak_wizard.classify(['1.1.1.1'],'1.1.1.1')['status'],'observed')
    def test_tun_off_requires_explicit_override(self):
        settings={'base_proxy_port':7897,'expected_node':'node'}
        data=[{'mode':'rule','tun':{'enable':False},'mixed-port':7897},{'proxies':{'AI':{'now':'node'}}}]
        with mock.patch.object(guard,'controller',side_effect=data):
            with self.assertRaises(guard.TunRequired):guard.check_controller(settings,require_tun=True)
        with mock.patch.object(guard,'controller',side_effect=data):self.assertTrue(guard.check_controller({**settings,'allow_system_proxy':True}))
    def test_environment_warning_leaves_gate_open_and_deduplicates(self):
        session=guard.Session(self.settings);session.gate.open();events=[]
        session.emit=lambda kind,**row:events.append((kind,row))
        with tempfile.TemporaryDirectory() as temp,mock.patch.object(guard,'RUNTIME',Path(temp)),mock.patch.object(env,'snapshot',return_value={**self.baseline,'timezone':'UTC'}),mock.patch.object(guard,'controller',return_value={'tun':{'enable':True}}):
            session.audit_environment();session.audit_environment()
        self.assertTrue(session.gate.enabled);self.assertFalse(session.failed)
        self.assertEqual(sum(row[1].get('check')=='time' for row in events),1)
    def test_staged_maintenance_imports_without_development_directory(self):
        import gui_setup
        with tempfile.TemporaryDirectory() as temp:
            stage=Path(temp)
            for folder,names in gui_setup.STAGED_FILES.items():
                (stage/folder).mkdir()
                for name in names:shutil.copy2(ROOT/folder/name,stage/folder/name)
            code="import sys;sys.path.insert(0,sys.argv[1]);import lulu_setup"
            result=subprocess.run([sys.executable,'-I','-B','-c',code,str(stage/'tools')],cwd=stage,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_ip_change_closes_gate_before_alert_and_keeps_old_baseline(self):
        session=guard.Session({'expected_ip':'1.1.1.1','expected_country':'TW'})
        session.core_port=123;session.auth='fixture';session.gate.open();states=[]
        session.emit=lambda kind,**kw:states.append((kind,session.gate.enabled))
        response=mock.Mock(status=200);response.getheader.return_value=None;response.read.return_value=b'ip=8.8.8.8\nloc=US\n'
        conn=mock.Mock();conn.getresponse.return_value=response
        with mock.patch.object(guard.http.client,'HTTPSConnection',return_value=conn):
            with self.assertRaises(guard.GuardError):session.check_egress()
        self.assertEqual(states,[('IP_CHANGED',False)])
        self.assertEqual(session.settings['expected_ip'],'1.1.1.1')
        with self.assertRaises(guard.GuardError):session.gate.open()

if __name__=='__main__':unittest.main()
