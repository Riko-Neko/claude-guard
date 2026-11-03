"""No real Claude execution: verify proxy-only launch contract and fault handling."""
import importlib.util
import os
from pathlib import Path
import plistlib
import tempfile
import threading
import time
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('guard_contract',ROOT/'src/guard.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
class ContractTests(unittest.TestCase):
    def test_launch_uses_native_client_proxy_without_sandbox_or_ssh_wrapper(self):
        with tempfile.TemporaryDirectory() as d:
            app=Path(d)/'Fixture.app';(app/'Contents/MacOS').mkdir(parents=True)
            (app/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'Fixture'}))
            s=g.Session({'protected_launch_enabled':True,'claude_app':str(app)})
            s.gate.open();s.proxy=mock.Mock(server_address=('127.0.0.1',47831))
            old_path=os.environ.get('PATH','');old_agent=os.environ.get('SSH_AUTH_SOCK')
            with mock.patch.object(g.system_filter,'inspect',return_value=42),mock.patch.object(g,'running_claude',return_value=[]),mock.patch.object(g.subprocess,'run',return_value=mock.Mock(returncode=0)),mock.patch.object(g.subprocess,'Popen',return_value=mock.Mock(pid=7)) as launch:
                s.launch()
            args=launch.call_args.args[0];env=launch.call_args.kwargs['env']
            self.assertEqual(args[0],str(app/'Contents/MacOS/Fixture'))
            self.assertFalse(any('sandbox' in a for a in args))
            self.assertIn('--proxy-server=http://127.0.0.1:47831',args)
            self.assertEqual(env['PATH'],old_path);self.assertEqual(env.get('SSH_AUTH_SOCK'),old_agent)
            self.assertNotIn('ProxyCommand',' '.join(args));self.assertNotIn('CLAUDE_GUARD_PROXY_PORT',env)
            self.assertIn('localhost',env['NO_PROXY'])
    def test_missing_real_filter_never_starts_account_client(self):
        s=g.Session({'protected_launch_enabled':True})
        with mock.patch.object(g.system_filter,'inspect',side_effect=g.system_filter.FilterError('not ready')),mock.patch.object(g.subprocess,'Popen') as launch:
            with self.assertRaises(g.GuardError):s.launch()
            launch.assert_not_called()
    def test_runtime_proxy_fault_closes_gate_without_terminating_client(self):
        s=g.Session({'health_interval_seconds':.001})
        s.core=mock.Mock();s.core.poll.return_value=None
        s.child=mock.Mock();s.child.poll.return_value=None;s.gate.open()
        with mock.patch.object(g,'check_controller',side_effect=g.GuardError('node changed')):
            t=threading.Thread(target=s.watch);t.start()
            for _ in range(100):
                if s.failed:break
                time.sleep(.005)
            s.stop.set();t.join(2)
        self.assertTrue(s.failed);self.assertFalse(s.gate.enabled)
        s.child.terminate.assert_not_called();s.child.kill.assert_not_called()
if __name__=='__main__':unittest.main(verbosity=2)
