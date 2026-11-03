"""Replay native error details without inspecting an account or a real network."""
from pathlib import Path
import ssl
import subprocess
import sys
import unittest
from unittest import mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import guard
from diagnostics import failure_diagnostic

class FailureDiagnosticTests(unittest.TestCase):
    def test_tls_error_preserves_real_code_and_source_without_inventing_address(self):
        error=ssl.SSLEOFError(8,'[SSL: UNEXPECTED_EOF_WHILE_READING] EOF occurred in violation of protocol (_ssl.c:1006)')
        result=failure_diagnostic(error,'egress')
        self.assertEqual(result['error_type'],'SSLEOFError');self.assertEqual(result['errno'],8)
        self.assertEqual(result['reason'],'UNEXPECTED_EOF_WHILE_READING')
        self.assertEqual(result['source_location'],'_ssl.c:1006')
        self.assertNotIn('memory_address',result)
        self.assertIn('意外结束',result['summary'])

    def test_real_address_is_retained_only_if_reported(self):
        self.assertEqual(failure_diagnostic(RuntimeError('fault address 0x7ffe1234'))['memory_address'],'0x7ffe1234')

    def test_hex_error_code_is_not_mislabeled_as_a_memory_address(self):
        result=failure_diagnostic(RuntimeError('error code 0x80070005'))
        self.assertNotIn('memory_address',result)
        self.assertIn('0x80070005',result['raw_message'])

    def test_secrets_and_timeout_command_arguments_are_not_rendered(self):
        raw='https://name:password@example.test/path?token=fixturetoken Bearer SECRET_TOKEN password=privatevalue'
        result=failure_diagnostic(RuntimeError(raw))
        for secret in ('name:password','fixturetoken','SECRET_TOKEN','privatevalue'):self.assertNotIn(secret,result['raw_message'])
        timeout=failure_diagnostic(subprocess.TimeoutExpired(['fixture','--secret','privatevalue'],5),'node')
        self.assertNotIn('privatevalue',str(timeout));self.assertIn('5s',timeout['raw_message'])

    def test_timeout_identifies_the_step(self):
        self.assertIn('本机接口',failure_diagnostic(TimeoutError(),'controller')['summary'])
        self.assertIn('出口 IP',failure_diagnostic(TimeoutError(),'egress')['summary'])

    def test_health_failure_keeps_original_tls_details_and_still_closes_gate(self):
        session=guard.Session({'protection_mode':'proxy','expected_ip':'8.8.8.8','probe_interval_seconds':0})
        session.core=mock.Mock();session.core.poll.return_value=None
        session.child=mock.Mock();session.child.poll.return_value=None
        session.gate.open();session.stop.wait=mock.Mock(side_effect=[False,True]);session.emit=mock.Mock()
        error=ssl.SSLEOFError(8,'[SSL: UNEXPECTED_EOF_WHILE_READING] fixture (_ssl.c:1006)')
        with mock.patch.object(guard,'check_controller',return_value=True),mock.patch.object(guard,'selected_node'),mock.patch.object(session,'check_egress',side_effect=error):
            session.watch()
        self.assertFalse(session.gate.enabled);self.assertTrue(session.auto_retry)
        final=session.emit.call_args;self.assertEqual(final.args[0],'BLOCKED')
        self.assertEqual(final.kwargs['diagnostic']['reason'],'UNEXPECTED_EOF_WHILE_READING')
        self.assertEqual(final.kwargs['diagnostic']['stage'],'egress')

if __name__=='__main__':unittest.main()
