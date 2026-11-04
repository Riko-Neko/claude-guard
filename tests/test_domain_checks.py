"""Injected fixtures only: no real services, Claude, VPN or installed Guard."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('domain_fixture', ROOT/'src/domain_checks.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)


class DomainTests(unittest.TestCase):
    def rows(self):
        return [{**r, 'status':'passed', 'method':'route'} for r in d.TARGETS]

    def test_weights_and_core_prerequisites(self):
        rows = self.rows()
        self.assertEqual(sum(r['weight'] for r in rows), 90)
        self.assertEqual(sum(r['weight'] for r in rows if r.get('core')), 30)
        self.assertEqual(d.score(rows, {'status':'unavailable'}), 90)
        rows[0]['status']='pending'
        self.assertIsNone(d.score(rows, {'status':'ok','entries':[]}))
        rows[0]['status']='failed'
        self.assertEqual(d.score(rows, {}), 0)

    def test_core_subdomain_failure_and_any_observed_mismatch_zero(self):
        for target in ('api.anthropic.com','downloads.claude.ai'):
            rows=self.rows()
            next(r for r in rows if r['domain']==target)['status']='failed'
            self.assertEqual(d.score(rows, {}), 0)
        rows=self.rows()
        rows[-1]['status']='mismatch'
        self.assertEqual(d.score(rows, {'status':'ok','entries':[]}), 0)

    def test_supplement_only_after_primary_90_and_integer_partial_bonus(self):
        rows=self.rows()
        geo={'status':'ok','entries':[{'status':'passed'}]*7+[{'status':'failed'}]*6}
        self.assertEqual(d.score(rows, geo), 95)
        rows[-1]['status']='pending'
        self.assertEqual(d.score(rows, geo), 89)
        rows[-1]['status']='passed'
        self.assertEqual(d.score(rows, {'status':'ok','entries':[{'status':'passed'}]*13}), 100)
        self.assertEqual(d.score(rows, {'status':'ok','entries':[]}), 100)
        self.assertEqual(d.score(rows, {'status':'pending','entries':[]}), 90)

    def test_core_only_is_30_auxiliary_uncertainty_never_awards_points(self):
        rows=self.rows()
        for r in rows:
            if not r.get('core'):r['status']='pending'
        self.assertEqual(d.score(rows, {'status':'ok','entries':[]}), 30)

    def test_geosite_dedup_by_entire_scope_not_only_root_name(self):
        geo=d.parse_geosite(b'+.anthropic.com\napi.anthropic.com\n+.claude.ai\n+.claude.com\n+.claude.app\n+.claudeusercontent.com\n+.claudemcpcontent.com\n+.claude.dev\n+.claude.dev\nservd-anthropic-website.b-cdn.net\n')
        self.assertEqual({r['domain'] for r in geo['entries']},
                         {'claude.dev','servd-anthropic-website.b-cdn.net'})
        self.assertEqual(geo['total_entries'],9)
        self.assertEqual(len(geo['sha256']),64)

    def test_unsupported_or_empty_geosite_not_silently_counted_complete(self):
        for text in (b'',b'# empty\n',b'regexp:.*\n',b'+.claude.com/path\n',b'*.claude.com',b'\xff',b'a'*131073):
            with self.subTest(text=text[:40]),self.assertRaises((ValueError,UnicodeError)):
                d.parse_geosite(text)

    def test_trace_requires_same_host_valid_public_ip_and_real_trace_fields(self):
        host='api.anthropic.com'
        valid=b'h=api.anthropic.com\nip=8.8.8.8\nloc=TW\ncolo=TPE\n'
        self.assertEqual(d.trace_ip(200,valid,host),'8.8.8.8')
        for status,text in ((302,valid),(403,valid),(200,b'<html>ip=8.8.8.8</html>'),
                            (200,valid.replace(b'api.anthropic.com',b'www.cloudflare.com')),
                            (200,valid.replace(b'8.8.8.8',b'127.0.0.1')),
                            (200,valid+b'ip=1.1.1.1\n'),(200,b'x'*16385)):
            self.assertIsNone(d.trace_ip(status,text,host))

    def monitor(self, directory, query, route=lambda:True, publish=lambda r:None):
        return d.Monitor(query,route,publish,Path(directory)/'check.json')

    def test_trace_fallback_and_wildcard_is_never_dialed(self):
        calls=[]
        def query(host,path,limit):
            calls.append(host)
            return 404,b''
        with tempfile.TemporaryDirectory() as temp:
            monitor=self.monitor(temp,query)
            row=monitor._target(d.TARGETS[2],'8.8.8.8')
            self.assertEqual((row['status'],row['method'],row['trace_result']),('passed','route','unsupported'))
            monitor._target(next(t for t in d.TARGETS if t['domain']=='claude.app'),'8.8.8.8')
            self.assertEqual(calls,['api.anthropic.com'])
            monitor.query=mock.Mock(side_effect=TimeoutError)
            row=monitor._target(d.TARGETS[2],'8.8.8.8')
            self.assertEqual(row['method'],'route')
            self.assertEqual(row['trace_result'],'unavailable')

    def test_trace_ip_mismatch_preserved_and_no_direct_fallback(self):
        query=mock.Mock(return_value=(200,b'h=api.anthropic.com\nip=1.1.1.1\nloc=TW\ncolo=TPE\n'))
        with tempfile.TemporaryDirectory() as temp:
            monitor=self.monitor(temp,query)
            row=monitor._target(d.TARGETS[2],'8.8.8.8')
            self.assertEqual((row['status'],row['observed_ip']),('mismatch','1.1.1.1'))
            query.assert_called_once_with('api.anthropic.com','/cdn-cgi/trace',16384)
            monitor.route_check=lambda:False
            query.reset_mock()
            self.assertEqual(monitor._target(d.TARGETS[2],'8.8.8.8')['status'],'failed')
            query.assert_not_called()

    def test_core_root_trace_is_checked_without_claiming_all_subdomain_ips(self):
        query=mock.Mock(return_value=(200,b'h=anthropic.com\nip=8.8.8.8\nloc=TW\ncolo=TPE\n'))
        with tempfile.TemporaryDirectory() as temp:
            monitor=self.monitor(temp,query)
            row=monitor._target(d.TARGETS[0],'8.8.8.8')
            self.assertEqual((row['status'],row['method'],row['scope']),('passed','trace','suffix'))
            query.assert_called_once_with('anthropic.com','/cdn-cgi/trace',16384)

    def test_close_prevents_queued_queries(self):
        query=mock.Mock()
        with tempfile.TemporaryDirectory() as temp:
            monitor=self.monitor(temp,query)
            monitor.close()
            self.assertEqual(monitor._target(d.TARGETS[2],'8.8.8.8')['status'],'failed')
            self.assertEqual(monitor._geosite()['status'],'unavailable')
            query.assert_not_called()

    def test_incremental_results_old_generation_isolation_cache_and_close(self):
        blocked=threading.Event();entered=threading.Event();events=[]
        def query(host,path,limit):
            if host=='api.anthropic.com':entered.set();blocked.wait(2)
            if host==d.GEOSITE_HOST:return 200,b'+.anthropic.com\n+.claude.dev\n'
            return 404,b''
        with tempfile.TemporaryDirectory() as temp:
            monitor=self.monitor(temp,query,publish=lambda r:events.append(copy.deepcopy(r)))
            monitor.request('8.8.8.8')
            self.assertTrue(entered.wait(1))
            self.assertTrue(events)
            self.assertFalse(events[0]['complete'])
            monitor.request('1.1.1.1')
            blocked.set()
            self.assertTrue(monitor.finished.wait(3))
            self.assertEqual(events[-1]['ip'],'1.1.1.1')
            self.assertTrue(events[-1]['complete'])
            self.assertEqual(events[-1]['score'],100)
            self.assertTrue(all(e['ip']=='1.1.1.1' for e in events[next(i for i,e in enumerate(events) if e['ip']=='1.1.1.1'):]))
            self.assertEqual((Path(temp)/'check.json').stat().st_mode & 0o777,0o600)
            count=len(events);monitor.request('1.1.1.1');self.assertEqual(count,len(events))
            monitor.close();monitor.request('8.8.8.8',force=True);self.assertEqual(count,len(events))


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('guard_domain_fixture',ROOT/'src/guard.py')
        cls.g=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.g)

    def test_private_config_tamper_dead_core_and_stop_invalidate_route(self):
        g=self.g;s=g.Session({})
        with tempfile.TemporaryDirectory() as temp:
            s.temp=mock.Mock(name=temp);s.temp.name=temp
            path=Path(temp)/'core.json';path.write_bytes(b'{"rules":["MATCH,ApprovedNode"]}')
            s.core=mock.Mock();s.core.poll.return_value=None
            s.core_config_signature=hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertTrue(s.domain_route())
            path.write_bytes(b'{"rules":["MATCH,DIRECT"]}')
            self.assertFalse(s.domain_route())
            path.write_bytes(b'{"rules":["MATCH,ApprovedNode"]}')
            s.core.poll.return_value=1;self.assertFalse(s.domain_route())
            s.core.poll.return_value=None;s.stop.set();self.assertFalse(s.domain_route())

    def test_transport_only_authenticates_to_local_core_no_redirect_or_direct_retry(self):
        g=self.g;s=g.Session({});s.core_port=23456;s.auth='fixture-secret'
        response=mock.Mock(status=302);connection=mock.Mock();connection.getresponse.return_value=response
        with mock.patch.object(s,'domain_route',return_value=True),mock.patch.object(g.http.client,'HTTPSConnection',return_value=connection) as ctor:
            self.assertEqual(s.domain_query('api.anthropic.com','/cdn-cgi/trace',16384),(302,b''))
            self.assertEqual(ctor.call_args.args,('127.0.0.1',23456))
            connection.set_tunnel.assert_called_once_with('api.anthropic.com',443,{'Proxy-Authorization':'Basic fixture-secret'})
            connection.request.assert_called_once_with('GET','/cdn-cgi/trace',headers={'Host':'api.anthropic.com','Accept':'text/plain'})
            connection.request.side_effect=OSError('fixture')
            with self.assertRaises(OSError):s.domain_query('api.anthropic.com','/cdn-cgi/trace',16384)
            self.assertEqual(ctor.call_count,2)
            with self.assertRaises(g.GuardError):s.domain_query('attacker.test','/',16384)
            self.assertEqual(ctor.call_count,2)


if __name__=='__main__':unittest.main()
