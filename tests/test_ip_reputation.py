"""Only fake public providers and temporary cache files; no live IP queries."""
import importlib.util
from pathlib import Path
import tempfile
import threading
import time
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('rep',ROOT/'src/ip_reputation.py');rep=importlib.util.module_from_spec(spec);spec.loader.exec_module(rep)
IP='8.8.8.8'  # fixture only; this address is never requested over a network

class ReputationTests(unittest.TestCase):
    def test_missing_risk_data_never_becomes_a_green_score(self):
        source=rep.SOURCES[2]
        row=rep.normalize(source,IP,{'ip':IP,'country':'Example','asn':'AS0 Fixture'})
        self.assertEqual(row['status'],'metadata_only')
        self.assertIsNone(rep.aggregate(IP,[row])['score'])

    def test_uses_max_explicit_provider_score_and_exposes_coverage(self):
        rows=[{'status':'ok','score':0},{'status':'ok','score':73},{'status':'pending','score':None}]
        result=rep.aggregate(IP,rows)
        self.assertEqual(result['score'],73);self.assertEqual(result['scored_sources'],2)
        self.assertEqual(result['pending'],1);self.assertFalse(result['complete'])
        self.assertEqual(rep.aggregate(IP,[{'status':'ok','score':0}])['score'],1)

    def test_invalid_scores_and_wrong_address_are_not_accepted(self):
        for value in (True,-1,101,float('nan'),'0',None):self.assertIsNone(rep.score(value))
        with self.assertRaises(ValueError):rep.normalize(rep.SOURCES[0],IP,{'ip':'1.1.1.1','risk':{'risk_score':0}})
        for ip in ('127.0.0.1','10.0.0.1','::1','not-an-ip'):
            with self.assertRaises(ValueError):rep.public_ip(ip)

    def test_fast_result_is_published_before_slow_provider_finishes(self):
        slow=threading.Event();fast=threading.Event();reports=[]
        def query(host,path):
            if host=='proxycheck.io':slow.wait(2);return {'status':'ok',IP:{'risk':62,'proxy':'yes'}}
            if host=='api.ipquery.io':return {'ip':IP,'risk':{'risk_score':10,'is_vpn':False}}
            return {'ip':IP,'country':'Fixture'}
        def publish(report):
            reports.append(report)
            if report['score']==10 and report['pending']>0:fast.set()
        with tempfile.TemporaryDirectory() as directory:
            monitor=rep.Monitor(query,publish,Path(directory)/'risk.json')
            try:
                monitor.request(IP)
                self.assertTrue(fast.wait(1),'Do not wait for every provider')
                self.assertFalse(monitor.finished.is_set())
                slow.set();self.assertTrue(monitor.finished.wait(1))
                self.assertEqual(reports[-1]['score'],62)
            finally:slow.set();monitor.close()

    def test_provider_failures_remain_unknown_and_cached_refresh_is_bounded(self):
        calls=[];reports=[]
        def unavailable(host,path):calls.append(host);raise TimeoutError('fixture')
        with tempfile.TemporaryDirectory() as directory:
            monitor=rep.Monitor(unavailable,reports.append,Path(directory)/'risk.json')
            monitor.request(IP);self.assertTrue(monitor.finished.wait(1))
            self.assertIsNone(reports[-1]['score'])
            monitor.request(IP);self.assertEqual(len(calls),3)
            monitor.close();count=len(reports);monitor.request('1.1.1.1');self.assertEqual(len(reports),count)

    def test_slow_previous_ip_cannot_overwrite_new_ip_results(self):
        release=threading.Event();reports=[]
        def query(host,path):
            ip='1.1.1.1' if '1.1.1.1' in path else IP
            if ip==IP:release.wait(2)
            if host=='api.ipquery.io':return {'ip':ip,'risk':{'risk_score':91 if ip==IP else 12}}
            if host=='proxycheck.io':return {'status':'ok',ip:{'risk':82 if ip==IP else 15}}
            return {'ip':ip,'country':'Fixture'}
        with tempfile.TemporaryDirectory() as directory:
            monitor=rep.Monitor(query,reports.append,Path(directory)/'risk.json')
            try:
                monitor.request(IP);monitor.request('1.1.1.1')
                self.assertTrue(monitor.finished.wait(1));release.set()
                with monitor.lock:
                    self.assertEqual(monitor.current_ip,'1.1.1.1')
                    old_generation=monitor.generation-1
                monitor._complete(old_generation,0,{'status':'ok','score':99})
                self.assertEqual(reports[-1]['ip'],'1.1.1.1');self.assertEqual(reports[-1]['score'],15)
            finally:release.set();monitor.close()

if __name__=='__main__':unittest.main()
