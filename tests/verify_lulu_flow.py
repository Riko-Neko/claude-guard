#!/usr/bin/env python3
"""Real per-process filter acceptance; only own C probes and stock Electron.

Never executes Claude or reads its account data. Does not modify any firewall,
Clash rule, or interface. Baseline control must work before a denial can pass.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import argparse

ROOT=Path(__file__).resolve().parents[1]
BASE=Path.home()/'Library/Caches/ClaudeGuardDevelopment'
FIXTURE=BASE/'Fixtures/guard-probe'
CONTROL=BASE/'Controls/guard-probe'
PORT=47831
results=[]
parser=argparse.ArgumentParser()
parser.add_argument('--wait-ready-seconds',type=float,default=0)
parser.add_argument('--allow-ipv6-loopback',action='store_true')
parser.add_argument('--allow-loopback',action='store_true')
parser.add_argument('--skip-electron',action='store_true')
args=parser.parse_args()
ready=False

def run(binary,kind,host,port):
    p=subprocess.run([str(binary),kind,host,str(port)],capture_output=True,text=True,timeout=6)
    return p.returncode

def record(name,ok,**detail):
    results.append({'test':name,'passed':bool(ok),**detail})
    print(json.dumps(results[-1]),flush=True)

def tcp_case(name,host,port,expected):
    baseline=run(CONTROL,'tcp',host,port)
    actual=run(FIXTURE,'tcp',host,port)
    record(name,baseline==0 and actual==expected,baseline_exit=baseline,fixture_exit=actual)

sockets=[]
try:
    for binary in [FIXTURE,CONTROL]:
        if not binary.is_file():raise RuntimeError('Build the account-free probes first')
    def listen(host,port=0,udp=False):
        af=socket.AF_INET6 if ':' in host else socket.AF_INET
        s=socket.socket(af,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        s.bind((host,port));s.settimeout(.8)
        if not udp:s.listen(20)
        sockets.append(s);return s
    gate=listen('127.0.0.1',PORT)
    other=listen('127.0.0.1');v6=listen('::1')
    if args.wait_ready_seconds:
        deadline=time.monotonic()+args.wait_ready_seconds;consecutive=0
        while time.monotonic()<deadline:
            # Public TCP is the invariant readiness check when loopback is an
            # explicit exception. A returned provider PID is insufficient.
            baseline=run(CONTROL,'tcp','1.1.1.1',443)
            denied=run(FIXTURE,'tcp','1.1.1.1',443)
            other.setblocking(False)
            try:
                while True:
                    c,_=other.accept();c.close()
            except BlockingIOError:pass
            finally:other.settimeout(.8)
            consecutive=consecutive+1 if baseline==0 and denied==13 else 0
            if consecutive>=2:ready=True;break
            time.sleep(.3)
        if not ready:raise RuntimeError('Provider process returned but filtering did not become ready')
    tcp_case('only-approved-gateway-allowed','127.0.0.1',PORT,0)
    tcp_case('ipv4-loopback-explicit-exception' if args.allow_loopback else 'other-ipv4-loopback-denied',
             '127.0.0.1',other.getsockname()[1],0 if args.allow_loopback else 13)
    tcp_case('ipv6-loopback-explicit-exception' if args.allow_ipv6_loopback or args.allow_loopback else 'ipv6-loopback-denied',
             '::1',v6.getsockname()[1],0 if args.allow_ipv6_loopback or args.allow_loopback else 13)
    tcp_case('existing-clash-loopback-explicit-exception' if args.allow_loopback else 'existing-clash-port-denied',
             '127.0.0.1',7897,0 if args.allow_loopback else 13)
    tcp_case('public-ipv4-direct-denied','1.1.1.1',443,13)
    tcp_case('public-ipv6-direct-denied','2606:4700:4700::1111',443,13)
    baseline=run(CONTROL,'child','1.1.1.1',443)
    actual=run(FIXTURE,'child','1.1.1.1',443)
    record('child-executable-in-protected-directory-denied',baseline==0 and actual==13,baseline_exit=baseline,fixture_exit=actual)
    for host in ['127.0.0.1','::1']:
        udp=listen(host,udp=True);port=udp.getsockname()[1]
        run(CONTROL,'udp',host,port)
        try:baseline=udp.recv(1024)==b'guard-fixture'
        except socket.timeout:baseline=False
        run(FIXTURE,'udp',host,port)
        try:leaked=bool(udp.recv(1024))
        except socket.timeout:leaked=False
        exception=args.allow_loopback or (host=='::1' and args.allow_ipv6_loopback)
        record('udp-'+host+('-explicit-exception' if exception else '-denied'),
               baseline and (leaked if exception else not leaked),control_received=baseline,fixture_received=leaked,
               explicit_exception=exception)
    for host in ['1.1.1.1','2606:4700:4700::1111']:
        # UDP sendto() may succeed before a later filtering drop. Require a
        # genuine reply to an account-free DNS query instead of its return size.
        baseline=run(CONTROL,'dns',host,53);actual=run(FIXTURE,'dns',host,53)
        record('public-udp-'+host+'-denied',baseline==0 and actual==13,baseline_exit=baseline,fixture_exit=actual)
    electron=BASE/'node_modules/electron/dist/Electron.app/Contents/MacOS/Electron'
    if not args.skip_electron:
      with tempfile.TemporaryDirectory(prefix='guard-filtered-electron-') as temp:
        env={k:v for k,v in os.environ.items() if not any(s in k.upper() for s in ['ANTHROPIC','CLAUDE','PROXY','ELECTRON_RUN_AS_NODE'])}
        env.update(GUARD_FIXTURE_DATA=temp,GUARD_FIXTURE_PORT=str(PORT))
        p=subprocess.run([str(electron),str(ROOT/'tests/electron_fixture.js')],env=env,capture_output=True,text=True,timeout=15)
        rows=[]
        for line in p.stdout.splitlines():
            try:rows.append(json.loads(line))
            except ValueError:pass
        native=any(r.get('kind')=='RENDER_OK' and r.get('sandboxed') and r.get('contextIsolated') for r in rows)
        complete=any(r.get('kind')=='FIXTURE_OK' for r in rows)
        record('filtered-stock-electron-native-sandbox-and-renderer',p.returncode==0 and native and complete,exit=p.returncode,native_security=bool(native))
finally:
    for s in sockets:s.close()
    report={'scope':'account-free C probes and official stock Electron only','claude_started':False,
            'provider_readiness_confirmed':ready,'loopback_explicit_exception':args.allow_loopback,
            'ipv6_loopback_explicit_exception':args.allow_ipv6_loopback or args.allow_loopback,
            'system_configuration_modified':False,'results':results,'all_passed':bool(results) and len(results)==9 and all(r['passed'] for r in results)}
    report['all_passed']=len(results)==(11 if args.skip_electron else 12) and all(r['passed'] for r in results)
    report['electron_compatibility_test_skipped']=args.skip_electron
    out=ROOT/'runtime/lulu-live-acceptance.json';out.write_text(json.dumps(report,indent=2))
raise SystemExit(0 if report['all_passed'] else 1)
