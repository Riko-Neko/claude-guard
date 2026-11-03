#!/usr/bin/env python3
"""Prepare/apply a pinned LuLu maintenance transaction. Never starts Claude.

prepare: unprivileged, produces a reviewable plan and staged archive only.
apply: explicit admin invocation, refuses active Claude/Guard, backs up fixed
LuLu files, preserves unrelated rule objects, then performs one provider reload.
"""
import argparse
import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import pwd
import signal
import stat
import subprocess
import sys
sys.dont_write_bytecode = True
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from lulu_archive import Archive,make_policy,PolicyError
spec=importlib.util.spec_from_file_location('maintenance',ROOT/'tools/check_lulu_maintenance.py')
maintenance=importlib.util.module_from_spec(spec);spec.loader.exec_module(maintenance)
RULES=Path('/Library/Objective-See/LuLu/rules.plist')
PREFS=Path('/Library/Objective-See/LuLu/preferences.plist')
STATE=Path('/Library/Application Support/Claude Guard')
VERSION='4.5.6'
PORT=47831

class StalePlanError(PolicyError):
    """No system writes/reloads occurred; the caller may prepare a new plan."""
    pass

def digest(data):return hashlib.sha256(data).hexdigest()

def caller_uid():
    # A user app opened by the package installer can inherit SUDO_UID=0.
    # Only an actually privileged helper may use the explicit caller override.
    if os.geteuid()!=0:return os.getuid()
    try:return int(os.environ.get('SUDO_UID','0'))
    except ValueError:raise PolicyError('Invalid administrator caller identity')

def protected_paths(scope,uid):
    home=Path(pwd.getpwuid(uid).pw_dir)
    if scope=='fixture':return [str(home/'Library/Caches/ClaudeGuardDevelopment/Fixtures')+'/*', str(home/'Library/Caches/ClaudeGuardDevelopment/node_modules/electron/dist/Electron.app')+'/*']
    if scope=='claude':return ['/Applications/Claude.app/*',str(home/'Library/Application Support/Claude/claude-code')+'/*']
    raise PolicyError('Unknown protected scope')

def check_app():
    app=Path('/Applications/LuLu.app')
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if info.get('CFBundleShortVersionString')!=VERSION:raise PolicyError('Unsupported LuLu version; review required')
    r=subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],capture_output=True,timeout=15)
    d=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',str(app)],capture_output=True,text=True,timeout=8)
    if r.returncode or 'TeamIdentifier=VBG97UB4TA' not in d.stderr:raise PolicyError('LuLu signature mismatch')

def check_idle():
    state=maintenance.inspect()
    if not state['maintenance_allowed']:raise PolicyError('; '.join(state['reasons']))
    return state

def read_fixed(path):
    for p in [path.parent,path]:
        if p.is_symlink():raise PolicyError('Refusing symlink in system configuration path')
    s=path.stat()
    if s.st_uid!=0 or s.st_mode & 0o022:raise PolicyError('System configuration ownership/permissions unsafe')
    data=path.read_bytes()
    if len(data)>32*1024*1024:raise PolicyError('Configuration unexpectedly large')
    return data

def preferences(data):
    p=plistlib.loads(data)
    if p.get('currentProfile'):raise PolicyError('Custom LuLu profile needs review; not overwritten')
    if p.get('blockMode'):raise PolicyError('Existing global block mode needs review; not overridden')
    if p.get('useAllowList') or p.get('useBlockList'):raise PolicyError('Global list conflicts need review; not overwritten')
    p.update(disabled=False,passiveMode=True,passiveModeAction=0,passiveModeRules=0,
             allowLocalHost=True,allowDNS=False,noIconMode=True)
    return plistlib.dumps(p,fmt=plistlib.FMT_XML,sort_keys=False)

def candidate_rules(data,scope,uid):
    client=protected_paths(scope,uid)
    archive=Archive(data)
    if scope=='claude':
        pairs=archive.mapping(archive.root)
        removed=[]
        for key,ref,rules in archive.entries():
            flags=[
                isinstance(r.get('path'),str) and any(r['path'].startswith(path[:-1]) or r['path']==path for path in client)
                for r in rules]
            vendor=key.lower().startswith('com.anthropic.')
            if any(flags) and not all(flags) and not vendor:
                raise PolicyError('A shared signing group also covers unrelated programs; manual review required instead of broad deletion')
            target=vendor or any(flags)
            if target:removed.append(key)
        for key in removed:pairs.pop(key,None)
        archive.root['NS.keys']=[archive.add(k) for k in pairs]
        archive.root['NS.objects']=list(pairs.values())
        data=plistlib.dumps(archive.data,fmt=plistlib.FMT_BINARY,sort_keys=False)
    desired=client + (protected_paths('fixture',uid) if scope=='claude' else [])
    mapping={k:rules for k,_,rules in Archive(data).entries()}
    missing=[]
    for path in desired:
        if path not in mapping:missing.append(path);continue
        fields=sorted((r.get('action'),r.get('endpointAddr'),r.get('endpointPort'),bool(r.get('isDisabled'))) for r in mapping[path])
        if fields!=[(0,'*','*',False),(1,'127.0.0.1',str(PORT),False)]:
            raise PolicyError('Existing test scope differs; refusing to overwrite unrelated rules')
    return (make_policy(data,missing,PORT) if missing else data),len(missing)*2


def prepare(path,scope="fixture"):
    uid=caller_uid()
    if os.geteuid()==0 or uid==0:raise PolicyError('Prepare as the signed-in user, not root')
    check_app();check_idle()
    old_rules,old_prefs=read_fixed(RULES),read_fixed(PREFS)
    paths=protected_paths(scope,uid)
    new_rules,new_count=candidate_rules(old_rules,scope,uid)
    path=Path(path).resolve();path.parent.mkdir(parents=True,exist_ok=True)
    path.with_suffix('.staged-rules.plist').write_bytes(new_rules)
    path.with_suffix('.staged-preferences.plist').write_bytes(preferences(old_prefs))
    plan={'schema':1,'scope':scope,'uid':uid,'lulu_version':VERSION,'gateway_port':PORT,
          'protected_paths':paths,'rules_before_sha256':digest(old_rules),'preferences_before_sha256':digest(old_prefs),
          'new_rule_count':new_count,'starts_claude':False,'reloads_provider_once':True,
          'unrelated_rule_objects_preserved':True,'launch_allowed':False}
    path.write_text(json.dumps(plan,ensure_ascii=False,indent=2)+'\n')
    os.chmod(path,0o600)
    print(json.dumps({'prepared':str(path),'scope':scope,'new_rule_count':plan['new_rule_count'],
                      'system_changed':False,'starts_claude':False},ensure_ascii=False))

def atomic(path,data):
    with tempfile.NamedTemporaryFile(prefix='.guard-',dir=path.parent,delete=False) as f:
        temporary=Path(f.name)
        try:
            os.fchmod(f.fileno(),0o644);os.fchown(f.fileno(),0,0)
            f.write(data);f.flush();os.fsync(f.fileno())
            os.replace(temporary,path)
        finally:
            if temporary.exists():temporary.unlink()

def provider_processes():
    output=subprocess.check_output(['/bin/ps','-axo','pid=,comm='],text=True,timeout=5)
    found=[]
    for line in output.splitlines():
        row=line.strip().split(None,1)
        if len(row)==2 and Path(row[1]).name=='com.objective-see.lulu.extension' and row[1].startswith('/Library/SystemExtensions/'):
            found.append((int(row[0]),row[1]))
    return found

def apply(plan_path,allow_restart):
    if os.geteuid()!=0 or not allow_restart:raise PolicyError('Explicit administrator invocation and maintenance-restart flag required')
    plan=json.loads(Path(plan_path).read_text())
    uid=caller_uid()
    if uid==0 or plan.get('uid')!=uid or plan.get('schema')!=1 or plan.get('scope') not in ('fixture','claude'):raise PolicyError('Plan/user mismatch')
    scope=plan['scope']
    if plan.get('protected_paths')!=protected_paths(scope,uid) or plan.get('gateway_port')!=PORT:raise PolicyError('Unexpected protected scope')
    if plan.get('lulu_version')!=VERSION:raise PolicyError('Version mismatch')
    check_app();check_idle()
    before_rules,before_prefs=read_fixed(RULES),read_fixed(PREFS)
    if digest(before_rules)!=plan['rules_before_sha256'] or digest(before_prefs)!=plan['preferences_before_sha256']:
        raise StalePlanError('Configuration changed since preparation; prepare again instead of overwriting')
    candidates=provider_processes()
    if len(candidates)!=1:raise PolicyError('Cannot uniquely identify the active LuLu provider')
    old_pid,exe=candidates[0]
    details=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',exe],capture_output=True,text=True,timeout=8)
    if 'TeamIdentifier=VBG97UB4TA' not in details.stderr:raise PolicyError('Provider identity mismatch')
    data,_=candidate_rules(before_rules,scope,uid)
    prefs=preferences(before_prefs)
    STATE.mkdir(mode=0o755,parents=True,exist_ok=True)
    if STATE.is_symlink() or STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o022:raise PolicyError('State directory unsafe')
    with (STATE/'maintenance.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if read_fixed(RULES)!=before_rules or read_fixed(PREFS)!=before_prefs:
            raise StalePlanError('Configuration changed before maintenance; prepare again')
        backups=STATE/'backups';backups.mkdir(mode=0o700,exist_ok=True)
        backup=backups/datetime.datetime.now().strftime('%Y%m%d-%H%M%S');backup.mkdir(mode=0o700)
        (backup/'rules.plist').write_bytes(before_rules);(backup/'preferences.plist').write_bytes(before_prefs)
        check_idle()
        atomic(RULES,data);atomic(PREFS,prefs)
        if maintenance.guard.running_claude():
            atomic(RULES,before_rules);atomic(PREFS,before_prefs)
            raise PolicyError('Claude appeared during maintenance; rolled back disk files, did not restart provider')
        # A single, explicitly authorised maintenance restart; never used at runtime.
        os.kill(old_pid,signal.SIGKILL)
        deadline=time.monotonic()+25;new_pid=None
        while time.monotonic()<deadline:
            time.sleep(.5)
            found=provider_processes()
            if len(found)==1 and found[0][0]!=old_pid:
                new_pid=found[0][0];break
        if new_pid is None:raise PolicyError('Provider did not return; keep Claude closed and inspect the backup')
        if read_fixed(RULES)!=data:raise PolicyError('Rules changed during provider reload; validation required')
        if read_fixed(PREFS)!=prefs:raise PolicyError('Preferences changed during provider reload; validation required')
        state={'schema':1,'phase':scope+'_rules_written_pending_live_tests','lulu_version':VERSION,
               'scope':scope,'gateway_port':PORT,'protected_paths':protected_paths(scope,uid),
               'rules_sha256':digest(data),'preferences_sha256':digest(read_fixed(PREFS)),
               'provider_pid':new_pid,'backup':str(backup),'launch_allowed':False}
        owner=STATE/'package-installation-id'
        if owner.is_file():state['owner_id']=read_fixed(owner).decode().strip()
        atomic(STATE/'installation.json',(json.dumps(state,ensure_ascii=False,indent=2)+'\n').encode())
    print(json.dumps({'applied':True,'scope':scope,'provider_restarted_once':True,
                      'live_test_required':True,'claude_started':False,'launch_allowed':False},ensure_ascii=False))

if __name__=='__main__':
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('prepare');p.add_argument('--plan',required=True);p.add_argument('--scope',choices=['fixture','claude'],default='fixture')
    p=sub.add_parser('apply');p.add_argument('--plan',required=True);p.add_argument('--allow-maintenance-restart',action='store_true')
    args=parser.parse_args()
    try:
        if args.action=='prepare':prepare(args.plan,args.scope)
        else:apply(args.plan,args.allow_maintenance_restart)
    except Exception as e:
        row={'ok':False,'message':str(e),'claude_started':False,'launch_allowed':False}
        if isinstance(e,StalePlanError):row['code']='GUARD_POLICY_STALE_PLAN'
        print(json.dumps(row,ensure_ascii=False),file=sys.stderr)
        raise SystemExit(1)
