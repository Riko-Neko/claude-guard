#!/usr/bin/env python3
"""One bounded recovery of an orphaned pre-install LuLu provider.

Only during a fresh Guard enrollment, after official onboarding, and only when
rules.plist is absent. Never writes rules or an onboarding completion marker.
The official provider regenerates its own default archive on restart.
"""
import datetime
import fcntl
import json
import os
from pathlib import Path
import plistlib
import re
import signal
import subprocess
import sys
import time
import uuid

STATE=Path('/Library/Application Support/Claude Guard')
BASE=Path('/Library/Objective-See/LuLu')
APP=Path('/Applications/LuLu.app')
BUNDLE='com.objective-see.lulu.extension'


def trusted(path):
    if path.is_symlink() or path.parent.is_symlink():raise RuntimeError('网络保护路径异常，未执行恢复。')
    info=path.stat()
    if info.st_uid!=0 or info.st_mode & 0o022:raise RuntimeError('网络保护文件权限异常，未执行恢复。')
    return path.read_bytes()

def trusted_state():
    info=STATE.stat()
    if STATE.is_symlink() or info.st_uid!=0 or info.st_mode & 0o022:raise RuntimeError('网络保护目录权限异常。')


def processes():
    return subprocess.check_output(['/bin/ps','-axo','pid=,comm='],text=True,timeout=5).splitlines()


def provider(rows):
    found=[]
    for row in rows:
        parts=row.strip().split(None,1)
        if len(parts)!=2:continue
        if '/Claude.app/' in parts[1] or '/Claude/claude-code/' in parts[1] or Path(parts[1]).name=='claude':
            raise RuntimeError('请先完全退出 Claude 和 Claude Code。')
        if parts[1].startswith('/Library/SystemExtensions/') and Path(parts[1]).name==BUNDLE:
            found.append((int(parts[0]),parts[1]))
    if len(found)!=1:raise RuntimeError('无法确认需要恢复的旧服务，未执行恢复。')
    return found[0]


def elapsed_seconds(value):
    if not re.fullmatch(r'(?:\d+-)?\d+:\d\d(?::\d\d)?',value.strip()):raise RuntimeError('无法确认旧服务启动时间。')
    day,clock=(value.strip().split('-',1) if '-' in value else ('0',value.strip()))
    values=[int(v) for v in clock.split(':')]
    total=0
    for part in values:total=total*60+part
    return int(day)*86400+total


def preflight():
    marker=STATE/'package-installation-id'
    owner=trusted(marker).decode().strip()
    receipt=json.loads(trusted(STATE/'installation.json'))
    if receipt.get('scope')!='claude' or receipt.get('owner_id')!=owner or receipt.get('phase')!='dependency_installed_pending_configuration':
        raise RuntimeError('当前不是新的组件安装，不能自动重建已有规则。')
    if (BASE/'rules.plist').exists():return None
    prefs_bytes=trusted(BASE/'preferences.plist');prefs=plistlib.loads(prefs_bytes)
    installed=prefs.get('installTime')
    if not isinstance(installed,datetime.datetime):raise RuntimeError('请先完成 LuLu 安装引导。')
    stamp=installed.replace(tzinfo=datetime.timezone.utc).timestamp() if installed.tzinfo is None else installed.timestamp()
    if stamp < marker.stat().st_mtime-5:raise RuntimeError('检测到既有 LuLu 设置，未自动重新初始化。')
    if any(prefs.get(key) for key in ('currentProfile','useAllowList','useBlockList','blockMode')):
        raise RuntimeError('检测到自定义网络保护设置，未自动重新初始化。')
    state=subprocess.run(['/usr/bin/systemextensionsctl','list'],capture_output=True,text=True,timeout=8)
    if state.returncode or not any(BUNDLE+' (4.5.6/4.5.6)' in line and '[activated enabled]' in line for line in state.stdout.splitlines()):
        raise RuntimeError('网络扩展尚未启用，未执行恢复。')
    pid,executable=provider(processes())
    age=elapsed_seconds(subprocess.check_output(['/bin/ps','-p',str(pid),'-o','etime='],text=True,timeout=5))
    if time.time()-age >= marker.stat().st_mtime-2:
        raise RuntimeError('当前服务并非安装前的旧服务，未执行重复恢复。')
    app_info=plistlib.loads((APP/'Contents/Info.plist').read_bytes())
    if app_info.get('CFBundleShortVersionString')!='4.5.6':raise RuntimeError('LuLu 版本不符，未执行恢复。')
    for path in (str(APP),executable):
        subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',path],check=True,capture_output=True,timeout=20)
        details=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',path],capture_output=True,text=True,timeout=8)
        if 'TeamIdentifier=VBG97UB4TA' not in details.stderr:raise RuntimeError('网络保护签名不符，未执行恢复。')
    return pid,executable,prefs_bytes


def recover():
    if os.geteuid()!=0:raise RuntimeError('需要管理员授权以恢复网络保护初始化。')
    trusted_state()
    lock=STATE/'maintenance.lock'
    if lock.is_symlink():raise RuntimeError('网络保护维护记录异常。')
    with lock.open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        plan=preflight()
        if plan is None:return {'restarted':False,'rules_present':True}
        pid,executable,prefs=plan
        backup=STATE/('storage-recovery-'+str(uuid.uuid4()))
        backup.mkdir(mode=0o700)
        (backup/'preferences.plist').write_bytes(prefs)
        # Recheck immediately before the one maintenance restart. Never replace
        # a rule file that appeared in the meantime or stop an ambiguous process.
        if (BASE/'rules.plist').exists():return {'restarted':False,'rules_present':True}
        if provider(processes())!=(pid,executable):raise RuntimeError('服务状态已变化，已取消恢复。')
        os.kill(pid,signal.SIGKILL)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            time.sleep(.5)
            try:new_pid,_=provider(processes())
            except RuntimeError:continue
            if new_pid!=pid and (BASE/'rules.plist').is_file():
                archive=plistlib.loads(trusted(BASE/'rules.plist'))
                if archive.get('$archiver')!='NSKeyedArchiver':raise RuntimeError('LuLu 生成的规则格式异常，未继续设置。')
                return {'restarted':True,'rules_present':True,'claude_started':False}
        raise RuntimeError('LuLu 仍未保存规则文件，恢复未完成。请保持 Claude 关闭。')

if __name__=='__main__':
    try:print(json.dumps(recover(),ensure_ascii=False))
    except Exception as error:print(str(error),file=sys.stderr);sys.exit(1)
