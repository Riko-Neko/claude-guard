#!/usr/bin/env python3
"""Finalize an owned LuLu uninstall only AFTER signed vendor deactivation.

No extension-removal commands, process killing, or rule changes. Remaining
application/data files are archived in a root-only directory, not purged.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import uuid

APP=Path('/Applications/LuLu.app')
DATA=Path('/Library/Objective-See/LuLu')
STATE=Path('/Library/Application Support/Claude Guard')
BUNDLE='com.objective-see.lulu.extension'


def trusted(path):
    if path.is_symlink() or path.parent.is_symlink():raise RuntimeError('网络保护路径状态异常，未清理文件。')
    info=path.stat()
    if info.st_uid!=0 or info.st_mode & 0o022:raise RuntimeError('网络保护记录权限异常，未清理文件。')
    return path.read_bytes()

def trusted_directory(path):
    if path.is_symlink():raise RuntimeError('网络保护目录状态异常，未清理文件。')
    info=path.stat()
    if info.st_uid!=0 or info.st_mode & 0o022:raise RuntimeError('网络保护目录权限异常，未清理文件。')


def assert_claude_closed():
    processes=subprocess.check_output(['/bin/ps','-axo','comm='],text=True,timeout=5)
    if any('/Claude.app/' in line or '/Claude/claude-code/' in line or Path(line.strip()).name=='claude' for line in processes.splitlines()):
        raise RuntimeError('请先完全退出 Claude 和 Claude Code。')
    return processes

def stopped_state(for_install=False):
    result=subprocess.run(['/usr/bin/systemextensionsctl','list'],capture_output=True,text=True,timeout=8)
    if result.returncode:raise RuntimeError('无法确认扩展移除状态，未清理文件。')
    rows=[line for line in result.stdout.splitlines() if BUNDLE in line]
    processes=assert_claude_closed()
    running=any(Path(line.strip()).name==BUNDLE for line in processes.splitlines())
    pending=any('waiting to uninstall' in line for line in rows)
    registered=any('waiting to uninstall' not in line for line in rows)
    enabling=any('[activated enabled]' in line or 'waiting for user' in line for line in rows)
    if running or (registered and not for_install) or (for_install and enabling):raise RuntimeError('LuLu 扩展仍未停止，已保留应用和配置。')
    return pending


def finalize(owner_id,previous_owner=None,for_install=False):
    if os.geteuid()!=0:raise RuntimeError('需要管理员授权以完成组件清理。')
    trusted_directory(STATE)
    lock=STATE/'maintenance.lock'
    if lock.is_symlink():raise RuntimeError('网络保护维护记录异常。')
    with lock.open('a') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return finalize_owned(owner_id,previous_owner,for_install)

def finalize_owned(owner_id,previous_owner=None,for_install=False):
    receipt=json.loads(trusted(STATE/'installation.json'))
    marker=trusted(STATE/'package-installation-id').decode().strip()
    expected_owner=previous_owner if for_install else owner_id
    if not owner_id or owner_id!=marker or receipt.get('owner_id')!=expected_owner or receipt.get('scope')!='claude':
        raise RuntimeError('网络保护管理记录不匹配，未清理文件。')
    if for_install:
        if not previous_owner or previous_owner==owner_id or receipt.get('phase') not in ('dependency_installed_pending_configuration','claude_rules_written_pending_live_tests'):
            raise RuntimeError('没有可确认的旧 Guard 组件，未清理文件。')
        prefs=DATA/'preferences.plist'
        if prefs.is_file():
            values=plistlib.loads(trusted(prefs))
            if any(values.get(key) for key in ('currentProfile','useAllowList','useBlockList','blockMode')):
                raise RuntimeError('LuLu 包含自定义设置，已保留原配置。')
    pending=stopped_state(for_install=True) if for_install else stopped_state()
    if APP.exists():
        if APP.is_symlink():raise RuntimeError('LuLu 应用路径异常，未清理文件。')
        info=plistlib.loads((APP/'Contents/Info.plist').read_bytes())
        subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True,capture_output=True,timeout=20)
        details=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',str(APP)],capture_output=True,text=True,timeout=8)
        if info.get('CFBundleShortVersionString')!='4.5.6' or 'TeamIdentifier=VBG97UB4TA' not in details.stderr:
            raise RuntimeError('LuLu 版本或签名已变化，未清理文件。')
        # This removes login registration and application files via the vendor.
        # The provider is already gone, so the vendor's XPC data cleanup may
        # report failure. Final state, rather than its exit code, is authoritative.
        if not for_install:
            result=subprocess.run([str(APP/'Contents/MacOS/LuLu'),'-uninstall'],capture_output=True,text=True,timeout=60)
            if result.returncode:print('Vendor cleanup: '+result.stdout+result.stderr,file=sys.stderr)
    pending=(stopped_state(for_install=True) if for_install else stopped_state()) or pending
    # Keep fixed-path leftovers recoverable; never delete other Objective-See tools.
    archive=STATE/'removed-components'
    if archive.is_symlink():raise RuntimeError('组件归档路径异常，未清理文件。')
    archive.mkdir(mode=0o700,exist_ok=True)
    trusted_directory(archive)
    destination=archive/str(uuid.uuid4());destination.mkdir(mode=0o700)
    (destination/'installation.json').write_text(json.dumps(receipt,ensure_ascii=False)+'\n')
    for path in ((DATA,) if for_install else (APP,DATA)):
        if path.is_symlink() or path.parent.is_symlink():raise RuntimeError('组件路径异常，未清理文件。')
        if path.exists():shutil.move(str(path),str(destination/path.name))
    result={'schema':1,'scope':'claude','owner_id':owner_id,'phase':'install_prepared' if for_install else 'component_removed',
            'pending_reboot':pending,'archive':str(destination),'launch_allowed':False}
    temporary=STATE/'installation.uninstall.tmp'
    if temporary.is_symlink():raise RuntimeError('卸载记录路径异常。')
    temporary.write_text(json.dumps(result,ensure_ascii=False)+'\n');temporary.chmod(0o644)
    temporary.replace(STATE/'installation.json')
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--owner-id',required=True)
    args=parser.parse_args()
    try:print(json.dumps(finalize(args.owner_id),ensure_ascii=False))
    except Exception as error:
        print(str(error),file=sys.stderr);sys.exit(1)
