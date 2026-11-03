#!/usr/bin/env python3
"""Prepare silent first-install preferences BEFORE the official filter is enabled."""
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import sys
import json
sys.dont_write_bytecode=True

def register_dependency():
    state=Path('/Library/Application Support/Claude Guard')
    marker=state/'package-installation-id'
    if not marker.is_file() or marker.is_symlink():return
    if marker.stat().st_uid!=0 or marker.stat().st_mode & 0o022:
        raise SystemExit('安装标识状态异常，请重新安装 Guard。')
    receipt=state/'installation.json'
    if state.is_symlink() or receipt.is_symlink():raise SystemExit('网络保护记录状态异常。')
    owner=marker.read_text().strip()
    if receipt.exists():
        old=json.loads(receipt.read_text())
        if old.get('scope')=='claude' and old.get('owner_id')==owner and old.get('phase') not in ('install_prepared','component_removed'):return
    data={'schema':1,'scope':'claude','owner_id':owner,'phase':'dependency_installed_pending_configuration','launch_allowed':False,'lulu_version':'4.5.6'}
    with tempfile.NamedTemporaryFile(dir=state,delete=False) as temp:
        name=Path(temp.name);os.fchmod(temp.fileno(),0o644)
        temp.write((json.dumps(data)+'\n').encode())
    name.replace(receipt)

def main(claim=False):
    if os.geteuid()!=0:raise SystemExit('需要管理员授权以准备网络保护。')
    rows=subprocess.check_output(['/bin/ps','-axo','pid=,comm='],text=True)
    for row in rows.splitlines():
        fields=row.strip().split(None,1)
        if len(fields)!=2:continue
        path=fields[1]
        if '/Claude.app/' in path or '/Claude/claude-code/' in path or Path(path).name=='claude':
            raise SystemExit('请先完全退出 Claude 和 Claude Code。')
    app='/Applications/LuLu.app'
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',app],check=True,capture_output=True)
    details=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',app],check=True,capture_output=True,text=True)
    if 'TeamIdentifier=VBG97UB4TA' not in details.stderr:raise SystemExit('网络保护组件签名不符。')
    if claim:register_dependency()
    directory=Path('/Library/Objective-See/LuLu');prefs=directory/'preferences.plist'
    if directory.is_symlink() or prefs.is_symlink():raise SystemExit('网络保护目录状态异常，已停止安装。')
    # A provider can outlive its on-disk data directory after an uninstall.
    # Restore storage before returning to official recovery; otherwise its
    # in-memory preferences/rules can never be persisted by the welcome wizard.
    directory.mkdir(parents=True,exist_ok=True,mode=0o755)
    if prefs.exists():
        old=plistlib.loads(prefs.read_bytes())
        # Preserve existing settings; the later maintenance step checks for
        # conflicts and updates preferences together with the protected rules.
        # Missing rules are recovered by the official provider's initialization,
        # not by deleting preferences or refusing to launch its recovery flow.
        return
    if any('com.objective-see.lulu.extension' in row for row in rows.splitlines()):
        # The official first-run wizard keys off installTime, and can reconnect
        # to an already enabled provider. Never alter live rules/preferences or
        # reject this recoverable state before giving that wizard a chance.
        print('GUARD_SETUP_OFFICIAL_RECOVERY',flush=True)
        return
    data={'passiveMode':True,'passiveModeAction':0,'passiveModeRules':0,
          'noIconMode':True,'disabled':False,'blockMode':False,
          'allowLocalHost':True,'allowDNS':False}
    # Do not write installTime: LuLu uses it as the first-run completion marker.
    # The official onboarding must activate the extension and save its own marker.
    with tempfile.NamedTemporaryFile(dir=directory,delete=False) as temp:
        name=Path(temp.name);os.fchmod(temp.fileno(),0o644)
        temp.write(plistlib.dumps(data))
    name.replace(prefs)
if __name__=='__main__':main(claim='--claim-dependency' in sys.argv)
