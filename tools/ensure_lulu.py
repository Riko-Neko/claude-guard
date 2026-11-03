#!/usr/bin/env python3
"""Ensure the unmodified, pinned official dependency. Never launches Claude."""
from pathlib import Path
import hashlib
import json
import plistlib
import shlex
import shutil
import sys
import subprocess
import tempfile
import time
import urllib.request
from admin_authorization import authorize, AuthorizationError
from install_preparation import plan_preparation,prepare_previous

VERSION='4.5.6'
SHA='805519c0e6132e3f9449e939a8d33c564536f7e3d0a185a1f78e17a805e8de8a'
APP=Path('/Applications/LuLu.app')

def has_pending_removal(output):
    # This describes old cleanup work, not the outcome of a NEW activation.
    return any('com.objective-see.lulu.extension' in line and 'waiting to uninstall' in line for line in output.splitlines())

def extension_state():
    state=subprocess.run(['/usr/bin/systemextensionsctl','list'],capture_output=True,text=True,timeout=8)
    if state.returncode:raise SystemExit('GUARD_SETUP_STATE_UNKNOWN')
    return state

def onboarding_completed(base):
    try:return bool(plistlib.loads((base/'preferences.plist').read_bytes()).get('installTime'))
    except (OSError,ValueError,plistlib.InvalidFileException):return False

def verify(app):
    info=plistlib.loads((app/'Contents/Info.plist').read_bytes())
    if info.get('CFBundleShortVersionString')!=VERSION:raise SystemExit('已有 LuLu 版本未经本项目核验；保留原安装，不自动覆盖。')
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(app)],check=True,capture_output=True,timeout=20)
    r=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',str(app)],capture_output=True,text=True,timeout=8)
    if 'TeamIdentifier=VBG97UB4TA' not in r.stderr:raise SystemExit('LuLu 发布签名不符，已停止。')

def dependency_ready(extension_output,base=None):
    base=base or Path('/Library/Objective-See/LuLu')
    enabled=any('com.objective-see.lulu.extension ('+VERSION+'/'+VERSION+')' in line and '[activated enabled]' in line for line in extension_output.splitlines())
    if not enabled or not (base/'rules.plist').is_file():return False
    return onboarding_completed(base)

def recover_missing_rules():
    print('正在恢复网络保护初始化…',flush=True)
    with tempfile.TemporaryDirectory(prefix='guard-storage-recovery-') as staging:
        helper=Path(staging)/'recover_lulu_storage.py'
        shutil.copyfile(Path(__file__).with_name('recover_lulu_storage.py'),helper)
        try:authorize(shlex.join([sys.executable,'-B',str(helper)]),'恢复网络保护初始化')
        except AuthorizationError as error:
            if '(-128)' in error.result.stderr:raise SystemExit(75)
            print(error.result.stderr.strip(),flush=True)
            raise SystemExit('GUARD_SETUP_RULE_STORAGE_FAILED')

def main():
    # Observe old registrations without predicting whether a fresh activation
    # can succeed. The signed official app gets the activation attempt.
    state=extension_state()
    try:previous=plan_preparation()
    except Exception as error:
        print(str(error),flush=True);raise SystemExit('GUARD_SETUP_PREPARATION_FAILED')
    if not APP.exists():
        cache=Path.home()/'Library/Caches/ClaudeGuardDevelopment';cache.mkdir(parents=True,exist_ok=True)
        image=cache/('LuLu_'+VERSION+'.dmg')
        if not image.exists():
            url='https://github.com/objective-see/LuLu/releases/download/v'+VERSION+'/LuLu_'+VERSION+'.dmg'
            print('正在从官方来源下载 LuLu…',flush=True)
            with urllib.request.urlopen(url,timeout=45) as response:image.write_bytes(response.read(30*1024*1024))
        if hashlib.sha256(image.read_bytes()).hexdigest()!=SHA:raise SystemExit('安装包校验失败，未安装。')
        with tempfile.TemporaryDirectory(prefix='guard-official-lulu-') as temp:
            mount=Path(temp)/'volume';mount.mkdir()
            subprocess.run(['/usr/bin/hdiutil','attach',str(image),'-readonly','-nobrowse','-noautoopen','-mountpoint',str(mount)],check=True,capture_output=True,timeout=30)
            try:
                verify(mount/'LuLu.app')
                subprocess.run(['/usr/bin/ditto',str(mount/'LuLu.app'),str(APP)],check=True,timeout=30)
            finally:subprocess.run(['/usr/bin/hdiutil','detach',str(mount)],check=True,capture_output=True,timeout=20)
    verify(APP)
    if previous:
        print('正在备份并清理旧网络保护配置…',flush=True)
        try:prepare_previous(previous)
        except AuthorizationError as error:
            if '(-128)' in error.result.stderr:raise SystemExit(75)
            print(error.result.stderr,flush=True);raise SystemExit('GUARD_SETUP_PREPARATION_FAILED')
        except Exception as error:
            print(str(error),flush=True);raise SystemExit('GUARD_SETUP_PREPARATION_FAILED')
        state=extension_state()
    # Configure silent operation before LuLu can start asking about unrelated apps.
    with tempfile.TemporaryDirectory(prefix='guard-maintenance-',dir=Path.home()/'Library/Caches') as staging:
        helper=Path(staging)/'initialize_filter.py'
        shutil.copyfile(Path(__file__).with_name('initialize_filter.py'),helper)
        command=shlex.join([sys.executable,'-B',str(helper),'--claim-dependency'])
        # Avoid an extra administrator prompt when there is nothing to initialise.
        prefs=Path('/Library/Objective-See/LuLu/preferences.plist')
        result=None
        receipt=Path('/Library/Application Support/Claude Guard/installation.json')
        marker=Path('/Library/Application Support/Claude Guard/package-installation-id')
        try:owned=json.loads(receipt.read_text()).get('owner_id')==marker.read_text().strip()
        except (OSError,ValueError):owned=False
        if not prefs.is_file() or not owned:
            try:result=authorize(command,'准备网络保护的初始设置')
            except AuthorizationError as error:
                # Preserve helper output so the parent can distinguish cancellation,
                # a genuine restart, and a failed operation after authentication.
                result=error.result
                if '(-128)' in result.stderr:
                    print('GUARD_SETUP_AUTH_CANCELLED',flush=True)
                    raise SystemExit(75)
                if '(-50)' in result.stderr:
                    print('GUARD_SETUP_AUTH_REQUEST_INVALID',flush=True)
        if result is not None and result.returncode:
            print(result.stdout.strip(),flush=True)
            print(result.stderr.strip(),flush=True)
            if '此前未完成的 LuLu 安装数据' in result.stderr:
                print('GUARD_SETUP_INCOMPLETE_DATA',flush=True)
            raise SystemExit('网络保护准备未完成。请根据授权提示或日志中的说明处理后重试。')
    if dependency_ready(state.stdout):
        print('网络保护组件已就绪。',flush=True)
        return
    state=extension_state()
    existing=onboarding_completed(Path('/Library/Objective-See/LuLu'))
    print('正在重新启用已有网络保护…' if existing else '请在 LuLu 安装引导中完成设置…',flush=True)
    if has_pending_removal(state.stdout):print('正在尝试重新激活网络保护…',flush=True)
    # One launch only. Do not restart/reopen the onboarding app during setup.
    processes=subprocess.check_output(['/bin/ps','-axo','comm='],text=True).splitlines()
    if str(APP/'Contents/MacOS/LuLu') not in (row.strip() for row in processes):
        subprocess.run(['/usr/bin/open','-a',str(APP)],check=True)
    approval_explained=False
    initialization_explained=False
    rules_explained=False
    recovery_attempted=False
    missing_rules_since=None
    deadline=time.monotonic()+180
    while True:
        r=extension_state()
        enabled=any('com.objective-see.lulu.extension (4.5.6/4.5.6)' in line and '[activated enabled]' in line for line in r.stdout.splitlines())
        waiting=any('com.objective-see.lulu.extension (4.5.6/4.5.6)' in line and 'waiting for user' in line for line in r.stdout.splitlines())
        if waiting and not approval_explained:
            approval_explained=True
            print('正在等待系统授权完成…',flush=True)
        base=Path('/Library/Objective-See/LuLu')
        # The provider can create rules before the welcome wizard has saved its
        # final preferences. Starting maintenance at that point races onboarding.
        onboarding_done=onboarding_completed(base)
        if enabled and not onboarding_done and not initialization_explained:
            initialization_explained=True
            print('正在等待 LuLu 完成初始化…',flush=True)
        if enabled and onboarding_done and not (base/'rules.plist').is_file():
            if not rules_explained:
                rules_explained=True
                print('正在等待网络保护保存规则…',flush=True)
            now=time.monotonic()
            if missing_rules_since is None:missing_rules_since=now
            if not recovery_attempted and now-missing_rules_since>=5:
                recovery_attempted=True
                recover_missing_rules()
                if not (base/'rules.plist').is_file():raise SystemExit('GUARD_SETUP_RULE_STORAGE_FAILED')
        if enabled and (base/'rules.plist').is_file() and onboarding_done:
            print('网络保护组件已就绪。');break
        if time.monotonic()>=deadline:
            if waiting:raise SystemExit('GUARD_SETUP_APPROVAL_PENDING')
            if enabled:raise SystemExit('GUARD_SETUP_RULE_STORAGE_FAILED' if onboarding_done else 'GUARD_SETUP_INITIALIZATION_PENDING')
            raise SystemExit('GUARD_SETUP_ACTIVATION_MISSING')
        time.sleep(1)

if __name__=='__main__':main()
