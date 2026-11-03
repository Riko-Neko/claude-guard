#!/usr/bin/env python3
"""Official LuLu shutdown/uninstall transaction. Never runs Claude or edits rules."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import time
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import guard
from admin_authorization import authorize
APP = Path('/Applications/LuLu.app')
RECEIPT = Path('/Library/Application Support/Claude Guard/installation.json')


def write_ready(path, ready, message=None):
    row={'ready':ready}
    if message:row['message']=message
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(row,ensure_ascii=False))
    temporary.chmod(0o600)
    temporary.replace(path)


def parent_running(pid):
    try:os.kill(pid,0)
    except ProcessLookupError:return False
    return True


def preflight_uninstall():
    if guard.running_claude():
        raise RuntimeError('请先完全退出 Claude 和 Claude Code，再关闭或卸载网络保护。')
    with (ROOT/'runtime/session.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('连接会话尚未结束，请稍后重试。')


def uninstall_after_exit(pid, ready, bundle):
    # This helper lives in the user Runtime, outside the app to be removed.
    # No component change or recycling may occur while Guard is still running.
    if pid != os.getppid():raise RuntimeError('卸载请求已失效，请从 Guard 重新开始。')
    if str(bundle)!='/Applications/Claude Guard.app':raise RuntimeError('请从应用程序中的 Claude Guard 开始卸载。')
    preflight_uninstall()
    write_ready(ready,True)
    deadline=time.monotonic()+30
    while parent_running(pid):
        if time.monotonic()>=deadline:raise RuntimeError('Claude Guard 尚未退出，卸载已停止。请退出后重试。')
        time.sleep(.1)
    outcome=perform('uninstall') or {}
    # Use Finder's recoverable trash operation and native permission handling.
    script='tell application "Finder" to delete (POSIX file '+json.dumps(str(bundle))+' as alias)'
    result=subprocess.run(['/usr/bin/osascript','-e',script],capture_output=True,text=True,timeout=120)
    if result.returncode or bundle.exists():
        raise RuntimeError('网络保护处理已完成，但 Guard 应用尚未移除。请将应用程序中的 Claude Guard 移到废纸篓。')
    if outcome.get('pending_reboot'):
        show_notice('Guard 和 LuLu 应用已移除。系统扩展已登记移除，将在下次重启后完成。')


def show_uninstall_error(message):
    language=os.environ.get('CLAUDE_GUARD_LANGUAGE','zh-Hant')
    prefix={'zh-Hant':'解除安裝未完成。應用程式仍保留，請重新開啟 Guard 後重試。',
            'zh-Hans':'卸载未完成。应用仍保留，请重新打开 Guard 后重试。',
            'en':'Uninstall did not complete. The app remains installed; reopen Guard to retry.'}[language if language in ('zh-Hant','zh-Hans','en') else 'en']
    script='display dialog '+json.dumps(prefix+'\n\n'+message,ensure_ascii=False)+' with title "Claude Guard" buttons {"OK"} default button 1 with icon caution'
    subprocess.run(['/usr/bin/osascript','-e',script],capture_output=True,text=True)

def show_notice(message):
    if message=='Guard 和 LuLu 应用已移除。系统扩展已登记移除，将在下次重启后完成。':
        language=os.environ.get('CLAUDE_GUARD_LANGUAGE','zh-Hant')
        message={'zh-Hant':'Guard 與 LuLu 應用程式已移除。系統擴展已登記移除，將在下次重新啟動後完成。',
                 'en':'Guard and LuLu have been removed. System extension removal is scheduled to complete after the next restart.'}.get(language,message)
    script='display dialog '+json.dumps(message,ensure_ascii=False)+' with title "Claude Guard" buttons {"OK"} default button 1'
    subprocess.run(['/usr/bin/osascript','-e',script],capture_output=True,text=True)


def extension_active():
    state = subprocess.run(['/usr/bin/systemextensionsctl', 'list'], capture_output=True, text=True, timeout=8)
    if state.returncode:
        raise RuntimeError('无法确认网络保护状态，操作未完成。')
    related = [line for line in state.stdout.splitlines() if 'com.objective-see.lulu.extension' in line]
    # Pending uninstall is not active filtering, but must also check the provider.
    # Even an activated-but-disabled registration still requires deactivation.
    active = any('waiting to uninstall' not in line for line in related)
    processes = subprocess.check_output(['/bin/ps', '-axo', 'comm='], text=True, timeout=5)
    return active or any(Path(line.strip()).name == 'com.objective-see.lulu.extension' for line in processes.splitlines())


def managed():
    if not RECEIPT.is_file() or RECEIPT.is_symlink():
        return False
    stat = RECEIPT.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:return False
    receipt=json.loads(RECEIPT.read_text())
    if receipt.get('scope')!='claude':return False
    if receipt.get('phase')=='component_removed':return False
    if receipt.get('owner_id'):
        marker=ROOT/'installation-id'
        return marker.is_file() and marker.read_text().strip()==receipt['owner_id']
    # Old machine-wide receipts are not proof a fresh standard install owns LuLu.
    settings_path=ROOT/'settings.json'
    if not settings_path.is_file():return False
    settings=json.loads(settings_path.read_text())
    return settings.get('protected_launch_enabled') is True and guard.enhanced(settings)


def verify():
    info = plistlib.loads((APP / 'Contents/Info.plist').read_bytes())
    if info.get('CFBundleShortVersionString') != '4.5.6':
        raise RuntimeError('LuLu 版本已变化，请通过官方界面关闭或卸载。')
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(APP)], check=True, capture_output=True, timeout=20)
    result = subprocess.run(['/usr/bin/codesign', '-dv', '--verbose=4', str(APP)], capture_output=True, text=True, timeout=8)
    if 'TeamIdentifier=VBG97UB4TA' not in result.stderr:
        raise RuntimeError('LuLu 签名不符，已停止操作。')


def perform(action):
    if guard.running_claude():
        raise RuntimeError('请先完全退出 Claude 和 Claude Code，再关闭或卸载网络保护。')
    runtime = ROOT / 'runtime'
    runtime.mkdir(exist_ok=True)
    with (runtime / 'session.lock').open('a') as session_lock:
        try:
            fcntl.flock(session_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('连接会话尚未结束，请稍后重试。')
        if not managed():
            # Never silently take over a LuLu installation not enrolled by Guard.
            if action != 'quit' and (APP.exists() or extension_active()):
                raise RuntimeError('未找到 Guard 管理记录，请通过 LuLu 官方界面卸载该组件。')
            return
        if not APP.exists() and extension_active():
            raise RuntimeError('LuLu 应用已缺失，但系统扩展仍在运行。请先恢复官方 LuLu，再重试扩展移除；Guard 已保留。')
        if APP.exists():
            verify()
            if guard.running_claude():
                raise RuntimeError('检测到 Claude 正在运行，已取消。')
            executable = str(APP / 'Contents/MacOS/LuLu')
            if extension_active():
                # System extension removal is a separate macOS authorization.
                # Submit it as the signed vendor app in the interactive USER
                # session; root cleanup must not delete that app beforehand.
                print(json.dumps({'stage':'extension_removal_authorization','context':'user'}),file=sys.stderr,flush=True)
                try:result=subprocess.run([executable,'-quit'],capture_output=True,text=True,timeout=180)
                except subprocess.TimeoutExpired:
                    raise RuntimeError('扩展移除授权尚未完成，已保留 LuLu 应用和配置。请完成系统提示后重试。')
                if result.returncode:print('LuLu deactivation: '+str(result.stdout)+str(result.stderr),file=sys.stderr)
        for _ in range(20):
            if not extension_active():
                if action == 'uninstall':
                    print(json.dumps({'stage':'component_cleanup','extension_stopped':True}),file=sys.stderr,flush=True)
                    owner=(ROOT/'installation-id').read_text().strip()
                    with tempfile.TemporaryDirectory(prefix='guard-uninstall-') as staging:
                        helper=Path(staging)/'uninstall_cleanup.py'
                        shutil.copyfile(Path(__file__).with_name('uninstall_cleanup.py'),helper)
                        result=authorize(shlex.join([sys.executable,'-B',str(helper),'--owner-id',owner]),'卸载 LuLu 网络保护组件')
                    if APP.exists() or extension_active():raise RuntimeError('组件清理尚未完成，Guard 应用已保留。')
                    try:return json.loads(result.stdout.strip())
                    except (AttributeError,TypeError,ValueError):return {}
                return {}
            time.sleep(.5)
        raise RuntimeError('macOS 尚未停止 LuLu 扩展，扩展移除授权未完成。已保留 LuLu 应用和配置，请完成系统提示后重试。')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['quit', 'uninstall'])
    parser.add_argument('--after-exit',type=int)
    parser.add_argument('--ready-file',type=Path)
    parser.add_argument('--remove-guard',type=Path)
    args = parser.parse_args()
    try:
        if args.after_exit is not None:
            if args.action!='uninstall' or args.ready_file is None or args.remove_guard is None:
                raise RuntimeError('卸载请求不完整，请重新开始。')
            uninstall_after_exit(args.after_exit,args.ready_file,args.remove_guard)
        else:perform(args.action)
        print(json.dumps({'ok': True, 'action': args.action}, ensure_ascii=False))
        return 0
    except Exception as exc:
        if args.after_exit is not None:
            if args.ready_file is not None and not args.ready_file.exists():write_ready(args.ready_file,False,str(exc))
            if not parent_running(args.after_exit):show_uninstall_error(str(exc))
        print(json.dumps({'ok': False, 'message': str(exc)}, ensure_ascii=False))
        return 1

if __name__ == '__main__':
    sys.exit(main())
