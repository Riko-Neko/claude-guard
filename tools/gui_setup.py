#!/usr/bin/env python3
"""Menu-driven setup. Dialogs and macOS authorization only; never launches Claude."""
from pathlib import Path
import json
import shlex
import shutil
import tempfile
import os
import signal
import time
import subprocess
import sys
import traceback
import fcntl
import argparse
import hashlib
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import guard
import configure_vpn
from admin_authorization import authorize, AuthorizationError
STAGED_FILES={'tools':['lulu_setup.py','check_lulu_maintenance.py'],
              'src':['lulu_archive.py','guard.py','system_filter.py','environment_checks.py','ip_reputation.py','diagnostics.py','domain_checks.py','network_transport.py']}
EMBEDDED=False
REQUEST_ID=0
ENVIRONMENT_INTERVAL=3600
IP_REPUTATION_ENABLED=True
CANCEL_REQUESTED=False

def request_cancel(*_):
    global CANCEL_REQUESTED
    CANCEL_REQUESTED=True

def check_cancel():
    if CANCEL_REQUESTED:raise Cancelled()

def progress_fingerprint(settings):
    return hashlib.sha256(json.dumps(settings,sort_keys=True,ensure_ascii=False).encode()).hexdigest()

def save_progress(settings,stage):
    path=ROOT/'runtime/setup-progress.json'
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps({'stage':stage,'settings_sha256':progress_fingerprint(settings)}))
    temporary.chmod(0o600);temporary.replace(path)

def clear_progress():
    (ROOT/'runtime/setup-progress.json').unlink(missing_ok=True)

def load_resume(protection):
    if protection!='enhanced':return None
    try:
        settings=json.loads((ROOT/'settings.json').read_text())
        progress=json.loads((ROOT/'runtime/setup-progress.json').read_text())
        if (settings.get('configured') is True and settings.get('protected_launch_enabled') is not True
            and settings.get('protection_mode')==protection
            and settings.get('environment_check_seconds')==ENVIRONMENT_INTERVAL
            and settings.get('ip_reputation_enabled',True)==IP_REPUTATION_ENABLED
            and progress.get('stage') in ('dependency','policy','validation','enable')
            and progress.get('settings_sha256')==progress_fingerprint(settings)):
            return settings,progress['stage']
    except (OSError,ValueError,TypeError):pass
    return None

def record_setup(stage,error=None):
    runtime=ROOT/'runtime';runtime.mkdir(exist_ok=True)
    row={'stage':stage,'time':time.time()}
    if error is not None:
        row['error_type']=type(error).__name__
        if isinstance(error,guard.GuardError):row['message']=str(error)
    path=runtime/'setup-events.jsonl'
    with path.open('a') as log:log.write(json.dumps(row,ensure_ascii=False)+'\n')
    path.chmod(0o600)

def ui_request(title,body,buttons,details=None,groups=None):
    global REQUEST_ID
    check_cancel()
    REQUEST_ID+=1
    request_id=REQUEST_ID
    print(json.dumps({'kind':'request','id':request_id,'title':title,'body':body,
                      'buttons':buttons,'details':details or {},'groups':groups or []},ensure_ascii=False),flush=True)
    while True:
        line=sys.stdin.readline()
        check_cancel()
        if not line:raise Cancelled()
        try:answer=json.loads(line)
        except ValueError:continue
        if answer.get('id')!=request_id:continue
        if groups:
            value=answer.get('value')
            if value not in groups:raise Cancelled()
            return value
        index=answer.get('index')
        if not isinstance(index,int) or not 0<=index<len(buttons):raise Cancelled()
        if len(buttons)>1 and index==0:raise Cancelled()
        return buttons[index]

class Cancelled(Exception):pass

def apple(script):
    result=subprocess.run(['/usr/bin/osascript','-e',script],capture_output=True,text=True)
    if result.returncode:
        if '(-128)' in result.stderr:raise Cancelled()
        raise RuntimeError('授权未完成，请重试。')
    return result.stdout.strip()

def dialog(title,body,buttons=('取消','继续'),details=None):
    check_cancel()
    if EMBEDDED:return ui_request(title,body,buttons,details)
    values=', '.join(json.dumps(v,ensure_ascii=False) for v in buttons)
    cancel=' cancel button 1' if len(buttons)>1 else ''
    return apple('button returned of (display dialog '+json.dumps(body,ensure_ascii=False)+
                 ' with title '+json.dumps(title,ensure_ascii=False)+' buttons {'+values+'} default button '+str(len(buttons))+cancel+')')

def choose(groups):
    if EMBEDDED:return ui_request('选择代理组','',[],groups=groups)
    values=', '.join(json.dumps(v,ensure_ascii=False) for v in groups)
    result=apple('set selected to choose from list {'+values+'} with title "Claude Guard" with prompt "选择 Claude 使用的代理组"\nif selected is false then error number -128\nreturn item 1 of selected')
    return result

def phase(message):
    record_setup('phase:'+message)
    if EMBEDDED:print(json.dumps({'kind':'phase','message':message},ensure_ascii=False),flush=True)
    else:print(message,flush=True)

def run(script,*args):
    # Keep technical output in a local log; never ask users to enter CLI values.
    check_cancel()
    record_setup('step_started:'+script)
    log_path=ROOT/'runtime/gui-install.log'
    log_path.touch(mode=0o600,exist_ok=True);log_path.chmod(0o600)
    log_start=log_path.stat().st_size if log_path.exists() else 0
    with log_path.open('a') as log:
        if script in ('tools/ensure_lulu.py','tools/enable_user_trial.py'):
            process=subprocess.Popen([sys.executable,str(ROOT/script),*args],stdout=subprocess.PIPE,stderr=log,text=True)
            for line in process.stdout:
                log.write(line);log.flush()
                if line.startswith(('正在等待系统授权','正在等待 LuLu','正在等待网络保护','正在恢复网络保护','正在重新启用','正在尝试重新激活','正在备份并清理','请在 LuLu 安装引导','正在复查受控连接')):phase(line.strip())
            result=subprocess.CompletedProcess(process.args,process.wait())
        else:
            result=subprocess.run([sys.executable,str(ROOT/script),*args],stdout=log,stderr=log)
    if script=='tools/ensure_lulu.py' and result.returncode==75:raise Cancelled()
    if result.returncode:
        record_setup('step_failed:'+script)
        with log_path.open('rb') as log:
            log.seek(log_start)
            step_output=log.read().decode('utf-8',errors='replace')
        if script=='tools/ensure_lulu.py' and 'GUARD_SETUP_RESTART_REQUIRED' in step_output:
            raise RuntimeError('本次官方激活尚未完成，增强保护未启用。你可以稍后继续设置，或自行选择普通模式。')
        if script=='tools/ensure_lulu.py':
            states={
                'GUARD_SETUP_PREPARATION_FAILED':'旧组件准备尚未完成，未继续安装。请完成当前系统授权后重试；原设置会保留或备份，不要求重新启动电脑。',
                'GUARD_SETUP_AUTH_REQUEST_INVALID':'系统授权请求未能建立，请更新 Guard 后重试。这不是未完成 LuLu 扩展授权。',
                'GUARD_SETUP_RULE_STORAGE_FAILED':'LuLu 已完成引导，但未能保存规则文件。网络保护初始化恢复未完成；请从菜单查看日志，无需重复完成引导。',
                'GUARD_SETUP_INCOMPLETE_DATA':'检测到之前未完成的 LuLu 安装数据。请先通过 LuLu 官方方式卸载并清理，然后重新开始安装。',
                'GUARD_SETUP_STATE_UNKNOWN':'无法读取 macOS 网络扩展状态。请稍后重试；如果问题持续，请查看安装日志。',
                'GUARD_SETUP_APPROVAL_PENDING':'LuLu 已请求系统扩展授权，但 macOS 尚未完成授权。请检查是否有待处理的系统提示，完成后重新开始设置。',
                'GUARD_SETUP_INITIALIZATION_PENDING':'系统扩展已启用，但 LuLu 尚未完成初始化。请完成 LuLu 的安装引导后重新开始设置。',
                'GUARD_SETUP_ACTIVATION_MISSING':'LuLu 本次扩展激活尚未完成，增强保护未启用。请检查当前系统授权提示后重试；也可稍后处理或自行选择普通模式。',
            }
            for marker,message in states.items():
                if marker in step_output:raise RuntimeError(message)
        messages={
            'src/guard.py':'当前 VPN 未通过连接检查。请确认所选节点可用，再重新开始设置。',
            'tools/ensure_lulu.py':'网络保护安装未完成。请查看当前授权提示；详细信息可从菜单查看日志。',
            'tools/lulu_setup.py':'未能完成网络保护配置，Claude 启动功能暂未启用。请重新开始设置；如问题持续，可从菜单查看日志。',
            'tests/verify_lulu_flow.py':'网络保护未通过验证，Claude 启动功能暂未启用。请确认已完成系统授权，然后重新开始设置。',
            'tools/enable_user_trial.py':'连接检查未通过，暂时无法启动 Claude。请检查 VPN 后重试。',
        }
        raise RuntimeError(messages.get(script,'设置未完成，请重试。详细信息可从菜单查看日志。'))
    record_setup('step_finished:'+script)
    check_cancel()

def main(protection='enhanced',restart=False):
    (ROOT/'runtime').mkdir(exist_ok=True)
    record_setup('started')
    if guard.running_claude():
        dialog('请先退出 Claude','安装期间需要更新网络保护设置。请先完全退出 Claude 和 Claude Code，再重新开始设置。',('知道了',));return
    if restart:clear_progress()
    resumed=load_resume(protection)
    if resumed:
        settings,stage=resumed
        record_setup('resumed:'+stage)
        if EMBEDDED:
            print(json.dumps({'kind':'resume','details':{key:settings[key] for key in ('proxy_group','expected_node','expected_ip','expected_country')}},ensure_ascii=False),flush=True)
        phase('正在复核已确认的连接…')
        # Final enablement already checks controller/node, upstream AND gateway.
        if stage!='enable':run('src/guard.py','check')
        finish_enhanced(settings,stage)
        return
    dialog('设置 Claude Guard','Claude Guard 将检测当前网络。你可以使用系统 VPN、其他代理工具或直连网络，请确认当前连接是你希望 Claude 使用的网络，然后继续。')
    allow_system_proxy=False
    while True:
        phase('正在检测 VPN…')
        try:
            settings=configure_vpn.detect(allow_system_proxy=allow_system_proxy,choose_group_callback=choose)
            check_cancel()
            break
        except Cancelled:
            raise
        except guard.TunRequired:
            dialog('需要开启 TUN','当前未开启 TUN，Guard 默认不会放行。你可以取消并开启 TUN；若明确选择仅系统代理，Guard 只能控制经过自己的连接，无法保证其他组件不会直连。',('取消并开启 TUN','仍仅使用系统代理'))
            allow_system_proxy=True
        except Exception as error:
            record_setup('vpn_detection_failed',error)
            dialog('VPN 检测未通过',str(error) if isinstance(error,(ValueError,guard.GuardError)) else '暂时无法确认当前网络出口，请检查网络或代理后重新检测。',('取消','重新检测'))
    dialog('确认 Claude 使用的 VPN','请确认节点与出口。',('取消','保存并继续'),details={key:settings[key] for key in ('proxy_group','expected_node','expected_ip','expected_country')})
    # Saving revokes old launch permission before any maintenance occurs.
    settings['protection_mode']=protection
    settings['environment_check_seconds']=ENVIRONMENT_INTERVAL
    settings['ip_reputation_enabled']=IP_REPUTATION_ENABLED
    baseline=settings.get('environment_baseline',{})
    dialog('确认环境检查基准','确认设备环境检测基准。',('取消','确认并继续'),details={'timezone':baseline.get('timezone','未确认'),'claude_version':baseline.get('claude_version','未确认')})
    configure_vpn.save(settings)
    phase('正在检查连接…');run('src/guard.py','check')
    if protection=='proxy':
        run('tools/enable_user_trial.py')
        phase('基础保护已就绪')
        clear_progress()
        dialog('基础保护已准备就绪','VPN 和受控代理连接检查已通过。基础模式不会安装或启用 LuLu；它可以断开经过 Guard 的连接，但无法阻止绕过代理的直连。',('知道了',))
        return
    save_progress(settings,'dependency')
    finish_enhanced(settings,'dependency')

def apply_policy():
    run('tools/build_network_fixture.py')
    plan=ROOT/'runtime/lulu-clean-install-plan.json'
    for attempt in range(3):
        try:
            apply_policy_attempt(plan)
            return
        except AuthorizationError as error:
            log_path=ROOT/'runtime/gui-install.log'
            log_path.touch(mode=0o600,exist_ok=True);log_path.chmod(0o600)
            with log_path.open('a') as log:
                log.write(error.result.stdout+'\n'+error.result.stderr+'\n')
            record_setup('policy_authorization_failed',error)
            if '(-128)' in error.result.stderr:raise Cancelled()
            # Only a typed failure BEFORE any write/reload is safe to retry.
            if 'GUARD_POLICY_STALE_PLAN' not in error.result.stderr or attempt==2:raise
            phase('正在更新网络保护配置…')
            time.sleep(1)
            check_cancel()

def apply_policy_attempt(plan):
    run('tools/lulu_setup.py','prepare','--scope','claude','--plan',str(plan))
    # Privileged processes cannot reliably read Documents under macOS privacy rules.
    with tempfile.TemporaryDirectory(prefix='guard-maintenance-',dir=Path.home()/'Library/Caches') as temp:
        staged=Path(temp)
        for folder,names in STAGED_FILES.items():
            (staged/folder).mkdir()
            for name in names:shutil.copyfile(ROOT/folder/name,staged/folder/name)
        staged_plan=staged/'plan.json';shutil.copyfile(plan,staged_plan)
        command=shlex.join(['/usr/bin/env','SUDO_UID='+str(os.getuid()),'PYTHONDONTWRITEBYTECODE=1',sys.executable,'-B',
                            str(staged/'tools/lulu_setup.py'),'apply','--plan',str(staged_plan),'--allow-maintenance-restart'])
        check_cancel()
        authorize(command,'应用 Claude 网络保护规则')
        # Do not interrupt a privileged system operation halfway through.
        # Cancellation is honoured at this completed transaction boundary.

def finish_enhanced(settings,stage):
    if stage in ('dependency','policy'):
        phase('正在安装网络保护…' if stage=='dependency' else '正在确认网络保护状态…')
        if stage=='dependency':
            dialog('安装网络保护','Claude Guard 将准备 LuLu 网络保护组件。请完成 LuLu 的首次安装引导，并在 macOS 提示时完成授权。连接规则将在引导完成后自动配置。首次引导期间 LuLu 可能显示连接询问。')
        run('tools/ensure_lulu.py')
        save_progress(settings,'policy')
        check_cancel()
        phase('正在配置网络保护…')
        apply_policy()
        save_progress(settings,'validation')
        check_cancel()
    if stage!='enable':
        phase('正在检查网络保护…')
        run('tests/verify_lulu_flow.py','--wait-ready-seconds','25','--allow-loopback','--skip-electron')
        save_progress(settings,'enable')
    run('tools/enable_user_trial.py')
    # Onboarding overwrites noIconMode, and the subsequent maintenance reload
    # refreshes only the provider. Reload the stale GUI after all checks pass.
    try:run('tools/refresh_lulu_ui.py')
    except Cancelled:raise
    except RuntimeError as error:record_setup('gui_refresh_warning',error)
    clear_progress()
    phase('网络保护已就绪')
    dialog('Claude Guard 已准备就绪','VPN 连接和网络保护检查均已通过。请点击菜单栏盾牌，选择“检查并启动 Claude”开始使用。以后启动时，Guard 会先检查连接，再打开 Claude。',('知道了',))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--protection',choices=['proxy','enhanced'],default='enhanced')
    parser.add_argument('--embedded',action='store_true')
    parser.add_argument('--restart',action='store_true')
    parser.add_argument('--environment-interval',type=int,choices=[900,3600,10800],default=3600)
    parser.add_argument('--ip-reputation',choices=['enabled','disabled'],default='enabled')
    args=parser.parse_args()
    EMBEDDED=args.embedded
    ENVIRONMENT_INTERVAL=args.environment_interval
    IP_REPUTATION_ENABLED=args.ip_reputation=='enabled'
    signal.signal(signal.SIGUSR1,request_cancel)
    (ROOT/'runtime').mkdir(exist_ok=True)
    lock=(ROOT/'runtime/setup.lock').open('a')
    try:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            dialog('设置正在进行','Claude Guard 已有一个设置窗口正在运行。请返回该窗口继续操作。',('知道了',))
            sys.exit(0)
        main(args.protection,restart=args.restart)
    except Cancelled:
        phase('已取消设置')
    except Exception as error:
        with (ROOT/'runtime/gui-install.log').open('a') as log:traceback.print_exc(file=log)
        phase('设置未完成')
        try:dialog('设置未完成',str(error),('知道了',))
        except Exception:pass
        sys.exit(1)
