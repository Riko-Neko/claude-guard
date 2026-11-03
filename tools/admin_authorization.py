"""One macOS-managed interactive authorization request.

The system chooses available authentication methods. Never collects credentials
or claims LocalAuthentication alone grants administrator privileges.
"""
import json
import os
import subprocess
import sys

class AuthorizationError(RuntimeError):
    def __init__(self, message, result):
        super().__init__(message)
        self.result = result


def authorize(command, reason):
    language=os.environ.get('CLAUDE_GUARD_LANGUAGE','zh-Hant')
    reasons={
        '准备网络保护的初始设置':('準備網路保護的初始設定','Prepare initial network protection settings'),
        '恢复网络保护初始化':('恢復網路保護初始化','Recover network protection initialization'),
        '备份并清理旧网络保护配置':('備份並清理舊網路保護設定','Back up and prepare previous network protection settings'),
        '应用 Claude 网络保护规则':('套用 Claude 網路保護規則','Apply Claude network protection rules'),
        '卸载 LuLu 网络保护组件':('解除安裝 LuLu 網路保護元件','Uninstall the LuLu network protection component')}
    if reason in reasons:
        if language=='zh-Hant':reason=reasons[reason][0]
        elif language=='en':reason=reasons[reason][1]
    script = ('do shell script ' + json.dumps(command, ensure_ascii=False)
              + ' with prompt ' + json.dumps('Claude Guard：' + reason, ensure_ascii=False)
              + ' with administrator privileges')
    # Standard Additions requires a password whenever `user name` is supplied.
    # Do not supply either credential: macOS owns the account selection and UI.
    result = subprocess.run(['/usr/bin/osascript', '-e', script], capture_output=True, text=True)
    if result.returncode:
        # Callers redirect stderr to private installation/uninstall logs. Keep
        # the actual operation failure, without treating authentication as proof
        # that the requested helper completed successfully.
        print('Guard administrator operation failed: '+reason, file=sys.stderr, flush=True)
        print(result.stderr.strip(), file=sys.stderr, flush=True)
        if '(-128)' in result.stderr:
            raise AuthorizationError('已取消管理员授权，未完成此操作。', result)
        if '(-50)' in result.stderr:
            raise AuthorizationError('系统授权请求未能建立，请更新 Guard 后重试。', result)
        raise AuthorizationError('管理员授权或操作未完成，请查看安装日志。', result)
    return result
