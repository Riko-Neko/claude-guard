"""Read-only LuLu enforcement preflight. Never installs, edits, or reloads rules."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
from lulu_archive import Archive

class FilterError(RuntimeError):pass
BASE=Path('/Library/Objective-See/LuLu')
RECEIPT=Path('/Library/Application Support/Claude Guard/installation.json')

def owned_bytes(path):
    path=Path(path)
    if path.is_symlink():raise FilterError('系统过滤配置是符号链接，拒绝启动')
    s=path.stat()
    if s.st_uid!=0 or s.st_mode&0o022:raise FilterError('系统过滤配置权限不符合要求')
    return path.read_bytes()

def inspect(settings,pinned_pid=None):
    if not isinstance(settings.get('claude_app'),str):raise FilterError('Claude 路径尚未配置，请先完成设置')
    receipt=json.loads(owned_bytes(RECEIPT))
    if receipt.get('scope')!='claude' or receipt.get('lulu_version')!='4.5.6':raise FilterError('Claude 的系统过滤规则尚未安装')
    port=settings.get('gateway_port',47831)
    if receipt.get('gateway_port')!=port:raise FilterError('受控代理端口与系统规则不一致')
    expected=[str(Path(settings['claude_app']))+'/*',str(Path.home()/'Library/Application Support/Claude/claude-code')+'/*']
    if receipt.get('protected_paths')!=expected:raise FilterError('受保护程序范围与当前机器不一致')
    prefs=plistlib.loads(owned_bytes(BASE/'preferences.plist'))
    if prefs.get('disabled') or prefs.get('blockMode') or prefs.get('currentProfile') or prefs.get('useAllowList') or prefs.get('useBlockList'):
        raise FilterError('过滤器被停用、切换配置或启用了全局例外')
    if not prefs.get('passiveMode') or prefs.get('passiveModeAction')!=0 or prefs.get('passiveModeRules')!=0:
        raise FilterError('网络保护的默认连接处理已变化，请先完成网络保护配置')
    if not prefs.get('allowLocalHost'):raise FilterError('本机通信例外尚未配置，避免影响工具和 SSH')
    entries=list(Archive(owned_bytes(BASE/'rules.plist')).entries())
    mapping={key:rules for key,_,rules in entries}
    for path in expected:
        rules=mapping.get(path,[])
        normalized=sorted((r.get('action'),r.get('endpointAddr'),r.get('endpointPort'),bool(r.get('isDisabled'))) for r in rules)
        if normalized!=[(0,'*','*',False),(1,'127.0.0.1',str(port),False)]:raise FilterError('Claude 过滤规则缺失或被修改')
    for key,_,rules in entries:
        if key in expected:continue
        for r in rules:
            path=r.get('path','')
            overlaps=path=='*' or any(path.startswith(p[:-1]) or (path.endswith('/*') and p.startswith(path[:-1])) for p in expected)
            if overlaps and r.get('action')==1 and not r.get('isDisabled'):
                raise FilterError('存在覆盖 Claude 的额外放行规则，需要维护复核')
    extension=subprocess.run(['/usr/bin/systemextensionsctl','list'],capture_output=True,text=True,timeout=5)
    if extension.returncode or not any('com.objective-see.lulu.extension (4.5.6/4.5.6)' in row and '[activated enabled]' in row for row in extension.stdout.splitlines()):
        raise FilterError('指定系统过滤扩展没有启用')
    output=subprocess.check_output(['/bin/ps','-axo','pid=,comm='],text=True,timeout=5)
    pids=[]
    for line in output.splitlines():
        row=line.strip().split(None,1)
        if len(row)==2 and row[1].startswith('/Library/SystemExtensions/') and Path(row[1]).name=='com.objective-see.lulu.extension':pids.append(int(row[0]))
    if len(pids)!=1 or (pinned_pid is not None and pids[0]!=pinned_pid):raise FilterError('过滤扩展停止或重启，需要重新检查')
    return pids[0]

def wait_ready(settings,timeout=20):
    """One account-free canary before launch; never execute the client to test it."""
    import time
    base=Path.home()/'Library/Caches/ClaudeGuardDevelopment'
    fixture,control=base/'Fixtures/guard-probe',base/'Controls/guard-probe'
    if not fixture.is_file() or not control.is_file():raise FilterError('启动探针缺失，请重新运行安装入口')
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        baseline=subprocess.run([str(control),'tcp','1.1.1.1','443'],capture_output=True,timeout=5)
        guarded=subprocess.run([str(fixture),'tcp','1.1.1.1','443'],capture_output=True,timeout=5)
        if baseline.returncode==0 and guarded.returncode==13:return inspect(settings)
        time.sleep(.3)
    raise FilterError('过滤扩展尚未实际阻断直连，未允许启动 Claude')
