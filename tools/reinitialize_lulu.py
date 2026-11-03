#!/usr/bin/env python3
"""Recover an enabled LuLu provider left alive after its data was uninstalled."""
import os
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import signal
import subprocess
import sys
import time
def running_claude():
    rows=subprocess.check_output(['/bin/ps','-axo','pid=,comm='],text=True)
    return any('/Claude.app/' in line or '/Claude/claude-code/' in line or
               (len(line.strip().split(None,1))==2 and Path(line.strip().split(None,1)[1]).name=='claude')
               for line in rows.splitlines())

def recover():
    if os.geteuid()!=0:raise SystemExit('需要管理员授权以完成网络保护安装。')
    if running_claude():raise SystemExit('请先退出 Claude 和 Claude Code，再重试安装。')
    directory=Path('/Library/Objective-See/LuLu')
    if all((directory/name).is_file() for name in ('preferences.plist','rules.plist')):return
    state=subprocess.check_output(['/usr/bin/systemextensionsctl','list'],text=True)
    if not any('com.objective-see.lulu.extension (4.5.6/4.5.6)' in row and '[activated enabled]' in row for row in state.splitlines()):
        raise SystemExit('请先完成系统扩展授权。')
    rows=subprocess.check_output(['/bin/ps','-axo','pid=,comm='],text=True)
    found=[]
    for row in rows.splitlines():
        fields=row.strip().split(None,1)
        if len(fields)!=2:continue
        path=Path(fields[1])
        if not (str(path).startswith('/Library/SystemExtensions/') and path.name=='com.objective-see.lulu.extension' and path.parent.name=='MacOS'):continue
        subprocess.run(['/usr/bin/codesign','--verify','--strict',str(path)],check=True,capture_output=True)
        details=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',str(path)],capture_output=True,text=True,check=True)
        if 'TeamIdentifier=VBG97UB4TA' not in details.stderr:raise SystemExit('过滤组件签名不符。')
        found.append(int(fields[0]))
    if len(found)!=1:raise SystemExit('无法确认过滤组件状态，请重启 Mac 后重新安装。')
    # Recheck immediately before the single maintenance reload. Never kill clients.
    if running_claude():raise SystemExit('检测到 Claude 正在运行，已取消安装维护。')
    os.kill(found[0],signal.SIGKILL)
    for _ in range(30):
        if directory.is_dir():
            print('网络保护配置目录已恢复。');return
        time.sleep(1)
    raise SystemExit('网络保护未完成初始化，请重启 Mac 后重新安装。')

if __name__=='__main__':recover()
