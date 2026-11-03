#!/usr/bin/env python3
"""Reload ONLY the current user's verified LuLu GUI after setup.

Never calls LuLu -quit, changes preferences, or signals the network provider.
"""
import os
from pathlib import Path
import plistlib
import signal
import subprocess
import time
APP=Path('/Applications/LuLu.app')
PREFS=Path('/Library/Objective-See/LuLu/preferences.plist')
GUI=str(APP/'Contents/MacOS/LuLu')


def gui_pids():
    rows=subprocess.check_output(['/bin/ps','-axo','uid=,pid=,comm='],text=True,timeout=5)
    found=[]
    for row in rows.splitlines():
        parts=row.strip().split(None,2)
        if len(parts)==3 and parts[0]==str(os.getuid()) and parts[2]==GUI:found.append(int(parts[1]))
    return found


def refresh():
    prefs=plistlib.loads(PREFS.read_bytes())
    if prefs.get('noIconMode') is not True or not prefs.get('installTime'):
        raise RuntimeError('LuLu 隐藏设置尚未准备好，未刷新界面。')
    subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(APP)],check=True,capture_output=True,timeout=20)
    details=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',str(APP)],capture_output=True,text=True,timeout=8)
    if 'TeamIdentifier=VBG97UB4TA' not in details.stderr:raise RuntimeError('LuLu 签名不符，未刷新界面。')
    for pid in gui_pids():
        if pid in gui_pids():
            try:os.kill(pid,signal.SIGTERM)
            except ProcessLookupError:pass
    deadline=time.monotonic()+5
    while gui_pids():
        if time.monotonic()>=deadline:raise RuntimeError('LuLu 界面未完成刷新，网络保护保持运行。')
        time.sleep(.1)
    subprocess.run(['/usr/bin/open','-g','-a',str(APP)],check=True,capture_output=True,timeout=10)

if __name__=='__main__':refresh()
