#!/usr/bin/env python3
"""Build only the tiny native account-free network probes; no Electron download."""
from pathlib import Path
import subprocess
import shutil
root=Path(__file__).resolve().parents[1]
base=Path.home()/'Library/Caches/ClaudeGuardDevelopment'
for folder in ['Fixtures','Controls']:(base/folder).mkdir(parents=True,exist_ok=True)
subprocess.run(['/usr/bin/cc',str(root/'tests/lulu_probe.c'),'-o',str(base/'Fixtures/guard-probe')],check=True)
shutil.copy2(base/'Fixtures/guard-probe',base/'Controls/guard-probe')
print('无账号网络探针已准备；未启动 Claude。')
