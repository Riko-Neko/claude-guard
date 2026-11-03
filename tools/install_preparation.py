#!/usr/bin/env python3
"""Prepare a clean enhanced install from proven previous Guard enrollment.

Unknown LuLu installs and current setup attempts are preserved. Old files are
archived only after the official service stops; OS extension records are untouched.
"""
import argparse
import json
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uninstall_cleanup as cleanup


def plan_preparation():
    receipt=cleanup.STATE/'installation.json'
    marker=cleanup.STATE/'package-installation-id'
    if not receipt.is_file() or not marker.is_file():return None
    previous=json.loads(cleanup.trusted(receipt))
    owner=cleanup.trusted(marker).decode().strip()
    old_owner=previous.get('owner_id')
    if previous.get('scope')!='claude' or not old_owner or old_owner==owner:return None
    if previous.get('phase') not in ('dependency_installed_pending_configuration','claude_rules_written_pending_live_tests'):return None
    if not cleanup.APP.exists() and not cleanup.DATA.exists():return None
    prefs=cleanup.DATA/'preferences.plist'
    if prefs.is_file():
        values=plistlib.loads(cleanup.trusted(prefs))
        if any(values.get(key) for key in ('currentProfile','useAllowList','useBlockList','blockMode')):
            raise RuntimeError('LuLu 包含自定义设置，未自动清理。请先在 LuLu 中确认这些设置。')
    return {'owner':owner,'previous_owner':old_owner}


def prepare_previous(plan):
    from admin_authorization import authorize
    cleanup.assert_claude_closed()
    # The caller has already restored/verified the pinned official app if needed.
    result=subprocess.run([str(cleanup.APP/'Contents/MacOS/LuLu'),'-quit'],capture_output=True,text=True,timeout=180)
    if result.returncode:print('Previous component shutdown: '+str(result.stdout)+str(result.stderr),file=sys.stderr)
    last_error=None
    for _ in range(20):
        try:cleanup.stopped_state(for_install=True);break
        except RuntimeError as error:last_error=error;time.sleep(.5)
    else:raise RuntimeError('旧网络保护服务尚未停止，未清理任何配置。请完成当前系统授权后重试。') from last_error
    with tempfile.TemporaryDirectory(prefix='guard-install-preparation-') as directory:
        target=Path(directory)
        for name in ('install_preparation.py','uninstall_cleanup.py','initialize_filter.py'):
            shutil.copyfile(Path(__file__).with_name(name),target/name)
        command=shlex.join([sys.executable,'-B',str(target/'install_preparation.py'),'--owner-id',plan['owner'],'--previous-owner',plan['previous_owner']])
        authorize(command,'备份并清理旧网络保护配置')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--owner-id',required=True);parser.add_argument('--previous-owner',required=True)
    args=parser.parse_args()
    try:
        report=cleanup.finalize(args.owner_id,args.previous_owner,for_install=True)
        # Prepare the new empty first-run preferences in this same authorized
        # transaction; leave installTime for the official welcome wizard.
        import initialize_filter
        initialize_filter.main(claim=True)
        print(json.dumps(report,ensure_ascii=False))
    except Exception as error:print(str(error),file=sys.stderr);sys.exit(1)
