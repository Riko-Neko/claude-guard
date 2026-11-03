#!/usr/bin/env python3
"""Read-only maintenance precheck. Never stops apps, edits rules, or restarts a filter."""
import argparse
import fcntl
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('guard_for_maintenance', ROOT / 'src/guard.py')
guard = importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)

def evaluate(claude_pids, extension_output, guard_busy=False, query_ok=True):
    related = [line.strip() for line in extension_output.splitlines()
               if 'com.objective-see.lulu.extension' in line]
    pending = any('waiting to uninstall' in row for row in related)
    enabled = any(row.split()[:2] == ['*', '*'] and '[activated enabled]' in row
                  for row in related)
    reasons=[]
    if claude_pids:reasons.append('Claude 或 Claude Code 仍在运行，请先完全退出；本工具不会替你关闭。')
    if guard_busy:reasons.append('Guard 会话仍在运行，请结束受保护会话或等待网络检查结束。')
    if not query_ok:reasons.append('无法确认系统扩展状态，暂不允许维护操作。')
    if pending and not enabled:
        reasons.append('旧扩展待清理，当前尚无已启用的新扩展。可以先尝试官方重新激活；激活成功前不修改规则或启动 Claude。')
    return {'maintenance_allowed':not reasons, 'requires_reboot':False,
            'reactivation_needed':pending and not enabled,
            'cleanup_reboot_pending':pending, 'enabled_extension_present':enabled,
            'official_reactivation_allowed':not claude_pids and not guard_busy and query_ok,
            'claude_process_count':len(claude_pids), 'guard_busy':guard_busy,
            'extension_report':related, 'reasons':reasons,
            'read_only':True, 'launch_allowed':False,
            'meaning':'只判断是否可以进入维护；不是防火墙验收，也不代表可以安全启动 Claude。'}

def inspect():
    guard_busy=False
    lock_path=ROOT/'runtime/session.lock'
    if lock_path.exists():
        with lock_path.open('r') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:guard_busy=True
    try:
        query=subprocess.run(['/usr/bin/systemextensionsctl','list'],capture_output=True,text=True,timeout=8)
        return evaluate(guard.running_claude(),query.stdout,guard_busy,query.returncode==0)
    except (OSError,subprocess.TimeoutExpired):
        return evaluate(guard.running_claude(),'',guard_busy,False)

if __name__=='__main__':
    result=inspect();print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result['maintenance_allowed'] else 1)
