#!/usr/bin/env python3
"""Validate installed rules and the proxy path; never launch Claude."""
from pathlib import Path
import http.client
import ipaddress
import json
import re
import ssl
import sys
import time
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import guard
import system_filter


def verify_gateway(session,settings):
    conn=http.client.HTTPSConnection('127.0.0.1',session.proxy.server_address[1],timeout=8,context=ssl.create_default_context())
    conn.set_tunnel('www.cloudflare.com',443)
    try:
        conn.request('GET','/cdn-cgi/trace',headers={'Host':'www.cloudflare.com'})
        response=conn.getresponse()
        if response.status!=200:raise guard.ConnectivityError('连接检查服务暂时不可用。')
        trace=dict(line.split('=',1) for line in response.read(16384).decode().splitlines() if '=' in line)
        try:
            ipaddress.ip_address(trace.get('ip',''))
            if not re.fullmatch(r'[A-Z]{2}',trace.get('loc','')):raise ValueError()
        except ValueError:raise guard.ConnectivityError('连接检查未返回有效结果。')
        if trace['ip']!=settings['expected_ip'] or trace['loc']!=settings['expected_country']:
            raise guard.ApprovalRequired('受控代理的真实出口与批准值不符，请重新核验。')
    finally:conn.close()


def main():
    path=ROOT/'settings.json';settings=json.loads(path.read_text())
    provider=None
    if guard.enhanced(settings):
        report_path=ROOT/'runtime/lulu-live-acceptance.json'
        report=json.loads(report_path.read_text())
        if not report.get('all_passed') or not report.get('loopback_explicit_exception') or not report.get('provider_readiness_confirmed'):
            raise guard.GuardError('实际过滤验收未通过；未启用真实启动。')
        if report_path.stat().st_mtime<system_filter.RECEIPT.stat().st_mtime:
            raise guard.GuardError('过滤验收结果早于本次安装；未启用真实启动。')
        provider=system_filter.inspect(settings)
    for attempt in range(3):
        if guard.running_claude():raise guard.GuardError('请先完全退出 Claude 和 Claude Code，再继续配置。')
        session=guard.Session(settings)
        try:
            session.start(create_gateway=True)
            verify_gateway(session,settings)
            if provider is not None:system_filter.inspect(settings,provider)
            session.emit('CHECK_COMPLETE',message='受控代理出口与批准 IP / 国家一致；本次未启动 Claude')
            break
        except Exception as error:
            if attempt==2 or not guard.transient_error(error):raise
            print('正在复查受控连接…',flush=True)
        finally:session.close()
        # Remain in this stage; never reinstall or reapply the validated policy.
        time.sleep(2)
    # The complete original checks must pass before writing launch permission.
    current=json.loads(path.read_text())
    if current!=settings:raise guard.GuardError('配置在检查期间发生变化，请重新确认后继续。')
    settings.update(protected_launch_enabled=True,mode='controlled_proxy',loopback_exception=True,
                    system_filter_status=('lulu_4_5_6_ready_for_user_trial' if provider is not None else 'not_used'),
                    launch_disabled_reason='',candidate_version='0.10.16')
    temporary=path.with_suffix('.tmp')
    temporary.write_text(json.dumps(settings,ensure_ascii=False,indent=2)+'\n');temporary.chmod(0o600);temporary.replace(path)
    print('连接与保护配置已完成。请从 Guard 菜单启动 Claude。',flush=True)

if __name__=='__main__':main()
