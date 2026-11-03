#!/usr/bin/env python3
"""Discover the current designated VPN; GUI confirmation is required before saving."""
import datetime
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import guard
import environment_checks

def detect(allow_system_proxy=False,choose_group_callback=None):
    if guard.running_claude():raise SystemExit('请先完全退出 Claude / 内置 Code，再配置 Guard；不会替你关闭它们。')
    source=Path.home()/'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
    config={'controller_socket':'/tmp/verge/verge-mihomo.sock','allow_system_proxy':allow_system_proxy}
    proxies=guard.controller(config,'proxies').get('proxies',{})
    groups=[name for name,value in proxies.items() if value.get('now')]
    if not groups:raise guard.GuardError('未找到代理组，请开启当前 VPN 并选择节点。')
    group='AI' if 'AI' in groups else (choose_group_callback or choose_group)(groups)
    node=proxies[group]['now']
    ruby="require 'yaml';require 'json';c=YAML.load_file(ARGV[0]);p=c.fetch('proxies').find{|p|p['name']==ARGV[1]};abort('请选择具体节点而不是分组') unless p;puts JSON.generate(p)"
    raw=json.loads(subprocess.check_output(['/usr/bin/ruby','-e',ruby,str(source),node],text=True))
    c=guard.controller(config,'configs')
    result={**config,'mode':'controlled_proxy','configured':True,'protected_launch_enabled':False,
            'requested_protection_backend':'system_network_filter','system_filter_status':'configured_pending_install',
            'launch_disabled_reason':'首次安装与出口验收尚未完成','expected_node':node,'proxy_group':group,
            'expected_ip':'','expected_country':'','node_sha256':guard.node_digest(raw),
            'core_executable':'/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo',
            'source_config':str(source),'base_proxy_port':c.get('mixed-port',7897),'gateway_port':47831,
            'claude_app':'/Applications/Claude.app','probe_interval_seconds':5,'health_interval_seconds':1,
            'environment_check_seconds':3600,
            'loopback_exception':True,'created_at':datetime.datetime.now().astimezone().isoformat()}
    session=DiscoverySession(result)
    try:session.start(create_gateway=False)
    finally:session.close()
    result.update(expected_ip=session.detected['ip'],expected_country=session.detected['loc'])
    result['environment_baseline']=environment_checks.snapshot(result['claude_app'])
    # Discovery never opens Claude; the installer subsequently validates the pin.
    return result

def save(result):
    settings=ROOT/'settings.json'
    if settings.exists():
        backup=ROOT/'runtime/config-backups';backup.mkdir(parents=True,exist_ok=True)
        (backup/('settings-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'.json')).write_bytes(settings.read_bytes())
    settings.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');settings.chmod(0o600)

class DiscoverySession(guard.Session):
    def check_egress(self):
        import http.client,ssl
        conn=http.client.HTTPSConnection('127.0.0.1',self.core_port,timeout=10,context=ssl.create_default_context())
        conn.set_tunnel('www.cloudflare.com',443,headers={'Proxy-Authorization':'Basic '+self.auth})
        try:
            conn.request('GET','/cdn-cgi/trace',headers={'Host':'www.cloudflare.com'})
            response=conn.getresponse()
            trace=dict(line.split('=',1) for line in response.read(16384).decode().splitlines() if '=' in line)
            if response.status!=200 or not ipaddress.ip_address(trace.get('ip','')).is_global or not re.fullmatch('[A-Z]{2}',trace.get('loc','')):
                raise guard.GuardError('无法确认当前出口 IP 和国家。')
            self.detected=trace
        finally:conn.close()

def choose_group(groups):
    from gui_setup import choose
    return choose(groups)

if __name__=='__main__':
    raise SystemExit('请从 Claude Guard 菜单选择首次安装 / 重新配置 VPN。')
