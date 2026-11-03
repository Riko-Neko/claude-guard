"""Local environment observations. Unknown is never a successful leak test.

No credentials, chat contents, browser profiles or fingerprint spoofing.
"""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import subprocess
import time


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=5)
    if result.returncode:raise OSError('observation unavailable')
    return result.stdout.strip()


def system_proxy_enabled(text):
    flags=re.findall(r'\b(?:HTTPEnable|HTTPSEnable|SOCKSEnable)\s*:\s*([01])\b',text)
    if flags:return '1' in flags
    return False if '<dictionary>' in text else None


def network_mode(config,system_proxy=None):
    tun=config.get('tun',{}) if isinstance(config,dict) else {}
    enabled=tun.get('enable') if isinstance(tun,dict) else None
    if type(enabled) is not bool:enabled=None
    mode='tun' if enabled is True else ('system_proxy' if system_proxy is True else 'proxy') if enabled is False else 'unknown'
    return dict(mode=mode,tun=enabled,system_proxy=system_proxy,
                checked_at=datetime.datetime.now().astimezone().isoformat())


def snapshot(claude_app):
    result = {'os': platform.mac_ver()[0], 'architecture': platform.machine(),
              'timezone': 'unknown', 'utc_offset_minutes': int(datetime.datetime.now().astimezone().utcoffset().total_seconds()/60),
              'languages': 'unknown', 'claude_version': 'unknown', 'dns_resolvers': None}
    try:
        zone = str(Path('/etc/localtime').resolve())
        result['timezone'] = zone.split('zoneinfo/', 1)[1] if 'zoneinfo/' in zone else time.tzname[0]
    except OSError:pass
    try:result['languages'] = command(['/usr/bin/defaults', 'read', '-g', 'AppleLanguages'])
    except (OSError, subprocess.TimeoutExpired):pass
    try:
        info = plistlib.loads((Path(claude_app)/'Contents/Info.plist').read_bytes())
        result['claude_version'] = info.get('CFBundleShortVersionString', 'unknown')
    except (OSError, ValueError):pass
    try:
        dns = command(['/usr/sbin/scutil', '--dns'])
        result['dns_resolvers'] = sorted(set(re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', dns))) or None
    except (OSError, subprocess.TimeoutExpired):pass
    return result


def evaluate(settings, current, controller_config, clock_skew=None, connections=0):
    baseline = settings.get('environment_baseline', {})
    tun = network_mode(controller_config)['tun']
    checks = [dict(id='route', status='observed' if tun is True else 'warning' if tun is False else 'unverified',
                   message='Clash 报告 TUN 已开启；受控代理出口另行验证。' if tun is True else '当前未开启 TUN，建议在 VPN 中开启；此变化只提醒，不因此阻断受控连接。' if tun is False else '当前网络模式未能确认，请稍后重新检查。')]
    dns = current.get('dns_resolvers')
    old_dns = baseline.get('dns_resolvers')
    dns_changed = old_dns is not None and dns is not None and dns != old_dns
    checks.append(dict(id='dns', status='warning' if dns_changed else 'unverified',
        message='系统 DNS 配置发生变化，需要复查；这不等同于已证实泄漏。' if dns_changed else ('已读取本地 DNS 配置，但尚未完成权威服务端的 DNS 泄漏验证。' if dns is not None else '本地 DNS 配置未能读取，泄漏情况未确认。')))
    checks.append(dict(id='webrtc', status='unverified', message='未在 Claude 内执行 WebRTC 检测；浏览器测试只能反映该浏览器环境。'))
    time_changed = any(k in baseline and current.get(k) != baseline[k] for k in ('timezone','utc_offset_minutes'))
    checks.append(dict(id='time', status='warning' if time_changed or (clock_skew is not None and abs(clock_skew)>120) else ('observed' if clock_skew is not None and current.get('timezone')!='unknown' else 'unverified'),
        message='时间或时区与基准不一致，请核对。' if time_changed or (clock_skew is not None and abs(clock_skew)>120) else ('时间及时区检查无异常。' if clock_skew is not None else '已读取时区；网络时间尚未确认。')))
    changed = [k for k in ('os','architecture','languages','claude_version') if k in baseline and baseline[k] != current.get(k)]
    threshold = settings.get('connection_warning_per_minute',600)
    incomplete=not baseline or any(current.get(k) in (None,'unknown') for k in ('os','architecture','languages','claude_version'))
    checks.append(dict(id='environment', status='warning' if changed or connections>threshold else ('unverified' if incomplete else 'observed'),
        message=('本机环境变化：'+', '.join({'os':'系统版本','architecture':'处理器架构','languages':'系统语言','claude_version':'Claude 版本'}[k] for k in changed)) if changed else ('最近一分钟连接次数超过提醒阈值。' if connections>threshold else ('本机环境基准或部分信息尚未确认。' if incomplete else '本机环境及连接频率未超过已设置的提醒条件。')),
        scope='仅本机基准与连接计数，不代表 Anthropic 风控或完整设备指纹检测。'))
    return checks


def write_report(path, checks):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    data={'time':datetime.datetime.now().astimezone().isoformat(), 'checks':checks}
    staged=path.with_suffix('.tmp')
    staged.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n');staged.chmod(0o600);staged.replace(path)
