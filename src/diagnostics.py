"""Bounded failure details for the user's UI; never include command arguments."""
import http.client
import re
import ssl
import subprocess
import traceback
from pathlib import Path


def redact(value):
    text=str(value)
    text=re.sub(r'(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]+','<redacted authorization>',text)
    text=re.sub(r'(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@',r'\1<redacted>@',text)
    text=re.sub(r'(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|proxy-authorization)(\s*[=:]\s*)[^\s,;&]+',r'\1\2<redacted>',text)
    text=re.sub(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{12,}','<redacted key>',text)
    return text[:1000]


def failure_diagnostic(error,stage='connection'):
    row={'stage':stage,'error_type':type(error).__name__}
    if isinstance(error,subprocess.TimeoutExpired):raw='Command timed out after '+str(error.timeout)+'s'
    else:raw=redact(error)
    row['raw_message']=raw
    for key in ('errno','library','reason','verify_code','verify_message'):
        value=getattr(error,key,None)
        if isinstance(value,(str,int)) and value!='':row[key]=redact(value) if isinstance(value,str) else value
    tls=re.search(r'\[([A-Z0-9_]+):\s*([A-Z0-9_]+)\]',raw)
    if tls:row.setdefault('library',tls[1]);row.setdefault('reason',tls[2])
    source=re.search(r'\(([^()\n]*\.[a-z]+:\d+)\)',raw)
    if source:row['source_location']=source[1]
    frames=traceback.extract_tb(error.__traceback__)
    if frames:row['origin']=Path(frames[-1].filename).name+':'+str(frames[-1].lineno)
    address=re.search(r'(?i)(?:\b(?:address|addr|pointer|ptr)\b|地址|位址)\s*[:=]?\s*(0x[0-9a-f]+)\b',raw)
    if address:row['memory_address']=address[1]
    if isinstance(error,ssl.SSLEOFError) or ('EOF' in str(row.get('reason','')) and isinstance(error,ssl.SSLError)):
        summary='TLS 连接意外结束。'
    elif isinstance(error,ssl.SSLCertVerificationError):summary='TLS 证书校验失败。'
    elif isinstance(error,ssl.SSLError):summary='TLS 连接检查失败。'
    elif isinstance(error,(TimeoutError,subprocess.TimeoutExpired)):
        summary={'egress':'出口 IP 检查超时。','controller':'VPN 本机接口响应超时。','node':'节点配置读取超时。','filter':'网络过滤器检查超时。'}.get(stage,'连接检查超时。')
    elif isinstance(error,ConnectionRefusedError):summary='VPN 本机接口拒绝连接。' if stage=='controller' else '代理连接被拒绝。'
    elif isinstance(error,FileNotFoundError):summary='VPN 本机接口未找到。' if stage=='controller' else '检查所需文件未找到。'
    elif isinstance(error,http.client.RemoteDisconnected):summary='对端未返回响应便关闭了连接。'
    elif isinstance(error,ConnectionResetError):summary='连接被对端重置。'
    elif isinstance(error,http.client.HTTPException):summary='HTTP 响应未能完整读取。'
    elif isinstance(error,OSError):summary='VPN 本机接口读取失败。' if stage=='controller' else '代理网络连接失败。'
    else:summary=raw or type(error).__name__
    row['summary']=summary
    return row
