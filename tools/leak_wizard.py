#!/usr/bin/env python3
"""Local browser ICE check. No STUN, TURN, external page or Claude launch."""
import http.server
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
import time
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
import environment_checks


def classify(addresses, expected):
    expected=ipaddress.ip_address(expected)
    public=set()
    for value in addresses:
        try:
            address=ipaddress.ip_address(value)
            if address.is_global:public.add(address)
        except ValueError:continue
    mismatch=sorted(str(address) for address in public if address!=expected)
    return {'status':'warning' if mismatch else ('observed' if public else 'unverified'),
            'message':'本地 WebRTC 候选中出现批准出口以外的公网地址，请复查；未验证其外网可达性，不代表 Claude 已泄漏。' if mismatch else ('本次浏览器本地 WebRTC 公网候选地址与批准出口一致；未进行公网 STUN 测试，不代表无泄漏。' if public else '本地检查未得到公网 ICE 候选地址；未使用外部 STUN，完整 WebRTC 泄漏情况未确认。'),
            'scope':'本次默认浏览器，非 Claude', 'unexpected_public_ips':mismatch}


def main():
    settings=json.loads((ROOT/'settings.json').read_text())
    token=secrets.token_urlsafe(24)
    page='''<!doctype html><meta charset="utf-8"><title>Claude Guard · 泄漏检查</title>
<style>body{font:17px system-ui;max-width:760px;margin:60px auto;padding:20px;line-height:1.7}button,a{padding:10px;margin:6px}pre{white-space:pre-wrap}</style>
<h1>网络泄漏检查</h1><p>本页测试当前浏览器，不会操作或启动 Claude。测试结果不能代替 Claude 自身的检查。</p>
<h2>WebRTC</h2><p>仅收集本地 ICE 候选；不配置 STUN 或 TURN，不连接外部测试服务，不访问摄像头、麦克风或浏览器账号。</p>
<button id="rtc">开始 WebRTC 检查</button><pre id="result">尚未测试</pre>
<h2>DNS</h2><p>本版只检查系统 DNS 配置及其变化，可从 Guard 菜单查看。未进行服务端 DNS 泄漏验证。</p>
<p>检查窗口有效期为 5 分钟。关闭本页不会改变 VPN、拦截状态或批准出口。</p>
<script>
const out=document.querySelector('#result');
async function submit(data){const r=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const d=await r.json();out.textContent=d.message;}
document.querySelector('#rtc').onclick=async()=>{
 const button=document.querySelector('#rtc');button.disabled=true;
 if(!window.RTCPeerConnection){out.textContent='当前浏览器不支持该检查，结果未确认。';button.disabled=false;return;}
 let pc;const addresses=[];
 try{
 pc=new RTCPeerConnection({iceServers:[]});pc.createDataChannel('guard-check');
 const done=new Promise(resolve=>{pc.onicecandidate=e=>{if(e.candidate){const c=e.candidate;const fields=c.candidate.split(' ');addresses.push(c.address||fields[4]);}else resolve();};});
 await pc.setLocalDescription(await pc.createOffer());out.textContent='正在收集网络候选地址…';
 await Promise.race([done,new Promise(resolve=>setTimeout(resolve,10000))]);
 await submit({kind:'webrtc',addresses});
 }catch(e){out.textContent='检查未完成，不能据此判定安全。';}finally{if(pc)pc.close();button.disabled=false;}
};</script>'''
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def respond(self,status,data,kind='application/json'):
            data=data.encode();self.send_response(status);self.send_header('Content-Type',kind+'; charset=utf-8')
            self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(data)
        def do_GET(self):
            if self.path!='/'+token:self.respond(404,'{}');return
            self.respond(200,page,'text/html')
        def do_POST(self):
            if self.path!='/'+token or self.headers.get('Origin')!=origin:self.respond(403,'{}');return
            try:
                length=int(self.headers.get('Content-Length','0'))
                if not 0<length<=16384:raise ValueError()
                data=json.loads(self.rfile.read(length))
                if data.get('kind')=='webrtc':
                    addresses=data.get('addresses',[])
                    if not isinstance(addresses,list) or len(addresses)>200 or not all(isinstance(a,str) for a in addresses):raise ValueError()
                    report=classify(addresses,settings['expected_ip']);report['id']='webrtc'
                else:raise ValueError()
                environment_checks.write_report(ROOT/'runtime/leak-report.json',[report])
                if report['status']=='warning':print(json.dumps({'kind':'LEAK_WARNING',**report},ensure_ascii=False),flush=True)
                self.respond(200,json.dumps(report,ensure_ascii=False))
            except (ValueError,TypeError,KeyError):self.respond(400,'{}')
    server=http.server.HTTPServer(('127.0.0.1',0),Handler);server.timeout=1
    origin='http://127.0.0.1:'+str(server.server_port)
    try:
        subprocess.run(['/usr/bin/open',origin+'/'+token],check=True)
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:server.handle_request()
    finally:server.server_close()

if __name__=='__main__':main()
