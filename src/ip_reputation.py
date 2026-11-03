"""Async public IP references. Transport is injected and must use Guard's node.

Scores are provider indicators, never a ban probability or proof of safety.
No credentials, account content, redirects or direct-network fallback.
"""
import copy
import datetime
import ipaddress
import json
import math
from pathlib import Path
import threading
import time
from urllib.parse import quote

SOURCES = (
    dict(id='ipquery', name='IPQuery', host='api.ipquery.io', docs='https://ipquery.io/sources'),
    dict(id='proxycheck', name='ProxyCheck', host='proxycheck.io', docs='https://proxycheck.io/api/'),
    dict(id='ipapi', name='ipapi.is', host='api.ipapi.is', docs='https://ipapi.is/free-tier.html'),
)

def timestamp():return datetime.datetime.now().astimezone().isoformat()

def public_ip(value):
    address=ipaddress.ip_address(value)
    if not address.is_global or '%' in str(value):raise ValueError('public IP required')
    return str(address)

def score(value):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not 0<=value<=100:return None
    return round(value)

def request_path(source,ip):
    ip=quote(public_ip(ip),safe='')
    if source=='ipquery':return '/'+ip+'?format=json'
    if source=='proxycheck':return '/v2/'+ip+'?vpn=1&risk=1&asn=1&ver=19-November-2024'
    if source=='ipapi':return '/?q='+ip
    raise ValueError('unknown source')

def normalize(source,ip,data):
    if not isinstance(data,dict):raise ValueError('invalid provider response')
    row={**source,'status':'ok','score':None,'signals':{},'checked_at':timestamp()}
    sid=source['id']
    if sid=='proxycheck':
        if data.get('status') not in ('ok','warning'):raise ValueError('provider unavailable or limited')
        item=data.get(ip)
        if not isinstance(item,dict):raise ValueError('address mismatch')
        row['score']=score(item.get('risk'))
        if item.get('proxy') in ('yes','no'):row['signals']['proxy']=item['proxy']=='yes'
        row['country']=str(item.get('isocode',''))[:8]
        row['network']=str(item.get('provider',''))[:200]
        row['classification']=str(item.get('type',''))[:100]
    else:
        if public_ip(data.get('ip',''))!=ip:raise ValueError('address mismatch')
        if sid=='ipquery':
            risk=data.get('risk',{})
            if not isinstance(risk,dict):raise ValueError('risk unavailable')
            row['score']=score(risk.get('risk_score'))
            for key in ('is_vpn','is_proxy','is_tor','is_datacenter','is_mobile'):
                if type(risk.get(key)) is bool:row['signals'][key]=risk[key]
            geo=data.get('location',{});isp=data.get('isp',{})
            row['country']=str(geo.get('country_code',''))[:8] if isinstance(geo,dict) else ''
            row['network']=str(isp.get('isp',isp.get('org','')))[:200] if isinstance(isp,dict) else ''
        else:
            # Anonymous ipapi.is has ownership metadata only since Sep 2026.
            # No missing flag is interpreted as a negative detection.
            row['status']='metadata_only'
            row['country']=str(data.get('country',''))[:100]
            row['network']=str(data.get('asn',''))[:200]
    if row['score'] is None and row['status']=='ok':row['status']='unscored'
    return row

def aggregate(ip,rows):
    known=[row['score'] for row in rows if row.get('status')=='ok' and row.get('score') is not None]
    pending=sum(row.get('status')=='pending' for row in rows)
    return dict(ip=ip,score=max(1,max(known)) if known else None,scored_sources=len(known),
                total_sources=len(rows),pending=pending,complete=pending==0,
                coverage='multi_source' if len(known)>=2 else 'single_source' if known else 'unavailable',
                sources=copy.deepcopy(rows),checked_at=timestamp(),method='max_provider_indicator_not_probability')

class Monitor:
    def __init__(self,query,publish,path,interval=3600):
        self.query=query;self.publish=publish;self.path=Path(path)
        self.interval=max(3600,interval)
        self.lock=threading.RLock();self.closed=False;self.generation=0
        self.last_started=0;self.current_ip=None;self.rows=[]
        self.finished=threading.Event();self.finished.set()
        self.timers=[]

    def request(self,ip,force=False):
        ip=public_ip(ip)
        with self.lock:
            if self.closed:return
            if ip==self.current_ip and (not self.finished.is_set() or (not force and time.monotonic()-self.last_started<self.interval)):return
            self.generation+=1;generation=self.generation
            for timer in self.timers:timer.cancel()
            self.timers=[]
            self.current_ip=ip;self.last_started=time.monotonic();self.finished.clear()
            self.rows=[{**source,'status':'pending','score':None,'signals':{}} for source in SOURCES]
            self._publish()
            for index,source in enumerate(SOURCES):
                timer=threading.Timer(7,self._timeout,args=(generation,index,source));timer.daemon=True
                self.timers.append(timer);timer.start()
                threading.Thread(target=self._worker,args=(generation,index,source,ip),daemon=True).start()

    def _timeout(self,generation,index,source):
        self._complete(generation,index,{**source,'status':'unavailable','score':None,'signals':{},'checked_at':timestamp(),'error_type':'TimeoutError'})

    def _worker(self,generation,index,source,ip):
        try:row=normalize(source,ip,self.query(source['host'],request_path(source['id'],ip)))
        except Exception as error:
            row={**source,'status':'unavailable','score':None,'signals':{},'checked_at':timestamp(),'error_type':type(error).__name__}
        self._complete(generation,index,row)

    def _complete(self,generation,index,row):
        with self.lock:
            if self.closed or generation!=self.generation or self.rows[index]['status']!='pending':return
            self.rows[index]=row
            self.timers[index].cancel()
            self._publish()
            if all(row['status']!='pending' for row in self.rows):self.finished.set()

    def _publish(self):
        report=aggregate(self.current_ip,self.rows)
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            temporary=self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');temporary.chmod(0o600);temporary.replace(self.path)
        except OSError:pass  # A cache problem cannot turn into a traffic decision.
        self.publish(report)

    def close(self):
        with self.lock:
            for timer in self.timers:timer.cancel()
            if self.current_ip and any(row['status']=='pending' for row in self.rows):
                for row in self.rows:
                    if row['status']=='pending':row['status']='unavailable';row['error_type']='Cancelled'
                try:self._publish()
                except Exception:pass
            self.closed=True;self.generation+=1;self.finished.set()
