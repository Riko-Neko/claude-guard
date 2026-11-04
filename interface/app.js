'use strict';
const dictionaries=window.GUARD_STRINGS;
const model={language:'zh-Hant',view:window.GUARD_VIEW||'setup',mode:'proxy',modeDraft:null,reputationEnabled:true,reputationDraft:null,reputation:null,domains:null,domainExpanded:false,domainInfoExpanded:false,networkMode:null,localChecks:[],menuScrollTop:0,riskExpanded:false,riskInfoExpanded:false,riskInfoScrollTop:0,canApproveExit:false,approvalSending:false,interval:3600,stage:0,busy:false,done:false,configured:false,status:'wait',ip:'—',region:'—',group:'—',node:'—',timezone:'—',version:'—',request:null,phaseInfo:null,report:null,allowed:false,active:false,paused:false,approvalRequired:false,connectionTitle:'',connectionReason:'',approvedIP:'',observedAt:'',invalidatedAt:''};
const t=k=>dictionaries[model.language]?.[k]||dictionaries['zh-Hant'][k]||k;
const shield='<svg class="shield" viewBox="0 0 36 40" aria-hidden="true"><path d="M18 2 32 8v12c0 9-9 15-14 18C13 35 4 29 4 20V8Z" fill="currentColor" opacity=".14"/><path d="M18 3 31 9v11c0 8-8 14-13 17C13 34 5 28 5 20V9Z" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="m11 20 5 5 10-12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
const info=key=>`<details class="info"><summary aria-label="${t('info')}">i</summary><div class="tip">${t(key)}</div></details>`;
const language=()=>`<select class="lang" id="language" aria-label="${t('language')}"><option value="zh-Hant">繁體中文</option><option value="zh-Hans">简体中文</option><option value="en">English</option></select>`;
function send(action,details={}){
 if(window.webkit?.messageHandlers?.guard){window.webkit.messageHandlers.guard.postMessage({action,...details});}
 else window.dispatchEvent(new CustomEvent('guard-preview-action',{detail:{action,...details}}));
}
function bind(){
 const lang=document.querySelector('#language');if(lang){lang.value=model.language;lang.onchange=()=>{model.language=lang.value;send('language',{language:model.language});render();};}
 document.querySelectorAll('[data-action]').forEach(button=>button.onclick=()=>send(button.dataset.action));
 document.querySelectorAll('.info').forEach(detail=>detail.onclick=e=>e.stopPropagation());
}
function render(){document.documentElement.lang=model.language;document.querySelector('#app').innerHTML=model.view==='menu'?menu():setup();bind();bindRisk();bindDomains();if(model.connectionReason){document.querySelector('#live-notice-title').textContent=model.connectionTitle||t('connectionFailed');document.querySelector('#live-notice-body').textContent=model.connectionReason;}if(model.view!=='menu')bindSetup();else{bindMenu();}}
function connectionNotice(){return model.connectionReason?`<section id="live-notice" class="connection-notice" role="alert"><strong id="live-notice-title"></strong><p id="live-notice-body"></p><button class="ghost small" data-action="settings">${t('reviewConnection')}</button></section>`:'';}
const actionPaths={check:'M20 7v5h-5 M20 12a8 8 0 1 0-2 6',settings:'M4 7h16 M4 17h16 M8 4v6 M16 14v6',results:'M6 3h9l3 3v15H6z M9 10h6 M9 14h6 M9 18h4',pause:'M8 5v14 M16 5v14',help:'M9 8a3 3 0 1 1 5 2c-2 1-2 2-2 3 M12 17h.01',logs:'M5 4h14v16H5z M8 8h8 M8 12h8 M8 16h5',uninstall:'M4 7h16 M9 7V4h6v3 M7 7l1 13h8l1-13 M10 10v7 M14 10v7',quit:'M12 3v9 M7 5a8 8 0 1 0 10 0'};
function actionIcon(name){return `<svg class="action-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="${actionPaths[name]||actionPaths.check}"/></svg>`;}
function shortTime(value){const date=new Date(value);return Number.isFinite(date.getTime())?date.toLocaleTimeString(model.language==='en'?'en-GB':model.language==='zh-Hans'?'zh-CN':'zh-TW',{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}):t('unknownTime');}
function freshTime(value,seconds){const elapsed=Date.now()-Date.parse(value||'');return Number.isFinite(elapsed)&&elapsed>=0&&elapsed<=seconds*1000;}
function modeMarkup(){
 const report=model.networkMode,known=report&&freshTime(report.checked_at,30)&&typeof report.tun==='boolean';
 const enabled=known&&report.tun;
 return `<section class="network-mode ${known?(enabled?'mode-tun':'mode-proxy'):'mode-unknown'}" aria-label="${t('networkMode')}"><div class="mode-status-line"><strong>${t('networkMode')}</strong><span>${known?(enabled?'✓ '+t('tunEnabled'):'⚠ '+t('nonTunMode')):t('modeUnknown')}</span></div><div class="mode-state-bar" aria-hidden="true"></div>${known&&!enabled?`<p>${t('tunRecommendation')}</p>`:''}</section>`;
}
function localCheckMarkup(id){
 const rows=(Array.isArray(model.localChecks)?model.localChecks:[]).filter(row=>row.id===id).sort((a,b)=>Date.parse(b.sourceTime||'')-Date.parse(a.sourceTime||''));
 const row=rows[0],fresh=row&&!row.stale&&freshTime(row.sourceTime,model.interval);
 const state=!fresh?'unknown':row.status==='warning'?'warning':row.status==='observed'?'observed':'unverified';
 const key=state==='unknown'?(row?'checkStale':'checkPending'):state==='warning'?'checkWarning':state==='observed'?'checkObserved':'checkUnverified';
 return `<button class="local-check check-${state}" data-action="results"><span class="check-name">${t('check_'+id)}</span><span class="check-state">${t(key)}</span><span class="check-color-bar" aria-hidden="true"></span></button>`;
}
function menu(){
 const primaryAction=model.approvalRequired?(model.canApproveExit?'approveIP':model.active?'settings':'check'):'launch';
 const primaryLabel=model.allowed?t(model.approvalRequired?(model.approvalSending?'confirmingExit':model.canApproveExit?'approveExitAction':model.active?'reviewExitAction':'recheckExit'):model.paused?'resume':'launch'):t('configureFirst');
 const tone=model.approvalRequired?'attention':model.paused?'attention':model.active&&!model.busy?'live':'neutral';
 return `<div class="popover"><header class="top"><div class="brand">${shield}<strong>Claude Guard</strong></div>${language()}</header>
 <section class="ip-hero"><div class="ip-heading"><span>${t('observedIP')}</span><span class="connection-pill ${tone}" id="menu-status"></span></div><div class="exit-value mono" id="menu-ip"></div><div class="ip-meta"><span class="region-chip" id="menu-region"></span><span id="menu-observed-time"></span><button class="ghost ip-recheck" data-action="check" ${model.busy||model.active?'disabled':''}>${actionIcon('check')}${t('menuRecheck')}</button></div></section>
 <div class="menu-scroll">${connectionNotice()}${modeMarkup()}<section class="menu-risk-card">${riskMarkup()}${domainMarkup()}</section><section class="local-checks"><div class="checks-heading"><strong>${t('localChecksTitle')}</strong><button class="ghost small" data-action="localChecks">${t('openLocalChecks')} ↗</button></div><div class="checks-grid">${['dns','webrtc','time','environment'].map(localCheckMarkup).join('')}</div></section></div>
 <div class="menu-actions"><button class="primary menu-primary" data-action="${primaryAction}" ${!model.allowed||model.busy||model.approvalSending||(model.active&&!model.paused&&!model.approvalRequired)?'disabled':''}>${primaryLabel}</button><div class="menu-grid"><button data-action="settings">${actionIcon('settings')}${t(model.configured?'menuReconfigure':'settings')}</button><button data-action="results">${actionIcon('results')}${t('menuResults')}</button><button data-action="pause" ${!model.active?'disabled':''}>${actionIcon('pause')}${t('menuPause')}</button></div></div>
 <footer class="menu-foot">${['help','logs','uninstall','quit'].map(action=>`<button class="ghost" data-action="${action}">${actionIcon(action)}<span>${t('menu_'+action)}</span></button>`).join('')}</footer></div>`;
}
function bindMenu(){
 const scroll=document.querySelector('.menu-scroll');scroll.scrollTop=model.menuScrollTop;scroll.onscroll=()=>{model.menuScrollTop=scroll.scrollTop;};
 document.querySelector('#menu-status').textContent=model.statusText||t('idle');
 const ip=document.querySelector('#menu-ip');ip.textContent=model.ip||'—';ip.className='exit-value mono'+(String(model.ip).includes(':')?' ipv6':'');
 document.querySelector('#menu-region').textContent=model.region&&!['—','未记录','未確認','未确认','unknown'].includes(model.region)?model.region:'—';
 const observed=document.querySelector('#menu-observed-time');observed.textContent=model.observedAt?shortTime(model.observedAt):t('notChecked');observed.title=model.observedAt||'';
}

function setup(){
 return `<main class="window ${model.busy?'busy':''}"><header class="top"><div class="brand">${shield}<div><strong>Claude Guard</strong><div class="eyebrow">${t(model.configured?'reconfigure':'configure')}</div></div></div>${language()}</header><div class="intro"><h1>${t('overview')}</h1><p>${t('promo')}</p></div><nav class="steps" aria-label="${t('configure')}">${['normal','vpn','baseline','protect','finish'].map((k,i)=>`<div class="step ${model.done||i<model.stage?'done':i===model.stage?'active':''}"><span class="dot">${model.done||i<model.stage?'✓':i+1}</span>${i===0?t('configure'):t(k)}</div>`).join('')}</nav><div class="content">${connectionNotice()}<section><div class="section-head"><div class="heading"><h2>${t(model.configured?'reconfigure':'configure')}</h2></div>${info('protectionInfo')}</div><div class="modes">${['proxy','enhanced'].map(mode=>`<label class="mode ${model.mode===mode?'selected':''}"><input type="radio" name="mode" value="${mode}" ${model.mode===mode?'checked':''} ${model.busy?'disabled':''}><div class="mode-title"><h3><span class="radio"></span>${t(mode==='proxy'?'normal':'enhanced')}</h3><span class="tag ${mode==='enhanced'?'warning':''}">${mode==='proxy'?t('recommended'):'⚠ '+t('advanced')}</span></div><p>${t(mode==='proxy'?'normalDesc':'enhancedDesc')}</p></label>`).join('')}</div></section><section class="card"><div class="section-head"><h2>${t('vpn')}</h2>${info('exitInfo')}</div><div class="details-grid">${['group','node','ip','region'].map(k=>`<div class="datum"><label>${t(k==='ip'&&!model.busy?'approvedIP':k)}</label><span id="value-${k}" class="${k==='ip'?'mono':''}">—</span></div>`).join('')}</div><div class="notice">${t('tun')}</div></section><section class="card"><div class="env-row"><div class="inline"><h2>${t('interval')}</h2>${info('intervalInfo')}</div><select class="interval" id="interval" ${model.busy?'disabled':''}><option value="900">${t('15m')}</option><option value="3600">${t('1h')}</option><option value="10800">${t('3h')}</option></select></div><div class="env-sub" id="environment-summary"></div><div class="env-row" style="margin-top:10px"><div class="inline"><span>${t('local')}</span>${info('localInfo')}</div><button class="ghost small" data-action="localChecks">↗</button></div>${riskMarkup()}</section><section id="task" class="task ${model.request||model.phaseInfo||model.done||model.error?'visible':''} ${model.error?'error':''}" aria-live="polite"><h2 id="task-title"></h2><p id="task-body"></p><div id="group-slot"></div><div id="task-actions" class="actions"></div></section><section id="report" class="card" ${model.report?'':'hidden'}></section></div><aside class="legal"><strong>⚑ ${t('legalTitle')}</strong><p>${t('legal')}</p></aside><footer class="footer"><span class="status-text"><span class="status-dot"></span><span id="phase-text"></span></span><button class="primary" id="start" ${model.busy?'disabled':''}>${t(model.error&&model.stage>=3?'resumeSetup':model.configured?'restartSetup':'start')}</button></footer></main>`;
}
function bindSetup(){
 document.querySelectorAll('input[name=mode]').forEach(radio=>radio.onchange=()=>{model.mode=radio.value;model.modeDraft=radio.value;render();});
 const interval=document.querySelector('#interval');interval.value=String(model.interval);interval.onchange=()=>model.interval=Number(interval.value);
 document.querySelector('#start').onclick=()=>startSetup();
 for(const k of ['group','node','ip','region'])document.querySelector('#value-'+k).textContent=k==='ip'&&!model.busy?(model.approvedIP||model.ip):model[k];
 document.querySelector('#environment-summary').textContent=`${t('zone')} · ${model.timezone}    ${t('version')} · ${model.version}`;
 document.querySelector('#phase-text').textContent=model.connectionReason&&!model.busy?(model.connectionTitle||model.statusText):t(model.status);
 renderTask();renderReport();
 if(model.request)document.querySelector('#task')?.scrollIntoView({block:'nearest'});
 else if(model.report)document.querySelector('#report')?.scrollIntoView({block:'nearest'});
}
function startSetup(restart=false){if(model.busy)return;model.modeDraft=model.mode;model.reputationDraft=model.reputationEnabled;model.busy=true;model.done=false;model.error=false;model.failureDetail=null;model.stage=1;model.request=null;model.phaseInfo=null;model.status='vpnBusy';send('startSetup',{mode:model.mode,interval:model.interval,restart,reputationEnabled:model.reputationEnabled});render();}
const autoTitles=new Set(['设置 Claude Guard','安装网络保护','基础保护已准备就绪','Claude Guard 已准备就绪']);
function answer(index,value){const id=model.request?.id;if(id===undefined)return;model.request=null;send('reply',{id,index,value});render();}
function renderTask(){
 const title=document.querySelector('#task-title'),body=document.querySelector('#task-body'),actions=document.querySelector('#task-actions');
 if(model.error){title.textContent=t('failed');body.textContent=t(model.errorKey||'failedBody');if(model.failureDetail){const detail=document.createElement('p');detail.textContent=model.failureDetail;body.append(detail);}if(!model.busy){const reset=document.createElement('button');reset.textContent=t('chooseVpnAgain');reset.onclick=()=>startSetup(true);actions.append(reset);}return;}
 if(model.done){title.textContent=t('done');body.textContent=t('doneBody');return;}
 const request=model.request;if(!request){if(model.phaseInfo){title.textContent=t(model.phaseInfo.title);body.textContent=t(model.phaseInfo.body);}return;}
 const map={'确认 Claude 使用的 VPN':['vpn','reviewExit',1,'confirmExit'],'确认环境检查基准':['baseline','reviewEnv',2,'confirmEnv'],'需要开启 TUN':['vpn','tunFail',1,'force'],'VPN 检测未通过':['vpn','vpnFail',1,'retry'],'选择代理组':['groupChoice','groupBody',1,'continue'],'设置正在进行':['notice','busy',model.stage,'continue']};
 const entry=map[request.title]||['notice','failedBody',model.stage,'continue'];title.textContent=t(entry[0]);body.textContent=t(entry[1]);
 if(request.groups?.length){const select=document.createElement('select');select.className='interval group-select';select.id='group-choice';request.groups.forEach(name=>{const option=document.createElement('option');option.textContent=name;option.value=name;select.append(option);});document.querySelector('#group-slot').append(select);}
 const cancel=document.createElement('button');cancel.textContent=t('cancel');cancel.onclick=()=>answer(0);actions.append(cancel);
 const confirm=document.createElement('button');confirm.className='primary';confirm.textContent=t(entry[3]);confirm.onclick=()=>answer(request.buttons.length-1,document.querySelector('#group-choice')?.value);actions.append(confirm);
}
function riskData(){
 const report=model.reputation;
 if(!model.reputationEnabled||!report||report.ip!==model.ip)return null;
 return report;
}
function riskMarkup(){
 const r=riskData(),n=r?.score,valid=typeof n==='number'&&Number.isFinite(n)&&n>=1&&n<=100;
 const fresh=r&&Number.isFinite(Date.parse(r.checked_at))&&Date.now()-Date.parse(r.checked_at)>=0&&Date.now()-Date.parse(r.checked_at)<3600000;
 const marker=valid&&fresh?1+(n-1)/99*98:50;
 return `<div class="risk-block" id="risk-block"><div class="risk-heading"><strong>${t('ipRisk')}</strong><button class="risk-info-toggle" id="risk-info-toggle" aria-label="${t('info')}" aria-expanded="${model.riskInfoExpanded}" aria-controls="risk-info">i</button><span class="risk-score ${valid&&fresh?'known':'unknown'}" id="risk-score"></span>${model.view==='menu'?`<button class="ghost risk-refresh" data-action="refreshRisk" aria-label="${t('refreshRisk')}" title="${t('refreshRisk')}" ${!model.configured||model.busy||!model.reputationEnabled?'disabled':''}>${actionIcon('check')}</button>`:''}</div><div class="risk-scale" id="risk-scale" role="img" aria-label="${t('riskScale')}"><svg class="risk-track" viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true"><g class="risk-marker ${valid&&fresh?'':'unknown'}"><path class="risk-marker-outline" d="M${marker} 2v8"/><path d="M${marker} 2v8"/></g></svg><div class="risk-legend"><span>1%</span><span>100%</span></div></div><div class="risk-info-body" id="risk-info" ${model.riskInfoExpanded?'':'hidden'}>${t('riskInfo')}</div>${model.view!=='menu'?'<div class="subtle" id="risk-progress"></div>':''}<details id="risk-details" ${model.riskExpanded?'open':''}><summary>${t('riskSources')}${model.view==='menu'&&r?`<span class="risk-summary-meta"> · ${r.total_sources-r.pending}/${r.total_sources}${r.scored_sources===1?' · '+t('riskSingleShort'):''}</span>`:''}</summary>${model.view==='menu'?'<div class="subtle" id="risk-progress"></div>':''}<p class="risk-source-note">${t('riskSourceInfo')}</p><div id="risk-source-list"></div></details>${model.view==='setup'?`<div class="env-row"><button class="ghost small" data-action="refreshRisk" ${!model.configured||model.busy||!model.reputationEnabled?'disabled':''}>${t('refreshRisk')}</button><label class="risk-opt"><input id="risk-enable" type="checkbox" ${model.reputationEnabled?'checked':''} ${model.busy?'disabled':''}>${t('enableRisk')}</label></div>`:''}</div>`;
}
function bindRisk(){
 const r=riskData(),n=r?.score;
 const fresh=r&&Number.isFinite(Date.parse(r.checked_at))&&Date.now()-Date.parse(r.checked_at)>=0&&Date.now()-Date.parse(r.checked_at)<3600000;
 const valid=typeof n==='number'&&Number.isFinite(n)&&n>=1&&n<=100&&fresh;
 const badge=document.querySelector('#risk-score');if(!badge)return;
 document.querySelector('#risk-info-toggle').onclick=()=>{model.riskInfoExpanded=!model.riskInfoExpanded;render();};
 const explanation=document.querySelector('#risk-info');
 if(model.riskInfoExpanded){explanation.scrollTop=model.riskInfoScrollTop;explanation.onscroll=()=>{model.riskInfoScrollTop=explanation.scrollTop;};}
 if(valid)badge.style.setProperty('--risk-hue',String(Math.round((100-n)/99*120)));
 badge.textContent=!model.reputationEnabled?t('riskDisabled'):valid?n+'%':t('riskUnknown');
 document.querySelector('#risk-progress').textContent=r?`${t('riskReturned')} ${r.total_sources-r.pending}/${r.total_sources} · ${t('riskScored')} ${r.scored_sources} · ${shortTime(r.checked_at)}`:t('riskPending');
 if(r&&r.scored_sources===1)document.querySelector('#risk-progress').textContent+=' · '+t('riskLimited');
 const list=document.querySelector('#risk-source-list');list.innerHTML='';
 const rows=Array.isArray(r?.sources)?r.sources:[];
 for(const source of rows){
  const item=document.createElement('div');item.className='risk-source';
  const title=document.createElement('strong');title.textContent=source.name||source.id;item.append(title);
  const text=document.createElement('p');const labels={pending:'riskLoading',ok:'riskReady',unavailable:'riskUnavailable',metadata_only:'riskMetadata',unscored:'riskUnknown'};
  text.textContent=t(labels[source.status]||'riskUnknown')+(typeof source.score==='number'?' · '+source.score+'/100':'');item.append(text);
  const info=document.createElement('p');info.textContent=[source.country,source.network,source.classification].filter(Boolean).join(' · ');item.append(info);
  const signals=document.createElement('p');signals.textContent=Object.entries(source.signals||{}).map(([key,value])=>t(({is_vpn:'riskVPN',is_proxy:'riskProxy',proxy:'riskProxy',is_tor:'riskTor',is_datacenter:'riskHosting',is_mobile:'riskMobile'})[key]||key)+': '+t(value?'riskDetected':'riskNotDetected')).join(' · ');item.append(signals);
  const link=document.createElement('button');link.className='ghost small';link.textContent=t('sourceDocumentation');link.onclick=()=>send('riskSource',{source:source.id});item.append(link);list.append(item);
 }
 document.querySelector('#risk-details').ontoggle=e=>model.riskExpanded=e.target.open;
 if(model.view==='setup'){
  const checkbox=document.querySelector('#risk-enable');checkbox.onchange=()=>{model.reputationEnabled=checkbox.checked;model.reputationDraft=checkbox.checked;render();};
 }
}
function domainData(){
 const r=model.domains;
 if(!r||r.ip!==model.ip||!freshTime(r.checked_at,3600)||
    (model.invalidatedAt&&Date.parse(r.started_at||r.checked_at)<=Date.parse(model.invalidatedAt)))return null;
 return r;
}
function domainMarkup(){
 const r=domainData(),n=r?.score,valid=Number.isInteger(n)&&n>=0&&n<=100,marker=valid?1+n*.98:50;
 return `<div class="domain-block"><div class="risk-heading"><strong>${t('domainPass')}</strong><button class="risk-info-toggle" id="domain-info-toggle" aria-label="${t('info')}" aria-expanded="${model.domainInfoExpanded}" aria-controls="domain-info">i</button><span class="risk-score ${valid?'known':'unknown'}" id="domain-score"></span><button class="ghost risk-refresh" data-action="refreshDomains" aria-label="${t('domainRefresh')}" title="${t('domainRefresh')}" ${!model.configured||model.busy?'disabled':''}>${actionIcon('check')}</button></div><div class="risk-scale" role="img" aria-label="${t('domainScale')}"><svg class="risk-track domain-track" viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true"><g class="risk-marker ${valid?'':'unknown'}"><path class="risk-marker-outline" d="M${marker} 2v8"/><path d="M${marker} 2v8"/></g></svg><div class="risk-legend"><span>0%</span><span>100%</span></div></div><div class="risk-info-body" id="domain-info" ${model.domainInfoExpanded?'':'hidden'}>${t('domainInfo')}</div><details id="domain-details" ${model.domainExpanded?'open':''}><summary>${t('domainDetails')}</summary><p class="risk-source-note" id="domain-meta"></p><div id="domain-list"></div><details class="domain-geosite"><summary>geosite:anthropic</summary><p class="risk-source-note" id="domain-geosite-meta"></p><div id="domain-geosite-list"></div></details></details></div>`;
}
function bindDomains(){
 if(model.view!=='menu')return;
 const badge=document.querySelector('#domain-score');if(!badge)return;
 const r=domainData(),n=r?.score,valid=Number.isInteger(n)&&n>=0&&n<=100;
 badge.textContent=valid?n+'%':t('riskUnknown');
 if(valid)badge.style?.setProperty('--risk-hue',String(n===0?0:n<90?35+(Math.max(30,n)-30):125));
 document.querySelector('#domain-info-toggle').onclick=()=>{model.domainInfoExpanded=!model.domainInfoExpanded;render();};
 document.querySelector('#domain-details').ontoggle=e=>{model.domainExpanded=e.target.open;};
 document.querySelector('#domain-meta').textContent=r?`${r.rows.filter(row=>row.status!=='pending').length}/${r.rows.length} · ${shortTime(r.checked_at)}${r.complete?'':' · '+t('riskLoading')}`:t('domainPending');
 const appendRows=(target,rows)=>{
  target.innerHTML='';
  for(const row of rows){
   const item=document.createElement('div');item.className='risk-source domain-source';
   const title=document.createElement('strong');title.textContent=(row.scope==='suffix'?row.domain+' · *':row.domain)+(row.weight!==undefined?' · '+row.weight+'%':'');item.append(title);
   const detail=document.createElement('p');
   const state={passed:'domainPassed',pending:'riskLoading',failed:'domainFailed',mismatch:'domainMismatch'};
   const method=row.method==='trace'?'domainTrace':row.method==='route'?'domainRoute':'riskLoading';
   detail.textContent=t(state[row.status]||'riskUnknown')+' · '+t(method);item.append(detail);
   if(row.scope==='suffix'&&row.method==='trace'){const note=document.createElement('p');note.textContent=t('domainScopeNote');item.append(note);}
   if(row.observed_ip){const ip=document.createElement('p');ip.className='mono';ip.textContent=t('domainReturnedIP')+': '+row.observed_ip;item.append(ip);}
   if(row.trace_result){const note=document.createElement('p');note.className='muted';note.textContent=t(row.trace_result==='unsupported'?'domainNoTrace':'domainTraceUnavailable')+(row.trace_status?' · HTTP '+row.trace_status:'')+(row.error_type?' · '+row.error_type:'');item.append(note);}
   target.append(item);
  }
 };
 appendRows(document.querySelector('#domain-list'),r?.rows||[]);
 const g=r?.geosite,extras=Array.isArray(g?.entries)?g.entries:[];
 document.querySelector('#domain-geosite-meta').textContent=g?.status==='ok'?`${extras.filter(x=>x.status==='passed').length}/${extras.length} · ${t('domainSupplement')} · SHA-256 ${g.sha256}`:t(g?.status==='pending'?'riskLoading':'riskUnavailable');
 appendRows(document.querySelector('#domain-geosite-list'),extras);
}
function renderReport(){
 const target=document.querySelector('#report');target.innerHTML='';if(!model.report)return;
 const h=document.createElement('h2');h.textContent=t('results');target.append(h);
 const scope=document.createElement('p');scope.textContent=t('reportScope');target.append(scope);
 for(const check of model.report){
  const row=document.createElement('div');row.className='report-row';
  const source=Date.parse(check.sourceTime||'');const stale=check.stale||!Number.isFinite(source)||(model.invalidatedAt&&source<=Date.parse(model.invalidatedAt))||Date.now()-source>model.interval*1000||source>Date.now();
  const heading=document.createElement('strong');const labels={route:'vpn',dns:'local',webrtc:'local',time:'baseline',environment:'baseline'};
  heading.textContent=t(labels[check.id]||'notice')+' · '+t(stale?'staleResult':check.status==='warning'?'notice':check.status==='unverified'?'unknown':'recordedResult');row.append(heading);
  const timestamp=document.createElement('p');timestamp.className='report-time';timestamp.textContent=t('checkedAt')+' · '+(check.sourceTime||t('unknownTime'));row.append(timestamp);
  const text=document.createElement('p');text.textContent=model.language==='en'?(check.status==='warning'?'A local observation changed. Review the baseline and logs.':check.status==='unverified'?'Not fully verified. Open info for the scope.':'Local observations recorded.'):check.message;row.append(text);target.append(row);
 }
}
window.guardEvent=event=>{
 if(event.kind==='settingsOpened'){if(!model.busy){model.done=false;model.error=false;model.failureDetail=null;model.request=null;model.phaseInfo=null;model.report=null;model.modeDraft=null;model.reputationDraft=null;model.stage=0;model.status='wait';}render();return;}
 if(event.kind==='state'){const draft=model.view==='setup'?model.modeDraft:null;const riskDraft=model.view==='setup'?model.reputationDraft:null;Object.assign(model,event.state);if(draft!==null)model.mode=draft;if(riskDraft!==null)model.reputationEnabled=riskDraft;render();return;}
 if(event.kind==='riskDetailsOpened'){model.riskExpanded=true;render();document.querySelector('#risk-block')?.scrollIntoView({block:'nearest'});return;}
 if(event.kind==='resume'){model.stage=3;model.status='resumeBusy';const d=event.details||{};for(const [key,value] of Object.entries({group:d.proxy_group,node:d.expected_node,ip:d.expected_ip,region:d.expected_country})){if(value!==undefined)model[key]=value;}render();return;}
 if(event.kind==='report'){model.report=event.checks;render();return;}
 if(event.kind==='request'){
  if(event.title==='请先退出 Claude'){send('closeClaude');send('reply',{id:event.id,index:0});return;}
  if(autoTitles.has(event.title)){if(event.title.includes('准备就绪')){model.done=true;model.stage=4;model.status='done';}send('reply',{id:event.id,index:event.buttons.length-1});render();return;}
  if(event.title==='设置未完成'){model.error=true;model.status='failed';model.failureDetail=event.body||null;model.errorKey=event.body?.includes('规则文件')?'storageFailure':event.body?.includes('授权请求未能建立')?'authRequestInvalid':(event.body?.includes('LuLu')&&event.body?.includes('尚未停止'))?'orphanedFilter':event.body?.includes('重启')?'activationIncomplete':event.body?.includes('授权')?'permissionNeeded':'failedBody';send('reply',{id:event.id,index:0});render();return;}
  model.request=event;const d=event.details||{};for(const [key,value] of Object.entries({group:d.proxy_group,node:d.expected_node,ip:d.expected_ip,region:d.expected_country,timezone:d.timezone,version:d.claude_version})){if(value!==undefined)model[key]=value;}
  const stages={'确认 Claude 使用的 VPN':1,'确认环境检查基准':2,'需要开启 TUN':1,'VPN 检测未通过':1,'选择代理组':1};model.stage=stages[event.title]??model.stage;render();return;
 }
 if(event.kind==='phase'){if(event.message==='正在重新启用已有网络保护…')model.phaseInfo={title:'existingLulu',body:'existingLuluInfo'};else if(event.message==='正在尝试重新激活网络保护…')model.phaseInfo={title:'reactivateLulu',body:'reactivateLuluInfo'};else if(event.message==='请在 LuLu 安装引导中完成设置…')model.phaseInfo={title:'firstLulu',body:'firstLuluInfo'};else if(event.message==='正在复查受控连接…')model.phaseInfo={title:'connectionRetry',body:'connectionRetryInfo'};else if(event.message==='正在更新网络保护配置…')model.phaseInfo={title:'filterBusy',body:'policyRetryInfo'};else if(!event.message.startsWith('正在等待系统授权')&&!event.message.startsWith('正在等待 LuLu'))model.phaseInfo=null;const phases={'正在检测 VPN…':[1,'vpnBusy'],'正在复核已确认的连接…':[3,'resumeBusy'],'正在确认网络保护状态…':[3,'filterBusy'],'正在结束设置…':[model.stage,'endingSetup'],'正在检查连接…':[2,'checkBusy'],'正在安装网络保护…':[3,'installBusy'],'正在等待系统授权完成…':[3,'permissionBusy'],'正在等待 LuLu 完成初始化…':[3,'initializationBusy'],'正在重新启用已有网络保护…':[3,'existingLuluBusy'],'正在尝试重新激活网络保护…':[3,'reactivateLulu'],'正在备份并清理旧网络保护配置…':[3,'preparationBusy'],'请在 LuLu 安装引导中完成设置…':[3,'initializationBusy'],'正在等待网络保护保存规则…':[3,'rulesBusy'],'正在恢复网络保护初始化…':[3,'repairBusy'],'正在更新网络保护配置…':[3,'filterBusy'],'正在复查受控连接…':[3,'connectionRetry'],'正在配置网络保护…':[3,'filterBusy'],'正在检查网络保护…':[3,'filterBusy'],'已取消设置':[0,'wait'],'设置未完成':[model.stage,'failed']};const found=phases[event.message];if(found){[model.stage,model.status]=found;}render();return;}
 if(event.kind==='finished'){model.busy=false;model.request=null;model.phaseInfo=null;if(event.success&&model.done){model.modeDraft=null;model.reputationDraft=null;model.status='done';model.stage=4;model.configured=true;send('closeSettings');}else if(!event.success){model.status='failed';model.error=true;}else{model.status='wait';}render();}
};
render();send('ready');
