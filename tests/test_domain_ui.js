// Actual frontend state replay. No browser, network, Claude or installed app.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.resolve(__dirname,'..'),elements=new Map(),actions=[];
function element(){return {children:[],style:{values:{},setProperty(k,v){this.values[k]=v;}},textContent:'',innerHTML:'',append(x){this.children.push(x);},scrollIntoView(){}};}
const document={documentElement:{},querySelector(q){if(!elements.has(q))elements.set(q,element());return elements.get(q);},querySelectorAll(){return [];},createElement:element};
const window={GUARD_STRINGS:JSON.parse(fs.readFileSync(path.join(root,'interface/strings.json'))),GUARD_VIEW:'menu',webkit:{messageHandlers:{guard:{postMessage(x){actions.push(x);}}}}};
const context=vm.createContext({window,document,Set,Date});
vm.runInContext(fs.readFileSync(path.join(root,'interface/app.js'),'utf8'),context);
const now=new Date().toISOString(),rows=[{domain:'anthropic.com',scope:'suffix',weight:15,status:'passed',method:'trace',observed_ip:'8.8.8.8'},{domain:'claude.ai',scope:'suffix',weight:15,status:'passed',method:'route'}];
const domains={ip:'8.8.8.8',score:30,rows,checked_at:now,started_at:now,geosite:{status:'pending',entries:[]},complete:false};
window.guardEvent({kind:'state',state:{ip:'8.8.8.8',domains,configured:true}});
assert.equal(elements.get('#domain-score').textContent,'30%');
assert.equal(elements.get('#domain-score').style.values['--risk-hue'],'35');
assert(elements.get('#app').innerHTML.includes('domain-track'));
assert(elements.get('#app').innerHTML.includes('data-action="refreshDomains"'));
assert(elements.get('#domain-list').children[0].children.some(c=>c.textContent.includes('8.8.8.8')));
assert(elements.get('#domain-list').children[1].children.some(c=>c.textContent.includes('代理路徑')));
elements.get('#domain-details').ontoggle({target:{open:true}});
elements.get('#domain-info-toggle').onclick();
assert(elements.get('#app').innerHTML.includes('id="domain-details" open'));
assert(!elements.get('#app').innerHTML.match(/id="domain-info"[^>]*/)[0].includes('hidden'));
window.guardEvent({kind:'state',state:{domains:{...domains,score:0}}});
assert.equal(elements.get('#domain-score').textContent,'0%');
assert.equal(elements.get('#domain-score').style.values['--risk-hue'],'0');
window.guardEvent({kind:'state',state:{domains:{...domains,score:100}}});
assert.equal(elements.get('#domain-score').textContent,'100%');
assert.equal(elements.get('#domain-score').style.values['--risk-hue'],'125');
for(const bad of [{...domains,ip:'1.1.1.1'},{...domains,checked_at:'2020-01-01T00:00:00Z'},{...domains,score:90.5}]){
 window.guardEvent({kind:'state',state:{domains:bad}});
 assert.notEqual(elements.get('#domain-score').textContent,'30%');
 assert(elements.get('#app').innerHTML.includes('domain-track'),'Track stays visible without results');
}
window.guardEvent({kind:'state',state:{domains,invalidatedAt:new Date(Date.now()+1000).toISOString()}});
assert.notEqual(elements.get('#domain-score').textContent,'30%','A late update from an invalidated run must not appear current');
for(const language of ['zh-Hant','zh-Hans','en']){
 window.guardEvent({kind:'state',state:{language,domains,invalidatedAt:''}});
 assert.equal(elements.get('#domain-score').textContent,'30%');
 for(const key of ['domainPass','domainInfo','domainRoute','domainTrace'])assert(window.GUARD_STRINGS[language][key]);
}
console.log('Domain UI: integer scoring, evidence labels, mismatch, stale-IP isolation, info and translations passed.');
