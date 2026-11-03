// Source results and explicit approval controls; no app, browser or network.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.resolve(__dirname,'..'),elements=new Map(),actions=[];
function element(){let html='',text='';return {children:[],value:'',checked:false,style:{setProperty(){}},append(x){this.children.push(x);},scrollIntoView(){},set innerHTML(v){html=v;this.children=[];},get innerHTML(){return html;},set textContent(v){text=v;this.children=[];},get textContent(){return text+this.children.map(x=>x.textContent).join(' ');}};}
const document={documentElement:{},querySelector(q){if(!elements.has(q))elements.set(q,element());return elements.get(q);},querySelectorAll(){return [];},createElement:element};
const window={GUARD_STRINGS:JSON.parse(fs.readFileSync(path.join(root,'interface/strings.json'))),GUARD_VIEW:'menu',webkit:{messageHandlers:{guard:{postMessage(x){actions.push(x);}}}}};
vm.runInContext(fs.readFileSync(path.join(root,'interface/app.js'),'utf8'),vm.createContext({window,document,Set,Date}));
const report={ip:'8.8.8.8',score:12,checked_at:new Date().toISOString(),scored_sources:1,total_sources:3,pending:2,sources:[{id:'ipquery',name:'IPQuery',status:'ok',score:12,signals:{is_vpn:false}},{id:'proxycheck',name:'ProxyCheck',status:'pending'}]};
window.guardEvent({kind:'state',state:{ip:'8.8.8.8',reputation:report,reputationEnabled:true,configured:true,allowed:true,active:true,approvalRequired:true,canApproveExit:true}});
assert.equal(elements.get('#risk-score').textContent,'12%');
assert(elements.get('#risk-progress').textContent.includes('1/3'),'Partial result must show coverage without waiting');
assert(elements.get('#risk-source-list').textContent.includes('ProxyCheck'));
assert(elements.get('#app').innerHTML.includes('data-action="approveIP"'),'Live candidate requires explicit consent');
window.guardEvent({kind:'state',state:{approvalSending:true,canApproveExit:false}});
assert(elements.get('#app').innerHTML.match(/<button class="primary menu-primary"[^>]*>/)[0].includes('disabled'),'No double approval click');
window.guardEvent({kind:'state',state:{ip:'1.1.1.1'}});
assert.notEqual(elements.get('#risk-score').textContent,'12%','Never show the previous IP score for a new exit');
window.guardEvent({kind:'state',state:{ip:'8.8.8.8',reputation:{...report,score:null,scored_sources:0,pending:0}}});
assert(elements.get('#risk-score').textContent.includes('未確認'),'Missing scores must not be green');
window.guardEvent({kind:'state',state:{view:'setup',busy:false,reputationEnabled:true}});
elements.get('#risk-enable').checked=false;elements.get('#risk-enable').onchange();
window.guardEvent({kind:'state',state:{reputationEnabled:true}});
assert(elements.get('#risk-score').textContent.includes('未啟用'),'Old snapshots must not overwrite the privacy choice');
elements.get('#start').onclick();
assert.equal(actions.findLast(x=>x.action==='startSetup').reputationEnabled,false);
console.log('Risk UI: partial results, source provenance, stale-IP isolation, approval and privacy selection passed.');
