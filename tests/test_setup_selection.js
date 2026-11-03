// Replay real radio/start handlers and stale native snapshots. No app/network.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.resolve(__dirname,'..'),elements=new Map(),actions=[];
const radios=['proxy','enhanced'].map(value=>({value}));
function element(){return {value:'',textContent:'',innerHTML:'',children:[],append(x){this.children.push(x);},scrollIntoView(){}};}
const document={documentElement:{},querySelector(q){if(!elements.has(q))elements.set(q,element());return elements.get(q);},querySelectorAll(q){return q==='input[name=mode]'?radios:[];},createElement:element};
const window={GUARD_STRINGS:JSON.parse(fs.readFileSync(path.join(root,'interface/strings.json'))),GUARD_VIEW:'setup',webkit:{messageHandlers:{guard:{postMessage(x){actions.push(x);}}}}};
vm.runInContext(fs.readFileSync(path.join(root,'interface/app.js'),'utf8'),vm.createContext({window,document,Set,Date}));
function selected(mode){assert(elements.get('#app').innerHTML.includes(`value="${mode}" checked`),`Expected ${mode} to remain selected`);}
window.guardEvent({kind:'state',state:{mode:'proxy',busy:false,configured:false}});
radios[1].onchange();selected('enhanced');
window.guardEvent({kind:'state',state:{mode:'proxy',busy:false}});selected('enhanced');
elements.get('#start').onclick();
assert.equal(actions.findLast(x=>x.action==='startSetup').mode,'enhanced');
window.guardEvent({kind:'state',state:{mode:'proxy',busy:true}});selected('enhanced');
window.guardEvent({kind:'phase',message:'正在安装网络保护…'});selected('enhanced');
window.guardEvent({kind:'finished',success:false});
window.guardEvent({kind:'state',state:{mode:'proxy',busy:false}});selected('enhanced');
elements.get('#start').onclick();
assert.equal(actions.findLast(x=>x.action==='startSetup').mode,'enhanced','Retry must retain the intended protection mode');
window.guardEvent({kind:'request',id:8,title:'Claude Guard 已准备就绪',buttons:['知道了']});
window.guardEvent({kind:'finished',success:true});
window.guardEvent({kind:'settingsOpened'});
window.guardEvent({kind:'state',state:{mode:'enhanced',busy:false,configured:true}});selected('enhanced');
radios[0].onchange();selected('proxy');
elements.get('#start').onclick();
window.guardEvent({kind:'state',state:{mode:'enhanced',busy:true}});selected('proxy');
assert.equal(actions.findLast(x=>x.action==='startSetup').mode,'proxy','Reverse mode switch must use the selected mode too');
window.guardEvent({kind:'finished',success:false});
window.guardEvent({kind:'settingsOpened'});
window.guardEvent({kind:'state',state:{mode:'enhanced',busy:false}});selected('enhanced');
console.log('Mode selection replay passed: stale snapshots, both modes, retries and explicit reopen.');
