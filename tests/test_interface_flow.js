// Real frontend event replay, no WebKit, network, account or installed app.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.resolve(__dirname,'..');
const elements=new Map(),actions=[];
function element(){return {value:'',textContent:'',innerHTML:'',children:[],append(child){this.children.push(child);},scrollIntoView(){}};}
const document={documentElement:{},querySelector(q){if(!elements.has(q))elements.set(q,element());return elements.get(q);},querySelectorAll(){return [];},createElement:element};
const window={GUARD_STRINGS:JSON.parse(fs.readFileSync(path.join(root,'interface/strings.json'))),GUARD_VIEW:'setup',webkit:{messageHandlers:{guard:{postMessage(value){actions.push(value);}}}}};
const context=vm.createContext({window,document,Set});
vm.runInContext(fs.readFileSync(path.join(root,'interface/app.js'),'utf8'),context);
window.guardEvent({kind:'state',state:{configured:true}});
assert(elements.get('#app').innerHTML.includes('重新設定'),'Existing setup must be explicitly labeled reconfiguration');
window.guardEvent({kind:'request',id:3,title:'基础保护已准备就绪',buttons:['知道了']});
assert(!actions.some(a=>a.action==='closeSettings'),'Do not close before process success');
window.guardEvent({kind:'finished',success:true});
assert.equal(actions.filter(a=>a.action==='closeSettings').length,1,'Success must close setup');
window.guardEvent({kind:'settingsOpened'});
window.guardEvent({kind:'finished',success:true});
assert.equal(actions.filter(a=>a.action==='closeSettings').length,1,'Reopen/cancellation must not replay old completion');
elements.get('#start').onclick();
window.guardEvent({kind:'request',id:5,title:'设置未完成',body:'LuLu 系统扩展已启用，但初始化尚未完成。',buttons:['知道了']});
assert(elements.get('#app').innerHTML.includes('id="start" disabled'),'Failure dialog must not re-enable retry before worker exits');
assert(elements.get('#task-body').children.some(child=>child.textContent.includes('LuLu')),'Display the actual failure reason');
window.guardEvent({kind:'finished',success:false});
assert.equal(actions.filter(a=>a.action==='closeSettings').length,1,'Failure must remain visible');
console.log('Interface flow: completion close, explicit reconfiguration, no stale success passed');

window.guardEvent({kind:'settingsOpened'});
window.guardEvent({kind:'phase',message:'正在重新启用已有网络保护…'});
assert(elements.get('#task-body').textContent.includes('既有設定'),'Existing configuration must be explained as reactivation');
window.guardEvent({kind:'phase',message:'请在 LuLu 安装引导中完成设置…'});
assert(elements.get('#task-body').textContent.includes('官方安裝引導'),'First-time setup must describe the official foreground guide');
window.guardEvent({kind:'request',id:88,title:'设置未完成',body:'本次系统请求提示重启，激活尚未完成。',buttons:['知道了']});
assert(elements.get('#task-body').textContent.includes('自行選擇普通模式'),'An incomplete activation must offer deferral or explicit mode choice, not mandatory restart');
assert(!elements.get('#task-body').textContent.includes('請先重新啟動 Mac'),'Do not impose a restart precondition');

window.guardEvent({kind:'settingsOpened'});
elements.get('#start').onclick();
window.guardEvent({kind:'phase',message:'正在复查受控连接…'});
assert(elements.get('#task-body').textContent.includes('自動重試'),'Temporary connectivity failure must explain the in-place retry');
assert(elements.get('#app').innerHTML.includes('id="start" disabled'),'Retry must stay busy instead of asking user to restart setup');
assert(!elements.get('#app').innerHTML.includes('task visible error'),'A pending retry is not a failed configuration');
window.guardEvent({kind:'phase',message:'正在更新网络保护配置…'});
assert(elements.get('#task-body').textContent.includes('自動繼續'),'Stale policy preparation must stay inside the current setup');

window.guardEvent({kind:'state',state:{view:'menu',allowed:true,active:true,paused:true,busy:false}});
let button=elements.get('#app').innerHTML.match(/<button class="primary menu-primary"[^>]*>[^<]*<\/button>/)[0];
assert(button.includes('重新檢查並恢復連線'),'Paused session must have a clear recovery action');
assert(!button.includes('disabled'),'Paused session must allow explicit recheck');
window.guardEvent({kind:'state',state:{busy:true}});
button=elements.get('#app').innerHTML.match(/<button class="primary menu-primary"[^>]*>[^<]*<\/button>/)[0];
assert(button.includes('disabled'),'Do not send duplicate reconnect requests');
window.guardEvent({kind:'state',state:{busy:false,paused:false}});
button=elements.get('#app').innerHTML.match(/<button class="primary menu-primary"[^>]*>[^<]*<\/button>/)[0];
assert(button.includes('disabled'),'Already connected sessions must not relaunch Claude');
console.log('Paused menu: manual recovery enabled, concurrent and active relaunch disabled');
