// Tooltip interaction replay; no browser, network or installed app.
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const root=path.resolve(__dirname,'..'),elements=new Map(),timers=new Map();let nextTimer=0;
function element(){return {children:[],textContent:'',innerHTML:'',hidden:true,style:{values:{},setProperty(k,v){this.values[k]=v;}},append(x){this.children.push(x);},scrollIntoView(){},setAttribute(k,v){this[k]=v;},getBoundingClientRect(){return {left:325,top:530,bottom:548,width:18,height:18};}};}
const anchor=element();anchor.dataset={tipKey:'test-info',tip:'Full tooltip details, including "quotes" and <literal text>.'};
const card=element();card.getBoundingClientRect=()=>({width:280,height:200});elements.set('#hover-card',card);
const document={documentElement:{},querySelector(q){if(!elements.has(q))elements.set(q,element());return elements.get(q);},querySelectorAll(q){return q==='[data-tip-key]'?[anchor]:[];},createElement:element};
const window={webkit:{messageHandlers:{guard:{postMessage(){}}}},GUARD_VIEW:'menu',innerWidth:360,innerHeight:600,GUARD_STRINGS:JSON.parse(fs.readFileSync(path.join(root,'interface/strings.json'))),setTimeout(fn){const id=++nextTimer;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);}};
vm.runInContext(fs.readFileSync(path.join(root,'interface/app.js'),'utf8'),vm.createContext({window,document,Set,Date}));
assert.equal(anchor.onclick,undefined,'Info must not need clicking');
anchor.onmouseenter();assert.equal(card.hidden,false);assert.equal(card.textContent,anchor.dataset.tip);
assert.equal(card.style.values.left,'72px');assert.equal(card.style.values.top,'324px','Position above trigger near bottom edge');
assert.equal(anchor['aria-describedby'],'hover-card');
anchor.onmouseleave();assert.equal(timers.size,1);card.onmouseenter();assert.equal(timers.size,0,'Allow pointer movement into the card');
card.onmouseleave();for(const fn of [...timers.values()])fn();assert(card.hidden);
anchor.onfocus();assert(!card.hidden,'Keyboard focus also exposes details');document.onkeydown({key:'Escape'});assert(card.hidden);
anchor.onmouseenter();anchor.dataset.tip='Updated local observations';window.guardEvent({kind:'state',state:{}});
assert.equal(card.textContent,'Updated local observations','Live snapshots update an open card without a click');
assert(!elements.get('#app').innerHTML.includes('class="check-state"'),'Local details are hover-only');
assert(elements.get('#app').innerHTML.includes('data-tip-key="local-dns"'));
console.log('Hover tips: hover/focus, viewport bounds, pointer bridge, Escape and live updates passed.');
