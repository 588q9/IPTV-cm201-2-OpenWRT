// Run the production LuCI view with only browser and RPC boundaries replaced.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../configs/remote-proxy/cm2012-proxy.js'), 'utf8');
const base = {state:'disabled',enabled:false,revision:'0',subscription_saved:false,pending:false,
 pending_ready:false,remaining:0,stage:'idle',apply_error:'',error:'',update_error:'',updating:false};
function fixture(initial={}) {
 const nodes=[],calls=[],polls=[],notifications=[],handlers={};let reply={...base,...initial};
 function E(tag,attrs={},children) {
  const node={tag,attrs,children,value:attrs.value||'',textContent:'',disabled:!!attrs.disabled,style:{},
   removeAttribute(name){delete this[name];},setAttribute(name,value){this[name]=value;}};
  nodes.push(node);return node;
 }
 const rpc={declare:d=>(...args)=>{
  calls.push({method:d.method,args});
  if(handlers[d.method])return handlers[d.method](...args);
  return Promise.resolve(d.method==='status'?reply:{});
 }};
 const page=new Function('view','rpc','ui','poll','E',source)({extend:v=>v},rpc,
  {addNotification:(_,node)=>notifications.push(node)},{add:f=>polls.push(f)},E);
 page.render(reply);
 return {nodes,calls,polls,handlers,notifications,
  set status(v){reply={...base,...v};},
  button:label=>{const b=nodes.find(n=>n.tag==='button'&&n.children===label);assert.ok(b,'button '+label+' is required');return b;},
  get input(){return nodes.find(n=>n.tag==='input');},get select(){return nodes.find(n=>n.tag==='select');},
  text:()=>nodes.map(n=>n.textContent+(typeof n.children==='string'?n.children:'')).join('\n')};
}
const tick=()=>Promise.resolve().then(()=>Promise.resolve());
(async()=>{
 const unavailable=fixture({state:'active',enabled:true,core_ready:true,external_state:'unavailable'});
 assert.match(unavailable.text(),/本地核心：已就绪/);
 assert.match(unavailable.text(),/公网代理和 DNS：不可用/);
 assert.ok(!unavailable.text().includes('异常，已恢复直连'),'external failure must not claim direct fallback');
 assert.match(fixture({state:'active',core_ready:true,external_state:'unknown'}).text(),/公网代理和 DNS：尚未验证/);
 assert.match(fixture({state:'active',core_ready:true,external_state:'available'}).text(),/公网代理和 DNS：最近检查通过/);
 const failed=fixture();let finish;
 failed.input.value='https://example.test/clash?token=private';failed.select.value='1';
 failed.handlers.apply=()=>new Promise(resolve=>{finish=resolve;});
 const first=failed.button('应用（90 秒确认）').attrs.click();
 assert.match(failed.text(),/正在提交/,'click must immediately acknowledge submission before RPC finishes');
 assert.equal(failed.button('应用（90 秒确认）').disabled,true);
 assert.equal(failed.input.value,'https://example.test/clash?token=private','do not erase an unaccepted subscription');
 failed.button('应用（90 秒确认）').attrs.click();await tick();
 assert.equal(failed.calls.filter(c=>c.method==='apply').length,1,'a pending request cannot be submitted twice');
 finish({error:'配置事务正忙。'});await first;
 assert.match(failed.text(),/配置事务正忙/);assert.equal(failed.input.value,'https://example.test/clash?token=private');
 assert.equal(failed.button('应用（90 秒确认）').disabled,false);
 console.log('PROXY_UI_SUBMISSION_FEEDBACK_OK');

 const saved=fixture();saved.input.value='https://example.test/clash?token=private';
 saved.handlers.save_subscription=()=>{saved.status={subscription_saved:true,revision:'1',stage:'saved'};return Promise.resolve({saved:true,revision:'1'});};
 await saved.button('保存订阅').attrs.click();
 assert.deepEqual(saved.calls.find(c=>c.method==='save_subscription').args,['https://example.test/clash?token=private','0']);
 assert.equal(saved.calls.some(c=>c.method==='apply'),false,'saving a subscription cannot enable traffic redirection');
 assert.equal(saved.select.value,'0');assert.equal(saved.input.value,'');
 assert.match(saved.text(),/订阅已保存/);assert.match(saved.text(),/无需确认/);
 assert.equal(saved.text().includes('token=private'),false,'saved URL must not be rendered into status');
 console.log('PROXY_UI_SAVE_WITHOUT_ENABLE_OK');

 const applying=fixture();applying.input.value='https://example.test/clash';applying.select.value='1';
 applying.handlers.apply=()=>{applying.status={state:'checking',enabled:true,revision:'2',subscription_saved:true,
  pending:true,pending_token:'test-token',pending_ready:false,stage:'download'};return Promise.resolve({token:'test-token',timeout:90});};
 await applying.button('应用（90 秒确认）').attrs.click();
 assert.equal(applying.input.value,'');assert.match(applying.text(),/下载订阅/);
 assert.equal(applying.button('确认正常').disabled,true,'confirmation is unavailable during preparation');
 assert.doesNotMatch(applying.text(),/剩余\s*0\s*秒/,'preparation must not look like an expired confirmation');
 applying.status={state:'active',enabled:true,revision:'2',subscription_saved:true,pending:true,
  pending_token:'test-token',pending_ready:true,remaining:74,stage:'confirm',routing_ready:true};
 await applying.polls[0]();
 assert.equal(applying.button('确认正常').disabled,false);assert.match(applying.text(),/74\s*秒/);
 applying.handlers.confirm=()=>{applying.status={state:'active',enabled:true,revision:'2',subscription_saved:true,routing_ready:true};return Promise.resolve({confirmed:true});};
 await applying.button('确认正常').attrs.click();
 assert.deepEqual(applying.calls.find(c=>c.method==='confirm').args,['test-token']);
 assert.equal(applying.button('确认正常').disabled,true);assert.match(applying.text(),/已确认/);
 console.log('PROXY_UI_READY_COUNTDOWN_OK');

 const polling=fixture({subscription_saved:true});polling.input.value='https://example.test/new';polling.select.value='1';
 polling.handlers.status=()=>Promise.reject(new Error('连接暂时中断'));
 await polling.polls[0]();
 assert.match(polling.text(),/状态读取失败/);assert.match(polling.text(),/连接暂时中断/);
 assert.equal(polling.input.value,'https://example.test/new');assert.equal(polling.select.value,'1');
 polling.handlers.status=undefined;polling.status={subscription_saved:true,state:'disabled',stage:'idle',apply_error:'订阅下载失败，已保留订阅地址。'};
 await polling.polls[0]();assert.match(polling.text(),/订阅下载失败/);
 console.log('PROXY_UI_ASYNC_ERRORS_VISIBLE_OK');
})().catch(error=>{console.error(error);process.exitCode=1;});
