const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../configs/templates/cm2012-wireless.js'), 'utf8');
const calls = [], buttons = [], stored = new Map(), controls = [];
const polls = [], outputs = [];
let statusReply = {confirmed:true};
const wanted = '12345678-1234-1234-1234-123456789abc';
const rpc = { declare: d => (...args) => { calls.push([d.method, args]); return Promise.resolve(d.method === 'status' ? statusReply : {confirmed:true}); } };
function E(tag, attrs = {}, children) {
 const element = {value: attrs.value || '', textContent:'', replaceChildren(){}, appendChild(){}, remove(){}, addEventListener(n,f){this['on'+n]=f}};
 if (tag === 'input' || tag === 'select' || tag === 'textarea') controls.push({attrs,children,element});
 if (tag === 'button') buttons.push({attrs,children});
 if (tag === 'pre') outputs.push(element);
 return element;
}
const page = new Function('view','rpc','ui','poll','E','sessionStorage',source)(
 {extend:v=>v},rpc,{addNotification(){}},{add:f=>polls.push(f)},E,
 {getItem:k=>stored.get(k),setItem:(k,v)=>stored.set(k,v),removeItem:k=>stored.delete(k)});
// A new management IP has a fresh sessionStorage; authenticated status supplies
// the current transaction so reconnecting users can still confirm its settings.
page.render({config:{ssid:'public',enabled:'1',channel:'1',uplink:'wifi',upstream_ssid:'upstream'},
 ap:{status:'ENABLED'}, ethernet:{up:false}, sta:{wpa_state:'COMPLETED'}, clients:{clients:{}},
 pending:true,pending_token:wanted});
buttons.find(b=>b.children==='确认可访问').attrs.click();
assert.equal(calls.find(c=>c[0]==='confirm')[1][0],wanted);
const role=controls.find(c=>Array.isArray(c.children)&&c.children.length===2&&c.children.some(o=>o.value==='lan'));
assert.ok(role, 'Ethernet LAN choice missing');
role.element.value='lan'; role.element.onchange();
buttons.find(b=>b.children==='新增路由').attrs.click();
buttons.find(b=>b.children==='应用设置').attrs.click();
const payload=calls.find(c=>c[0]==='apply')[1];
assert.equal(payload[4],'wifi');
assert.equal(payload[7],'lan');
assert.equal(JSON.parse(payload[9]).length,1);
console.log('CROSS_ORIGIN_CONFIRMATION_OK');
(async()=>{
 statusReply={error:'fixture configuration read failed'};
 await assert.rejects(page.load(),/fixture configuration read failed/);
 stored.set('cm2012-token',wanted);
 await polls[0]();
 assert.match(outputs[0].textContent,/fixture configuration read failed/);
 assert.equal(stored.get('cm2012-token'),wanted,'failed polling must not clear a pending token');
 console.log('STATUS_READ_FAILURE_VISIBLE');
})().catch(error=>{console.error(error);process.exitCode=1});
