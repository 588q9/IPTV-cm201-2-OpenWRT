const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../configs/templates/cm2012-wireless.js'), 'utf8');
const calls = [], buttons = [], stored = new Map();
const wanted = '12345678-1234-1234-1234-123456789abc';
const rpc = { declare: d => (...args) => { calls.push([d.method, args]); return Promise.resolve({confirmed:true}); } };
function E(tag, attrs = {}, children) {
 const element = {value: attrs.value || '', textContent:'', replaceChildren(){}, appendChild(){}};
 if (tag === 'button') buttons.push({attrs,children});
 return element;
}
const page = new Function('view','rpc','ui','poll','E','sessionStorage',source)(
 {extend:v=>v},rpc,{addNotification(){}},{add(){}},E,
 {getItem:k=>stored.get(k),setItem:(k,v)=>stored.set(k,v),removeItem:k=>stored.delete(k)});
// A new management IP has a fresh sessionStorage; authenticated status supplies
// the current transaction so reconnecting users can still confirm its settings.
page.render({config:{ssid:'public',enabled:'1',channel:'1',uplink:'wifi',upstream_ssid:'upstream'},
 ap:{status:'ENABLED'}, ethernet:{up:false}, sta:{wpa_state:'COMPLETED'}, clients:{clients:{}},
 pending:true,pending_token:wanted});
buttons.find(b=>b.children==='确认可访问').attrs.click();
assert.equal(calls.find(c=>c[0]==='confirm')[1][0],wanted);
console.log('CROSS_ORIGIN_CONFIRMATION_OK');
