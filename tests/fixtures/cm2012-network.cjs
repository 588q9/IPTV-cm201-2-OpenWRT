// Exercise the production ucode validation/rendering with a UCI boundary double.
// Native ARM/ucode tests run the same vectors before deployment.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const file = path.join(__dirname, '../../configs/templates/cm2012-network-lib.uc');
assert.ok(fs.existsSync(file), 'network configuration library is required');
const source = fs.readFileSync(file, 'utf8');
const lib = new Function('type','length','match','split','index','int','push','join','json','sprintf','keys','die',source)(
 v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,
 v=>v.length, (v,r)=>String(v).match(r), (v,s)=>v.split(s), (v,x)=>v.indexOf(x),
 v=>Number.parseInt(v,10), (a,v)=>a.push(v), (s,a)=>a.join(s), JSON.parse,
 (s,n)=>s==='%02X'?n.toString(16).toUpperCase().padStart(2,'0'):s.replace('%d',String(n)),Object.keys, message=>{throw new Error(message)});
function args(edits={}) { return {eth_role:'lan',uplink:'wifi',allow_upstream:'0',
 routes_json:'[]',upstream_sources_json:'[]',...edits}; }
const route={target:'192.168.60.0/24',gateway:'192.168.50.2',interface:'lan',metric:'10',enabled:'1'};
assert.equal(lib.validate(args()).error,undefined);
assert.equal(lib.validate(args({eth_role:'wan',uplink:'ethernet'})).error,undefined);
for (const edit of [{eth_role:'evil'},{eth_role:'lan',uplink:'ethernet'},
 {routes_json:'not json'},{routes_json:'{}'},{allow_upstream:'1'},
 {upstream_sources_json:'["0.0.0.0/0"]'},
 ...[{target:'0.0.0.0/0'},{target:'192.168.60.1/24'},{gateway:'1;reboot'},
 {interface:'eth0'},{metric:'-1'},{enabled:'yes'},{target:'192.168.60.0/33'},
 {gateway:'256.1.1.1'}].map(v=>({routes_json:JSON.stringify([{...route,...v}])})),
 {routes_json:JSON.stringify([route,route])}])
 assert.ok(lib.validate(args(edit)).error, JSON.stringify(edit));
assert.equal(lib.validate(args({routes_json:JSON.stringify([route])})).error,undefined);
const table='Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'+
 'br-lan\t003CA8C0\t0232A8C0\t0003\t0\t0\t10\t00FFFFFF\t0\t0\t0\n';
assert.equal(lib.installed(route,'br-lan',table),true);
assert.equal(lib.installed({...route,gateway:'192.168.50.3'},'br-lan',table),false);
assert.equal(lib.installed(route,'ap0',table),false);
function cursor() {
 const db={network:{lan:{'.type':'interface',device:'ap0',ipaddr:'192.168.50.1',netmask:'255.255.255.0'},
 wan:{'.type':'interface',device:'eth0',proto:'dhcp'},
 foreign:{'.type':'route',target:'10.23.0.0/16',gateway:'192.168.50.3',interface:'lan'}},
 dhcp:{lan:{'.type':'dhcp'}},firewall:{upper:{'.type':'zone',name:'wan',network:['wwan'],masq:'1',masq_dest:['!10.0.0.0/8']},
 foreign:{'.type':'rule',name:'user-rule'}},cm2012:{settings:{'.type':'settings'}}};
 return {db,load(p){return !!db[p]},get(p,s,o){return o===undefined?db[p]?.[s]?.['.type']:db[p]?.[s]?.[o]},set(p,s,o,v){
  db[p]??={};db[p][s]??={};if(v===undefined)db[p][s]['.type']=o;else db[p][s][o]=v;return true;
 },delete(p,s,o){if(o)delete db[p]?.[s]?.[o];else delete db[p]?.[s];return true},
 foreach(p,t,f){for(const [n,s] of Object.entries(db[p]||{}))if(t===null||s['.type']===t)f({...s,'.name':n})}};
}
const c=cursor();
let cfg=lib.validate(args({routes_json:JSON.stringify([route]),allow_upstream:'1',upstream_sources_json:'["192.168.1.0/24"]'}));
lib.configure(c,cfg);
assert.equal(c.db.network.lan.device,'br-lan');
assert.equal(c.db.network.wan.device,undefined);
assert.deepEqual(c.db.network.cm2012_bridge.ports,['eth0','ap0']);
assert.equal(c.db.network.foreign.target,'10.23.0.0/16');
assert.equal(c.db.network.cm2012_route_0.target,'192.168.60.0/24');
assert.equal(c.db.firewall.foreign.name,'user-rule');
assert.deepEqual(c.db.firewall.upper.masq_dest,['!10.0.0.0/8','!192.168.1.0/24']);
const rules=Object.values(c.db.firewall).filter(s=>s['.type']==='rule'&&s.cm2012==='1');
assert.deepEqual(rules.map(r=>r.dest_ip).sort(),['192.168.50.0/24','192.168.60.0/24']);
assert.ok(rules.every(r=>r.src==='wan'&&r.dest==='lan'&&r.src_ip==='192.168.1.0/24'));
lib.configure(c,lib.validate(args({eth_role:'wan',routes_json:'[]'})));
assert.equal(c.db.network.lan.device,'ap0');
assert.equal(c.db.network.wan.device,'eth0');
assert.equal(c.db.network.cm2012_route_0,undefined);
assert.deepEqual(c.db.firewall.upper.masq_dest,['!10.0.0.0/8']);
assert.equal(c.db.network.foreign.target,'10.23.0.0/16');
const before={lan:{'.type':'interface',device:'ap0'},user:{'.type':'route',target:'10.0.0.0/8'}};
const applied={...before,lan:{'.type':'interface',device:'br-lan'},owned:{'.type':'route',target:'192.168.60.0/24'}};
const current={...applied,new_user:{'.type':'route',target:'172.16.0.0/16'}};
assert.deepEqual(lib.restore_diff(before,applied,current),[
 {section:'lan',option:'device',value:'ap0'}, {section:'owned',remove:true}]);
assert.deepEqual(lib.restore_diff({z:{masq_dest:['!10.0.0.0/8']}},
 {z:{masq_dest:['!10.0.0.0/8','!192.168.1.0/24']}},
 {z:{masq_dest:['!10.0.0.0/8','!192.168.1.0/24','!172.16.0.0/12']}}),
 [{section:'z',option:'masq_dest',value:['!10.0.0.0/8','!172.16.0.0/12']}]);
assert.equal(lib.section_key({'.type':'zone','.name':'cfg111',name:'wan'}),
 lib.section_key({'.type':'zone','.name':'cfg222',name:'renamed',cm2012_zone_id:'wan'}));
console.log('NETWORK_VALIDATION_AND_RENDERING_OK');

// Fail independently so the red run identifies every broken contract.
const failures=[];
function regression(name,run) { try {run();console.log('PASS '+name)} catch(e) {failures.push(name);console.error('FAIL '+name+': '+e.message)} }
regression('concurrently edited transaction-added section remains whole',()=>{
 const added={owned:{'.type':'route',target:'192.0.2.0/24',interface:'lan',metric:'10',cm2012:'1'}};
 assert.deepEqual(lib.restore_diff({},added,{owned:{...added.owned,metric:'20'}}),[]);
});
regression('concurrent deletion of an edited section remains deleted',()=>{
 const before={wan:{'.type':'interface',device:'eth0',proto:'dhcp'}};
 const applied={wan:{'.type':'interface',proto:'dhcp'}};
 assert.deepEqual(lib.restore_diff(before,applied,{}),[]);
 // A section deleted by the transaction itself still needs restoration.
 assert.deepEqual(lib.restore_diff(before,{},{}),[
  {section:'wan',option:'.type',value:'interface'},
  {section:'wan',option:'device',value:'eth0'},
  {section:'wan',option:'proto',value:'dhcp'}]);
});
regression('untouched anonymous route and rule survive identity renumbering',()=>{
 for(const kind of ['route','rule']) {
  const old={'.name':'cfg01a','.anonymous':true,'.type':kind,target:'10.0.0.0/8'};
  const next={...old,'.name':'cfg02b','.index':2};
  assert.deepEqual(lib.restore_diff({cfg01a:old},{cfg02b:next},{cfg02b:{...next,target:'10.1.0.0/16'}}),[]);
 }
});
regression('ambiguous anonymous identities fail closed',()=>{
 const a={'.name':'cfg01a','.anonymous':true,'.type':'route',target:'10.0.0.0/8'};
 assert.throws(()=>lib.restore_diff({cfg01a:a},{cfg02b:{...a,'.name':'cfg02b'},cfg03c:{...a,'.name':'cfg03c'}},{}));
});
regression('managed route and rule names survive repeated configuration',()=>{
 const c=cursor();assert.equal(lib.configure(c,cfg).error,undefined);
 const original=c.delete;let deleted=[];c.delete=(p,s,o)=>{if(!o)deleted.push(s);return original(p,s,o)};
 assert.equal(lib.configure(c,cfg).error,undefined);
 assert.deepEqual(deleted,[]);
});
regression('every required UCI mutation failure rejects configuration',()=>{
 const probe=cursor();let operations=0;
 for(const method of ['set','delete']) {const base=probe[method];probe[method]=(...a)=>{operations++;return base(...a)}}
 lib.configure(probe,cfg);
 for(let failure=1;failure<=operations;failure++) {
  const c=cursor();let at=0;
  for(const method of ['set','delete']) {const base=c[method];c[method]=(...a)=>++at===failure?false:base(...a)}
  assert.ok(lib.configure(c,cfg).error,'mutation '+failure+' accepted');
 }
});
regression('unreadable configuration rejects rendering',()=>{
 for(const config of ['cm2012','network','firewall']) {
  const c=cursor();c.load=p=>p!==config;assert.ok(lib.configure(c,cfg).error,config+' load accepted');
 }
});
const rpcSource=fs.readFileSync(path.join(__dirname,'../../configs/templates/cm2012-rpc.uc'),'utf8')
 .replace(/^import .*;$/gm,'').replace(/0([67]00)/g,'0o$1').replace(/for \(let (\w+) in /g,'for (let $1 of ')
 .replace(/a\.channel in channels/g,'channels.includes(a.channel)')
 .replace(/a\.enabled in \['0','1'\]/g,"['0','1'].includes(a.enabled)")
 .replace(/a\.uplink in \['ethernet','wifi'\]/g,"['ethernet','wifi'].includes(a.uplink)");
function rpcFixture(fail={}) {
 const c=cursor();c.db.cm2012.ap={'.type':'ap',key:'password123'};c.db.cm2012.sta={'.type':'sta'};
 const commands=[];const base=c.set;c.set=(...a)=>fail.set && a[1]===fail.set ? false : base(...a);
 c.commit=p=>p!==fail.commit;
 const originalLoad=c.load;c.load=p=>p!==fail.load && originalLoad(p);
 const plugin=new Function('readfile','open','mkdir','chmod','popen','lsdir','cursor','connect','loadfile',
 'system','type','length','index','match','trim','sprintf','split','die',rpcSource)(
 ()=> '12345678-1234-1234-1234-123456789abc',()=>({write:value=>value.length,close:()=>true}),()=>true,()=>true,
 ()=>null,()=>[],()=>c,()=>({call:()=>({})}),name=>()=>name.includes('network')?lib:{},
 command=>{commands.push(command);return command.includes(' abort')? (fail.abort?1:0):command.includes(' snapshot')?(fail.snapshot?1:0):0},
 v=>Array.isArray(v)?'array':typeof v,v=>v.length,(v,x)=>v.indexOf(x),(v,r)=>v.match(r),v=>v.trim(),
 (f,v)=>JSON.stringify(v),(v,s)=>v.split(s),message=>{throw Error(message)}).cm2012;
 return {plugin,commands};
}
const rpcArgs={ssid:'CM2012 test',key:'password123',channel:'153',enabled:'1',uplink:'ethernet',
 upstream_ssid:'',upstream_key:'',eth_role:'wan',allow_upstream:'0',routes_json:'[]',upstream_sources_json:'[]'};
regression('RPC refuses UCI set failures',()=>{
 for(const section of ['ap','sta']) {
  const {plugin}=rpcFixture({set:section});assert.ok(plugin.apply.call({args:rpcArgs}).error,section+' accepted');
 }
});
regression('RPC refuses configuration read failure before preparing transaction',()=>{
 const {plugin,commands}=rpcFixture({load:'cm2012'});assert.ok(plugin.apply.call({args:rpcArgs}).error);
 assert.ok(!commands.some(c=>c.includes(' prepare')));
});
regression('RPC never claims restored when abort failed',()=>{
 for(const fail of [{commit:'network',abort:true},{snapshot:true,abort:true}]) {
  const {plugin}=rpcFixture(fail),result=plugin.apply.call({args:rpcArgs});
  assert.ok(result.error);assert.ok(!/已恢复/.test(result.error),result.error);
  assert.match(result.error,/恢复失败|recovery failed/i);
 }
});
const restoreSource=fs.readFileSync(path.join(__dirname,'../../configs/templates/cm2012-network-restore.uc'),'utf8')
 .replace(/^import .*;$/gm,'').replace(/for \(let (\w+) in /g,'for (let $1 of ');
function restoreFixture(fail) {
 const cursors={};
 for(const stage of ['before','applied','live']) {
  const c=cursor();for(const config of ['cm2012','network','dhcp','firewall'])c.db[config]={};
  c.db.network.lan={'.type':'interface',device:stage==='before'?'ap0':'br-lan'};
  if(stage!=='before')c.db.network.owned={'.type':'route',target:'192.0.2.0/24'};
  const load=c.load;c.load=p=>!(fail===stage+'-load' && p==='network')&&load(p);
  if(stage==='live') for(const method of ['set','delete','commit']) {
   const base=c[method]||(()=>true);c[method]=(...args)=>fail===method?false:base(...args);
  }
  cursors[stage]=c;
 }
 new Function('ARGV','cursor','loadfile','die','push',restoreSource)(['journal','config'],
 dir=>cursors[dir==='journal'?'before':dir==='journal/applied'?'applied':'live'],()=>()=>lib,
 message=>{throw Error(message)},(a,v)=>a.push(v));
 return cursors.live.db;
}
regression('restore rejects every failed required UCI boundary',()=>{
 for(const fail of ['before-load','applied-load','live-load','set','delete','commit'])
  assert.throws(()=>restoreFixture(fail),undefined,fail+' accepted');
 const restored=restoreFixture(null);assert.equal(restored.network.lan.device,'ap0');
 assert.equal(restored.network.owned,undefined);
});
if(failures.length) throw new Error(failures.length+' network regressions failed');
