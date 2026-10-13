// Exercise the production ucode validation/rendering with a UCI boundary double.
// Native ARM/ucode tests run the same vectors before deployment.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const file = path.join(__dirname, '../../configs/templates/cm2012-network-lib.uc');
assert.ok(fs.existsSync(file), 'network configuration library is required');
const source = fs.readFileSync(file, 'utf8');
const lib = new Function('type','length','match','split','index','int','push','join','json','sprintf','keys',source)(
 v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,
 v=>v.length, (v,r)=>String(v).match(r), (v,s)=>v.split(s), (v,x)=>v.indexOf(x),
 v=>Number.parseInt(v,10), (a,v)=>a.push(v), (s,a)=>a.join(s), JSON.parse,
 (s,n)=>s==='%02X'?n.toString(16).toUpperCase().padStart(2,'0'):s.replace('%d',String(n)),Object.keys);
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
 firewall:{upper:{'.type':'zone',name:'wan',network:['wwan'],masq:'1',masq_dest:['!10.0.0.0/8']},
 foreign:{'.type':'rule',name:'user-rule'}},cm2012:{settings:{'.type':'settings'}}};
 return {db,get(p,s,o){return o===undefined?db[p]?.[s]?.['.type']:db[p]?.[s]?.[o]},set(p,s,o,v){
  db[p]??={};db[p][s]??={};if(v===undefined)db[p][s]['.type']=o;else db[p][s][o]=v;return true;
 },delete(p,s,o){if(o)delete db[p]?.[s]?.[o];else delete db[p]?.[s];return true},
 foreach(p,t,f){for(const [n,s] of Object.entries(db[p]||{}))if(s['.type']===t)f({...s,'.name':n})}};
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
