// Production pure ucode policy, executed against a UCI boundary double.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const file=path.join(__dirname,'../../configs/templates/cm2012-tailscale-lib.uc');
assert.ok(fs.existsSync(file),'Tailscale policy implementation is required');
const source=fs.readFileSync(file,'utf8').replace(/for \(let (\w+) in /g,'for (let $1 of ');
const lib=new Function('type','length','match','split','index','int','push','keys','die',source)(
 v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,
 v=>v.length,(v,r)=>String(v).match(r),(v,s)=>v.split(s),(v,x)=>v.indexOf(x),
 v=>Number.parseInt(v,10),(a,v)=>a.push(v),Object.keys,message=>{throw Error(message)});
const lan={up:true,l3_device:'br-lan','ipv4-address':[{address:'192.168.50.1',mask:24}]};
const settings={enabled:'1',allowed_sources:['100.80.0.2/32'],management_ports:['22','5252','9091']};
const plan=lib.render(settings,lan);
assert.equal(plan.error,undefined);assert.equal(plan.lan_cidr,'192.168.50.0/24');
assert.deepEqual(plan.daemon.advertiseRoutes,['192.168.50.0/24']);
assert.equal(plan.daemon.acceptDNS,false);assert.equal(plan.daemon.acceptRoutes,false);
assert.equal(plan.daemon.netfilterMode,'off');assert.equal(plan.daemon.runSSHServer,false);
assert.equal(plan.daemon.exitNode,'');assert.equal(plan.daemon.advertiseExitNode,false);
assert.equal(plan.daemon.disableSNAT,false);assert.equal(plan.daemon.remoteConfig,false);
assert.ok(!plan.daemon.advertiseRoutes.includes('0.0.0.0/0'));
assert.ok(!plan.daemon.advertiseRoutes.includes('::/0'));
const sections=Object.values(plan.firewall);
assert.ok(sections.every(s=>s.cm2012_remote==='tailscale'&&s.family==='ipv4'));
assert.ok(!sections.some(s=>s['.type']==='forwarding'));
const zone=sections.find(s=>s['.type']==='zone');
assert.equal(zone.input,'REJECT');assert.equal(zone.forward,'REJECT');
assert.deepEqual(zone.device,['tailscale0']);
const forward=sections.find(s=>s['.type']==='rule'&&s.dest==='lan');
assert.equal(forward.src_ip,'100.80.0.2/32');assert.equal(forward.dest_ip,'192.168.50.0/24');
const nat=sections.find(s=>s['.type']==='nat');
assert.equal(nat.src,'lan');assert.equal(nat.src_ip,'100.80.0.2/32');
assert.equal(nat.dest_ip,'192.168.50.0/24');assert.equal(nat.snat_ip,'192.168.50.1');
const management=sections.find(s=>s['.type']==='rule'&&!s.dest);
assert.deepEqual(management.dest_port,['22','5252','9091']);
assert.equal(management.src_ip,'100.80.0.2/32');
for(const edit of [{allowed_sources:['0.0.0.0/0']},{allowed_sources:['192.168.50.2/32']},
 {allowed_sources:['100.80.0.1/24']},{allowed_sources:['100.80.0.2/32','100.80.0.2/32']},
 {management_ports:['9090']},{management_ports:['22;reboot']},{enabled:'yes'}])
 assert.ok(lib.render({...settings,...edit},lan).error,JSON.stringify(edit));
for(const value of [{...lan,up:false},{...lan,l3_device:'eth0;reboot'},
 {...lan,'ipv4-address':[{address:'192.168.50.1',mask:0}]},
 {...lan,'ipv4-address':[{address:'100.80.0.1',mask:24}]},
 {...lan,'ipv4-address':[{address:'192.168.50.1',mask:24},{address:'10.0.0.1',mask:24}]}])
 assert.ok(lib.render(settings,value).error,JSON.stringify(value));
assert.equal(lib.render({...settings,enabled:'0'},{}).error,undefined);
assert.deepEqual(lib.render({...settings,enabled:'0'},{}).firewall,{});
function cursor(initial={}) {
 const db=structuredClone(initial);return {db,load:p=>p==='firewall',
 get:(p,s,o)=>o===undefined?db[s]?.['.type']:db[s]?.[o],
 set(p,s,o,v){db[s]??={};if(v===undefined)db[s]['.type']=o;else db[s][o]=v;return true},
 delete(p,s){delete db[s];return true},
 foreach(p,t,f){for(const [n,s] of Object.entries(db))if(!t||s['.type']===t)f({...s,'.name':n})}};
}
const foreign={'.type':'rule',name:'foreign',target:'ACCEPT',cm2012:'1'};
const c=cursor({foreign});assert.equal(lib.configure(c,plan).error,undefined);
assert.deepEqual(c.db.foreign,foreign);
const once=structuredClone(c.db);assert.equal(lib.configure(c,plan).changed,false);
assert.deepEqual(c.db,once);assert.equal(lib.clear(c).error,undefined);assert.deepEqual(c.db,{foreign});
const collision=cursor({cm2012_ts_zone:foreign});
assert.ok(lib.configure(collision,plan).error);assert.deepEqual(collision.db,{cm2012_ts_zone:foreign});
for(const method of ['set','delete']) {
 const c=cursor();lib.configure(c,plan);c[method]=()=>false;
 const result=method==='delete'?lib.clear(c):lib.configure(c,lib.render({...settings,allowed_sources:['100.80.0.3/32']},lan));
 assert.ok(result.error,method+' failure accepted');
}
assert.equal(lib.pending({prepared:true,confirmed:false}),true);
assert.equal(lib.pending({prepared:true,confirmed:true}),false);
assert.equal(lib.pending({prepared:false,confirmed:false}),false);
assert.equal(lib.state('0',false,'Running'),'disabled');
assert.equal(lib.state('1',true,'Running'),'paused');
assert.equal(lib.state('1',false,'NeedsLogin'),'needs_login');
assert.equal(lib.state('1',false,'Running'),'check_route_approval');
const rpcFile=path.join(__dirname,'../../configs/templates/cm2012-tailscale-rpc.uc');
assert.ok(fs.existsSync(rpcFile),'Tailscale RPC implementation is required');
const rpcSource=fs.readFileSync(rpcFile,'utf8').replace(/^import .*;$/gm,'')
 .replace(/for \(let (\w+) in /g,'for (let $1 of ').replace(/0700/g,'0o700');
function rpcFixture(pending=false) {
 const writes=[],commands=[],db={enabled:'0',allowed_sources:[],management_ports:[]};
 const c={load:()=>true,get:(p,s,o)=>db[o],set:(p,s,o,v)=>{writes.push([o,v]);db[o]=v;return true},commit:()=>true};
 const plugin=new Function('readfile','mkdir','rmdir','stat','cursor','connect','loadfile','system','json','sprintf',
 'type','length','match','trim','popen',rpcSource)(()=>null,()=>true,()=>true,
 p=>pending&&p==='/etc/cm2012-transaction'?{}:null,()=>c,
 ()=>({call:()=>lan}),()=>()=>lib,cmd=>{commands.push(cmd);return 0},JSON.parse,
 (s,v)=>JSON.stringify(v),v=>Array.isArray(v)?'array':typeof v,v=>v.length,(v,r)=>v.match(r),v=>v.trim(),()=>null).cm2012_tailscale;
 return {plugin,writes,commands};
}
const request={args:{enabled:'1',allowed_sources_json:'["100.80.0.2/32"]',management_ports_json:'["22"]'}};
let rpc=rpcFixture(true);assert.ok(rpc.plugin.apply.call(request).error);assert.deepEqual(rpc.writes,[]);
rpc=rpcFixture();assert.ok(rpc.plugin.apply.call({...request,args:{...request.args,allowed_sources_json:'["0.0.0.0/0"]'}}).error);
assert.deepEqual(rpc.writes,[]);
rpc=rpcFixture();assert.equal(rpc.plugin.apply.call(request).error,undefined);
assert.deepEqual(rpc.writes,[['enabled','1'],['allowed_sources',['100.80.0.2/32']],['management_ports',['22']]]);
assert.ok(rpc.commands.includes('/usr/libexec/cm2012-tailscale reconcile >/dev/null 2>&1'));
console.log('TAILSCALE_POLICY_OK');
