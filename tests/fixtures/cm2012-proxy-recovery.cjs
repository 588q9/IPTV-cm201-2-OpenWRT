// Regression cases for durable recovery; fake I/O only, no router/network.
'use strict';
const fs=require('node:fs'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'cm2012-proxy.cjs'),'utf8');
const marker='const io=os(),svc=factory.create(io,lib);';
const tests=String.raw`
function setup(active=true){
 const io=os();io.files['/etc/config/cm2012_proxy']=JSON.stringify(io.settings);
 io.restore_config=()=>{Object.assign(io.settings,JSON.parse(io.files['/etc/config/cm2012_proxy']));return true;};
 const remove=io.remove_tree;io.remove_tree=p=>{remove(p);for(const d of [...io.dirs])if(d.startsWith(p+'/'))io.dirs.delete(d);};
 let held=false;io.decision_lock=()=>{if(held)return false;held=true;return true;};io.decision_unlock=()=>{held=false;};
 io.stop_worker=()=>true;
 const svc=factory.create(io,lib);
 if(active){const a=svc.apply({enabled:'1',expected_revision:'0'});assert.ok(a.token);assert.equal(svc.transaction(a.token).error,undefined);assert.equal(svc.confirm({token:a.token}).confirmed,true);}
 return {io,svc,lock:()=>held};
}
let passed=0,failed=0;
function test(name,fn){try{fn();passed++;console.log('PASS',name);}catch(e){failed++;console.error('FAIL',name,e.message);}}
const journal='/etc/cm2012-proxy-transaction',undo='/etc/cm2012-proxy/update-undo',updating='/tmp/cm2012-proxy/update';
test('rollback retries after a transient firewall failure',()=>{
 const {io,svc,lock}=setup(),token=svc.apply({enabled:'0',expected_revision:'1'}).token;
 assert.equal(svc.transaction(token).error,undefined);
 const run=io.run;let fail=true;io.run=a=>{if(fail&&a[0]==='/sbin/fw3'){fail=false;return false;}return run(a);};
 assert.ok(svc.rollback({token}).error);assert.equal(lock(),false);
 io.now=()=>1000;svc.guard();assert.equal(svc.status().pending,false);assert.equal(io.settings.enabled,'1');assert.equal(svc.status().routing_ready,true);
});
test('rollback snapshot survives a failed restored core',()=>{
 const {io,svc}=setup(),token=svc.apply({enabled:'0',expected_revision:'1'}).token;svc.transaction(token);io.healthy=false;
 assert.ok(svc.rollback({token}).error);assert.equal(io.exists(journal),true,'snapshot cannot disappear before restored core succeeds');
 io.healthy=true;svc.guard();assert.equal(io.exists(journal),false);assert.equal(svc.status().routing_ready,true);
});
test('expired worker restores without waiting for guard',()=>{
 const {io,svc}=setup(),old=io.read('/etc/cm2012-proxy/active.json'),token=svc.update_subscription({expected_revision:'1'}).token;
 io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});let clock=10;io.now=()=>clock;
 io.health=wait=>{if(wait)clock=311;return true;};assert.ok(svc.update(token).error);
 assert.equal(io.read('/etc/cm2012-proxy/active.json'),old);assert.equal(svc.status().routing_ready,true);assert.equal(io.exists(undo),false);
});
test('update copy failure retains undo and guard retries',()=>{
 const {io,svc}=setup(),old=io.read('/etc/cm2012-proxy/active.json'),token=svc.update_subscription({expected_revision:'1'}).token;
 io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});let clock=10;io.now=()=>clock;
 const copy=io.copy;let fail=true;io.copy=(a,b)=>{if(fail&&a===undo+'/before0'){fail=false;return false;}return copy(a,b);};
 io.health=wait=>{if(wait)clock=311;return true;};assert.ok(svc.update(token).error);assert.equal(io.exists(undo),true);
 assert.ok(svc.update_subscription({expected_revision:'1'}).error);svc.guard();assert.equal(io.read('/etc/cm2012-proxy/active.json'),old);assert.equal(io.exists(undo),false);
});
test('boot restores files without waiting for LAN then guard resumes',()=>{
 const {io,svc}=setup(),old=io.read('/etc/cm2012-proxy/active.json'),token=svc.apply({enabled:'0',expected_revision:'1'}).token;svc.transaction(token);
 io.now=()=>1;io.healthy=false;let health=0;io.health=()=>{health++;return false;};
 assert.equal(svc.recover().error,undefined);assert.equal(health,0);assert.equal(io.exists(journal),true);assert.equal(io.read('/etc/cm2012-proxy/active.json'),old);
 io.health=()=>true;svc.guard();assert.equal(io.exists(journal),false);assert.equal(svc.status().routing_ready,true);
});
test('cancel does not restore while worker group is alive',()=>{
 const {io,svc}=setup(),token=svc.update_subscription({expected_revision:'1'}).token;io.stop_worker=()=>false;io.now=()=>311;
 svc.guard();assert.equal(io.exists(updating),true,'cancellation must retain ownership evidence while execution remains alive');
 io.stop_worker=()=>true;svc.guard();assert.equal(io.exists(updating),false);assert.ok(svc.update(token).error);
});
test('decision lock excludes a second process and is released on exceptions',()=>{
 const {io,svc}=setup();io.decision_lock=()=>false;const before=JSON.stringify(io.files);
 assert.ok(svc.apply({enabled:'0',expected_revision:'1'}).error);assert.equal(JSON.stringify(io.files),before);
});
test('deferred update recovery suspends traffic during network changes',()=>{
 const {io,svc}=setup(),token=svc.update_subscription({expected_revision:'1'}).token;
 const write=io.write;let clock=10;io.now=()=>clock;
 io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});
 io.write=(p,v)=>{write(p,v);if(p==='/etc/cm2012-proxy/last-update'){io.dirs.add('/tmp/cm2012-wifi/pending');clock=311;}};
 assert.ok(svc.update(token).error);assert.equal(io.exists(undo),true);
 assert.equal(svc.status().routing_ready,false,'deferred recovery must withdraw the running candidate');
 assert.doesNotMatch(svc.status().update_error,/现有配置已保留/);
 svc.guard();assert.equal(svc.status().routing_ready,false);
 io.dirs.delete('/tmp/cm2012-wifi/pending');svc.guard();assert.equal(io.exists(undo),false);assert.equal(svc.status().routing_ready,true);
});
test('boot file recovery does not depend on firewall or core stop',()=>{
 const {io,svc}=setup(),token=svc.apply({enabled:'0',expected_revision:'1'}).token;svc.transaction(token);
 const run=io.run;io.run=a=>a[0]==='/sbin/fw3'||a[0]==='/etc/init.d/cm2012-mihomo'?false:run(a);
 assert.equal(svc.recover().error,undefined);assert.equal(io.settings.enabled,'1');
 assert.equal(io.exists(journal+'/files-restored'),true);assert.equal(io.exists(journal),true);
 io.run=run;svc.guard();assert.equal(io.exists(journal),false);assert.equal(svc.status().routing_ready,true);
});
console.log('PROXY_RECOVERY_CASES',passed,'passed',failed,'failed');if(failed)process.exitCode=1;
`;
new Function('require','__dirname',source.slice(0,source.indexOf(marker))+tests)(require,__dirname);
