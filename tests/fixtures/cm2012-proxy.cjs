// Execute the production ucode's pure policy with native filesystem/network boundaries outside it.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const file = path.join(__dirname, '../../configs/remote-proxy/cm2012-proxy-lib.uc');
assert.ok(fs.existsSync(file), 'production proxy policy library is required');
// POSIX character class spelling is translated only for the JavaScript harness.
const lib = new Function('type','length','match','split','index','int','push','join','json','sprintf','keys','die','lc','slice',fs.readFileSync(file,'utf8').replaceAll('[[:cntrl:]]','[\\x00-\\x1f\\x7f]').replace(/for\(let (\w+) in /g,'for(let $1 of '))(
 v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,
 v=>v?.length??Object.keys(v||{}).length,(v,r)=>String(v).match(r),(v,s)=>v.split(s),(v,x)=>v.indexOf(x),
 v=>Number.parseInt(v,10),(a,v)=>a.push(v),(s,a)=>a.join(s),JSON.parse,
 (s,n)=>s==='%J'?JSON.stringify(n):s==='%c'?String.fromCharCode(n):s.replace('%d',String(n)),Object.keys,m=>{throw new Error(m)},s=>s.toLowerCase(),(a,n)=>a.slice(n));
const env={lan_device:'br-lan',lan_ip:'192.168.50.1',lan_cidr:'192.168.50.0/24',
 bootstrap:['192.168.1.1'],management:['198.51.100.0/24'],secret:'a'.repeat(64)};
const subscription={proxies:[{name:'sample',type:'ss',server:'example.test',port:443,cipher:'aes-128-gcm',password:'private'}],
 'proxy-groups':[{name:'Chosen',type:'select',proxies:['sample']}],rules:['DOMAIN,example.com,Chosen'],
 tun:{'auto-route':true},dns:{listen:'0.0.0.0:53'},'external-controller':'0.0.0.0:9999',secret:'remote',
 script:{code:'malicious'},'external-ui':'/etc'};
const config=lib.compile(subscription,env,{});
const dnsFallback=config['proxy-groups'].find(g=>g.name==='CM2012-DNS');
assert.equal(dnsFallback.type,'fallback');
assert.equal(dnsFallback.url,'https://1.1.1.1/cdn-cgi/trace');
assert.equal(dnsFallback.interval,60);assert.equal(dnsFallback.timeout,3000);
assert.equal(dnsFallback.lazy,false);assert.equal(dnsFallback['expected-status'],'200');
assert.equal(dnsFallback['empty-fallback'],'REJECT');
assert.equal(lib.compile({...subscription,proxies:[{...subscription.proxies[0],'ws-opts':{path:'/websocket'}}]},env,{}).proxies[0]['ws-opts'].path,'/websocket');
assert.equal(config.tun.device,'mihomo0');assert.equal(config.tun.stack,'gvisor');
assert.equal(config.tun.mtu,1280);assert.equal(config.tun.gso,false);
assert.equal(config.tun['auto-route'],false);assert.equal(config.tun['auto-redirect'],false);
assert.deepEqual(config.tun['inet6-address'],[]);assert.equal(config.ipv6,false);
assert.equal(config['external-controller'],'127.0.0.1:9090');
assert.equal(config['external-controller-tls'],'192.168.50.1:9091');
assert.equal(config.secret,'a'.repeat(64));assert.equal(config.script,undefined);
assert.equal(config.dns.listen,'192.168.50.1:1053');assert.equal(config.dns['enhanced-mode'],'redir-host');
assert.deepEqual(config.dns['proxy-server-nameserver'],['192.168.1.1']);
// Verified local node answers must survive compilation without overriding ordinary DNS.
const nodeHostsEnv={...env,node_hosts:{'example.test':['203.0.113.8','203.0.113.8','198.51.100.9'],'unrelated.example':['203.0.113.99']}};
const resolved=lib.compile(subscription,nodeHostsEnv,{});
assert.deepEqual(resolved.hosts,{'cm2012-proxy-health.invalid':'198.18.0.1','example.test':['203.0.113.8','198.51.100.9']});
assert.equal(resolved.proxies[0].server,'example.test','keep the original hostname and TLS identity');
assert.equal(config.hosts['example.test'],undefined,'no implicit mappings without local approval');
for(const value of [null,'203.0.113.8',[],['127.0.0.1'],['192.168.50.1'],['10.0.0.1'],['100.64.0.1'],['172.16.0.1'],['169.254.1.1'],['198.18.0.1'],['224.0.0.1'],['999.1.1.1'],Array(9).fill('203.0.113.8')])
 assert.throws(()=>lib.compile(subscription,{...env,node_hosts:{'example.test':value}},{}),/Invalid node host/);
for(const value of [[],true,'invalid'])assert.throws(()=>lib.compile(subscription,{...env,node_hosts:value},{}),/Invalid node host/);
// Short-lived node answers must use independent encrypted resolvers, not stale pins.
const dynamicNodeDns={...nodeHostsEnv,node_nameservers:['https://1.12.12.12/dns-query','https://120.53.53.53/dns-query']};
const dynamicResolved=lib.compile(subscription,dynamicNodeDns,{});
assert.deepEqual(dynamicResolved.dns['proxy-server-nameserver'],['https://1.12.12.12/dns-query','https://120.53.53.53/dns-query']);
assert.deepEqual(dynamicResolved.hosts,{'cm2012-proxy-health.invalid':'198.18.0.1'},'dynamic node DNS must supersede stale local node addresses');
assert.equal(dynamicResolved.proxies[0].server,'example.test');
assert.deepEqual(dynamicResolved.dns['default-nameserver'],['192.168.1.1']);
assert.deepEqual(dynamicResolved.dns['direct-nameserver'],['192.168.1.1']);
for(const value of ['https://1.12.12.12/dns-query',{},true,Array(5).fill('https://1.12.12.12/dns-query'),['http://1.12.12.12/dns-query'],['https://1.12.12.12/dns-query#CM2012-DNS'],['https://127.0.0.1/dns-query'],['https://192.168.50.1/dns-query'],['https://dns.example/dns-query']])
 assert.throws(()=>lib.compile(subscription,{...env,node_nameservers:value},{}),/Invalid node nameserver/);
const ownAddresses={...env,self_ipv4:['192.168.50.1','203.0.113.12'],bootstrap:['203.0.113.12','192.168.1.1']};
assert.deepEqual(lib.compile(subscription,ownAddresses,{}).dns['proxy-server-nameserver'],['192.168.1.1'],'uplink DNS must exclude every local interface address');
assert.throws(()=>lib.compile(subscription,{...ownAddresses,bootstrap:['203.0.113.12']},{}));
const dnsSource={...subscription,dns:{'nameserver-policy':{
 'example.org':['https://dns.google/dns-query','192.168.1.1'],
 '+.example.net':'9.9.9.9','+.lan':'8.8.8.8','+.test':'1.1.1.1',
 'loop.example':['127.0.0.1','203.0.113.12','https://192.168.50.1/dns-query'],
 'unsafe.example':['file:///etc/passwd','https://dns.google/dns-query#RULE','exec:reboot'],
 'mixed.example':['127.0.0.1','https://dns.google/dns-query']}}};
const dnsPolicy=lib.compile(dnsSource,ownAddresses,{}).dns['nameserver-policy'];
assert.deepEqual(dnsPolicy['example.org'],['https://dns.google/dns-query','192.168.1.1']);assert.deepEqual(dnsPolicy['+.example.net'],['9.9.9.9']);
assert.deepEqual(dnsPolicy['+.lan'],['127.0.0.1:53']);assert.equal(dnsPolicy['+.test'],undefined,'node-domain bootstrap cannot be overridden by subscription DNS policy');
assert.equal(dnsPolicy['loop.example'],undefined);assert.equal(dnsPolicy['unsafe.example'],undefined);assert.deepEqual(dnsPolicy['mixed.example'],['https://dns.google/dns-query']);
// DNS selection and unmatched business traffic must have distinct controls.
assert.deepEqual(config.dns.nameserver,['https://cloudflare-dns.com/dns-query#CM2012-DNS']);
assert.equal(config.rules.at(-1),'MATCH,CM2012-DEFAULT');
assert.deepEqual(config['proxy-groups'].find(g=>g.name==='CM2012-DNS').proxies,['sample']);
assert.deepEqual(config['proxy-groups'].find(g=>g.name==='CM2012-DEFAULT').proxies,['sample']);
const withFinal=lib.compile({...subscription,rules:['MATCH,Chosen']},env,{});
assert.equal(withFinal.rules.at(-1),'MATCH,Chosen');
assert.ok(withFinal['proxy-groups'].some(g=>g.name==='CM2012-DNS'));
assert.ok(!withFinal['proxy-groups'].some(g=>g.name==='CM2012-DEFAULT'),'an upstream final rule must not gain an unused default selector');
const legacySource={...subscription,rules:['MATCH,CM2012-PROXY'],
 'proxy-groups':[{name:'Chosen',type:'select',proxies:['CM2012-PROXY','sample'],'default-selected':'CM2012-PROXY'}]};
const legacy=lib.compile(legacySource,env,{});
assert.equal(legacy.rules.at(-1),'MATCH,CM2012-DEFAULT');
assert.deepEqual(legacy['proxy-groups'][0].proxies,['CM2012-DEFAULT','sample']);
assert.equal(legacy['proxy-groups'][0]['default-selected'],'CM2012-DEFAULT');
assert.equal(legacySource['proxy-groups'][0].proxies[0],'CM2012-PROXY','normalization must not mutate saved subscription input');
assert.ok(!legacy['proxy-groups'].some(g=>g.name==='CM2012-PROXY'));
for(const reserved of ['CM2012-DNS','CM2012-DEFAULT']) {
 assert.throws(()=>lib.compile({...subscription,proxies:[{...subscription.proxies[0],name:reserved}]},env,{}),/Duplicate proxy/);
 assert.throws(()=>lib.compile({...subscription,'proxy-groups':[{name:reserved,type:'select',proxies:['sample']}]},env,{}),/Duplicate group/);
}
assert.ok(config.rules.indexOf('IP-CIDR,100.64.0.0/10,DIRECT,no-resolve')<config.rules.indexOf('DOMAIN,example.com,Chosen'));
// No geodata assets are locked: compilation must fail before Mihomo -t can fetch them.
const geodataRules=['GEOSITE,cn','GEOIP,CN','IP-ASN,4134','SRC-IP-ASN,4134','SRC-GEOIP,CN','SRC-GEOSITE,cn'];
for(const rule of geodataRules) {
 assert.throws(()=>lib.compile({...subscription,rules:[rule+',Chosen']},env,{}),/Geodata rules require locked assets/,rule);
 const source={...subscription,'rule-providers':{remote:{type:'http',url:'https://example.test/rules',behavior:'classical'}},rules:['RULE-SET,remote,Chosen']};
 for(const payload of [rule,' '+rule,'AND,(('+rule+'),(NETWORK,TCP))'])
  assert.throws(()=>lib.compile(source,env,{'rule:remote':{payload:[payload]}}),/Geodata rules require locked assets/,payload);
}
// Only a verified, locally locked Country.mmdb enables country rules.
const geoEnv={...env,geoip_ready:true};
for(const rule of ['GEOIP,CN','SRC-GEOIP,US']) {
 const prepared=lib.compile({...subscription,rules:[rule+',Chosen']},geoEnv,{});
 assert.equal(prepared.rules.at(-2),rule+',Chosen');
 assert.equal(prepared['geodata-mode'],false);
 assert.equal(prepared['geo-auto-update'],false);
 assert.equal(prepared['geox-url'].mmdb,'https://127.0.0.1:1/disabled-geodata');
 const source={...subscription,'rule-providers':{remote:{type:'http',url:'https://example.test/rules',behavior:'classical'}},rules:['RULE-SET,remote,Chosen']};
 for(const payload of [rule,' '+rule,'AND,(('+rule+'),(NETWORK,TCP))'])
  assert.equal(lib.compile(source,geoEnv,{'rule:remote':{payload:[payload]}})['rule-providers'].remote.payload[0],payload);
 for(const ready of [false,1,'true',undefined])assert.throws(()=>lib.compile({...subscription,rules:[rule+',Chosen']},{...env,geoip_ready:ready},{}),/Geodata rules require locked assets/);
}
for(const rule of ['GEOSITE,cn','SRC-GEOSITE,cn','IP-ASN,4134','SRC-IP-ASN,4134','GEOIP-NOT-COUNTRY,CN']) {
 assert.throws(()=>lib.compile({...subscription,rules:[rule+',Chosen']},geoEnv,{}),/Geodata rules require locked assets/);
 const source={...subscription,'rule-providers':{remote:{type:'http',url:'https://example.test/rules',behavior:'classical'}},rules:['RULE-SET,remote,Chosen']};
 for(const payload of [rule,'AND,((GEOIP,CN),('+rule+'))'])assert.throws(()=>lib.compile(source,geoEnv,{'rule:remote':{payload:[payload]}}),/Geodata rules require locked assets/);
}
const localRules={...subscription,'rule-providers':{remote:{type:'http',url:'https://example.test/rules',behavior:'classical'}},rules:['RULE-SET,remote,Chosen']};
assert.deepEqual(lib.compile(localRules,env,{'rule:remote':{payload:['DOMAIN-SUFFIX,example.org','IP-CIDR,203.0.113.0/24']}})['rule-providers'].remote.payload,['DOMAIN-SUFFIX,example.org','IP-CIDR,203.0.113.0/24']);
for(const edit of [
 {proxies:[]},{'proxy-groups':[{name:'bad',type:'select',proxies:['missing']}]},
 {proxies:[{...subscription.proxies[0],plugin:'exec'}]},
 {proxies:[{...subscription.proxies[0],type:'unknown'}]},
 {rules:['DOMAIN,example.com,missing']},{rules:['RULE-SET,missing,Chosen']},
 {'proxy-providers':{p:{type:'file',path:'/etc/shadow'}}},
 {'proxy-groups':[{name:'cycle',type:'select',proxies:['cycle']}]},
 {rules:['SCRIPT,malicious,Chosen']}
])assert.throws(()=>lib.compile({...subscription,...edit},env,{}),JSON.stringify(edit));
const providerSource={...subscription,proxies:[],'proxy-providers':{vendor:{type:'http',url:'https://example.test/private?token=x',path:'/etc/passwd',interval:3600}},
 'proxy-groups':[{name:'Chosen',type:'select',use:['vendor']}]};
const provided=lib.compile(providerSource,env,{vendor:{proxies:subscription.proxies}});
assert.equal(provided['proxy-providers'].vendor.type,'inline');
assert.equal(provided['proxy-providers'].vendor.url,undefined);
assert.equal(provided['proxy-providers'].vendor.path,undefined);
assert.deepEqual(lib.compile(providerSource,nodeHostsEnv,{vendor:{proxies:subscription.proxies}}).hosts['example.test'],['203.0.113.8','198.51.100.9'],'downloaded provider nodes use the same verified local answers');
assert.throws(()=>lib.compile(providerSource,env,{vendor:{proxies:[{...subscription.proxies[0],'client-key':'/etc/shadow'}]}}));
assert.throws(()=>lib.compile(subscription,{...env,bootstrap:['127.0.0.1']},{}));
const rules='0: from all lookup local\n5210: from all fwmark 0x80000/0xff0000 lookup main\n5270: from all lookup 52\n32766: from all lookup main\n32767: from all lookup default\n';
const plan=lib.policy(env,rules,'');
assert.ok(plan.every(a=>!a.includes('flush')));
assert.ok(plan.filter(a=>a[2]==='rule').every(a=>a.includes('iif')&&a.includes('br-lan')));
const ts=plan.find(a=>a.includes('100.64.0.0/10'));
assert.equal(ts.at(-1),'main');assert.ok(Number(ts[5])>5270);
assert.equal(plan.at(-1).at(-1),'2022');
assert.throws(()=>lib.policy(env,rules+'11000: from all lookup 77\n',''));
assert.throws(()=>lib.policy(env,rules.replace('5270:','12000:'),''));
assert.throws(()=>lib.policy(env,rules,'default dev user0\n'));
assert.throws(()=>lib.policy({...env,lan_device:'br-lan;reboot'},rules,''));
const fw=lib.firewall(env);
assert.equal(fw.cmproxy_zone.input,'REJECT');assert.equal(fw.cmproxy_zone.forward,'REJECT');
assert.equal(fw.cmproxy_lan.src,'lan');assert.equal(fw.cmproxy_lan.dest,'cmproxy');
for(const p of ['tcp','udp']){const r=fw['cmproxy_dns_'+p];assert.equal(r.target,'DNAT');assert.equal(r.src,'lan');assert.equal(r.dest_ip,'192.168.50.1');assert.equal(r.dest_port,'1053')}
assert.ok(Object.values(fw).every(s=>s.cm2012_proxy==='1'&&s.cm2012===undefined));
// fw3 runs src=* INPUT rules before zone_*_input, including ACCEPT zones.
const tailscaleFile=path.join(__dirname,'../../configs/templates/cm2012-tailscale-lib.uc');
const tailscaleLib=new Function('type','length','match','split','index','int','push','keys','die',fs.readFileSync(tailscaleFile,'utf8'))(
 v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,v=>v?.length??Object.keys(v||{}).length,
 (v,r)=>String(v).match(r),(v,s)=>v.split(s),(v,x)=>v.indexOf(x),v=>Number.parseInt(v,10),(a,v)=>a.push(v),Object.keys,m=>{throw Error(m)});
function inputVerdict(proxyFirewall,packet,ports=['9091','1053']) {
 const ts=tailscaleLib.render({enabled:'1',allowed_sources:['100.80.0.2/32'],management_ports:ports},{up:true,l3_device:'br-lan','ipv4-address':[{address:'192.168.50.1',mask:24}]}).firewall;
 const sections=[...Object.values(proxyFirewall),...Object.values(ts)],rules=sections.filter(s=>s['.type']==='rule'&&!s.dest);
 const ip=n=>n.split('.').reduce((v,p)=>v*256+Number(p),0);
 const matches=r=>{
  if(r.dest_ip && r.dest_ip!==packet.dest)return false;
  if(r.proto && !String(r.proto).split(' ').includes(packet.proto))return false;
  if(r.dest_port && !(Array.isArray(r.dest_port)?r.dest_port:String(r.dest_port).split(' ')).includes(String(packet.port)))return false;
  if(r.src_ip){const [address,prefix='32']=r.src_ip.split('/'),block=2**(32-Number(prefix));if(Math.floor(ip(address)/block)!==Math.floor(ip(packet.source)/block))return false;}
  if(r.device && r.device!==packet.device)return false;
  if(r.extra){const m=r.extra.match(/^(! )?-i ([a-zA-Z0-9_.:-]+)$/);assert.ok(m,'unsupported interface test');if((packet.device===m[2])===Boolean(m[1]))return false;}
  return true;
 };
 for(const r of rules.filter(r=>r.src==='*'))if(matches(r))return r.target;
 for(const r of rules.filter(r=>r.src===packet.zone))if(matches(r))return r.target;
 return packet.zone==='trusted'?'ACCEPT':sections.find(s=>s['.type']==='zone'&&s.name===packet.zone)?.input||'REJECT';
}
for(const [zone,device,source,port,proto,want] of [
 ['lan','br-lan','192.168.50.2',1053,'tcp','ACCEPT'],['lan','br-lan','192.168.50.2',1053,'udp','ACCEPT'],['lan','br-lan','192.168.50.2',9091,'tcp','ACCEPT'],
 ['wan','eth0','192.168.50.2',1053,'tcp','REJECT'],['wan','eth0','198.51.100.2',9091,'tcp','REJECT'],
 ['trusted','oldtun0','198.51.100.2',1053,'udp','REJECT'],['trusted','oldtun0','198.51.100.2',9091,'tcp','REJECT'],
 ['cm2012_ts','tailscale0','100.80.0.2',9091,'tcp','ACCEPT'],['cm2012_ts','tailscale0','100.80.0.3',9091,'tcp','REJECT'],
 ['cm2012_ts','tailscale0','100.80.0.2',1053,'tcp','REJECT'],['cm2012_ts','tailscale0','100.80.0.2',1053,'udp','REJECT'],['cm2012_ts','tailscale0','100.80.0.2',9091,'udp','REJECT']
])assert.equal(inputVerdict(fw,{zone,device,source,port,proto,dest:'192.168.50.1'}),want,`${zone} ${source} ${proto}/${port}`);
assert.equal(inputVerdict(fw,{zone:'cm2012_ts',device:'tailscale0',source:'100.80.0.2',port:9091,proto:'tcp',dest:'192.168.50.1'},['22']),'REJECT','a Tailscale source still needs management_ports authorization for 9091');
assert.equal(lib.guard(2,false),3);assert.equal(lib.guard(2,true),0);
assert.equal(lib.request({enabled:'1',expected_revision:'2'},'3').error!==undefined,true);
assert.equal(lib.request({enabled:'1',expected_revision:'3',subscription_url:'http://example.test'},'3').error!==undefined,true);
assert.equal(lib.request({enabled:'0',expected_revision:'3'},'3').enabled,'0');
const workerToken='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',workerArgs='/bin/sh\0/usr/libexec/cm2012-proxy\0update\0'+workerToken+'\0';
assert.equal(lib.worker_command(workerArgs,'update',workerToken),true);
for(const line of [workerArgs.replace('/usr/libexec/cm2012-proxy','/tmp/usr/libexec/cm2012-proxy'),workerArgs.replace('update\0','transaction\0'),workerArgs+'extra\0',workerArgs.replace(workerToken,'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'),'/bin/sh\0-c\0'+workerArgs])assert.equal(lib.worker_command(line,'update',workerToken),false,'only the exact worker process may be cancelled');
console.log('PROXY_BOUNDARIES_OK');
// The production transaction state machine uses an explicit OS boundary.
const serviceFile=path.join(__dirname,'../../configs/remote-proxy/cm2012-proxy-service.uc');
assert.ok(fs.existsSync(serviceFile),'production proxy transaction state machine is required');
const factory=new Function('type','length','match','split','index','int','push','join','json','sprintf','keys','die',fs.readFileSync(serviceFile,'utf8').replace(/for\(let (\w+) in /g,'for(let $1 of '))(
 v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,
 v=>v?.length??Object.keys(v||{}).length,(v,r)=>String(v).match(r),(v,s)=>v.split(s),(v,x)=>v.indexOf(x),
 v=>Number.parseInt(v,10),(a,v)=>a.push(v),(s,a)=>a.join(s),JSON.parse,
 (s,n)=>s==='%J'?JSON.stringify(n):s.replace('%d',String(n)),Object.keys,m=>{throw new Error(m)});
function os(){const files={'/etc/config/cm2012_proxy':'old-uci'},dirs=new Set(),settings={enabled:'0',revision:'0',subscription_url:'https://example.test/sub'},commands=[];let firewall={foreign:{name:'user'}},healthy=true;
 return {files,dirs,settings,commands,get healthy(){return healthy},set healthy(v){healthy=v},now:()=>10,uuid:()=> 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
 exists:p=>Object.hasOwn(files,p)||dirs.has(p),read:p=>files[p]??null,write:(p,v)=>{files[p]=v},remove:p=>{delete files[p]},
 mkdir:p=>{if(dirs.has(p))return false;dirs.add(p);return true},remove_tree:p=>{for(const k of Object.keys(files))if(k.startsWith(p+'/'))delete files[k];dirs.delete(p)},
 copy:(a,b)=>{if(!Object.hasOwn(files,a))return false;files[b]=files[a];return true},sync:()=>true,
 config:()=>({...settings}),save:c=>{Object.assign(settings,c);files['/etc/config/cm2012_proxy']=JSON.stringify(settings)},reload:()=>{},
 restore_config:()=>{Object.assign(settings,{enabled:'0',revision:'0'});return true},
 decision_lock:()=>true,decision_unlock:()=>{},spawn:()=>true,stop_worker:()=>true,ensure_guard:()=>true,env:()=>({...env}),secret:()=>env.secret,fetch:()=>subscription,
 test:()=>true,run:a=>{commands.push(a);return true},capture:a=>a.includes('rule')?rules:'',
 firewall:w=>{for(const [k,v] of Object.entries(firewall))if(v.cm2012_proxy==='1')delete firewall[k];Object.assign(firewall,w)},
 get fw(){return firewall},health:()=>healthy,version:()=> 'v1.19.32'};}
const io=os(),svc=factory.create(io,lib);
assert.ok(svc.apply({enabled:'1',expected_revision:'9'}).error);
const applied=svc.apply({enabled:'1',expected_revision:'0'});assert.equal(applied.timeout,90);
assert.ok(io.exists('/etc/cm2012-proxy-transaction/prepared'));
assert.ok(svc.apply({enabled:'1',expected_revision:'0'}).error,'pending transaction blocks a second write');
assert.equal(svc.transaction().error,undefined);assert.equal(svc.status().state,'active');
assert.equal(svc.confirm({token:'wrong'}).error!==undefined,true);
assert.equal(svc.confirm({token:applied.token}).confirmed,true);
assert.equal(io.exists('/etc/cm2012-proxy-transaction'),false);
const old=io.read('/etc/cm2012-proxy/active.json');io.fetch=()=>{throw Error('https://secret.test?password=x')};
const failed=svc.update_subscription({expected_revision:'1'});assert.ok(svc.update(failed.token).error);assert.equal(io.read('/etc/cm2012-proxy/active.json'),old);
assert.equal(JSON.stringify(svc.status()).includes('password'),false);
io.healthy=false;svc.guard();svc.guard();svc.guard();
assert.equal(svc.status().state,'degraded');assert.equal(io.fw.foreign.name,'user');
assert.equal(Object.values(io.fw).some(s=>s.cm2012_proxy==='1'),false);
assert.ok(io.commands.some(a=>a[2]==='rule'&&a[3]==='del'&&a.includes('iif')));
console.log('PROXY_TRANSACTIONS_OK');
// Expiring during a blocking remote fetch must never resurrect the candidate.
const late=os(),lateSvc=factory.create(late,lib),pendingApply=lateSvc.apply({enabled:'1',expected_revision:'0'});
late.fetch=()=>{late.write('/etc/cm2012-proxy-transaction/rolling-back','1');return subscription;};
assert.ok(lateSvc.transaction().error);
assert.equal(late.read('/etc/cm2012-proxy/active.json'),null);
assert.equal(late.settings.enabled,'0');
assert.ok(pendingApply.token);
const timeout=os(),timeoutSvc=factory.create(timeout,lib);
timeoutSvc.apply({enabled:'1',expected_revision:'0'});timeout.now=()=>311;let stopped=false;timeout.stop_worker=()=>{stopped=true;return true;};
timeoutSvc.guard();assert.equal(stopped,true);assert.equal(timeout.exists('/etc/cm2012-proxy-transaction'),false);
const pendingDisable=os(),disableSvc=factory.create(pendingDisable,lib);
disableSvc.apply({enabled:'1',expected_revision:'0'});disableSvc.transaction();
assert.equal(disableSvc.disable({expected_revision:'1'}).disabled,true);
assert.equal(pendingDisable.settings.enabled,'0');assert.equal(pendingDisable.exists('/etc/cm2012-proxy-transaction'),false);
console.log('PROXY_DEADLINE_RECOVERY_OK');
// Scheduling must perform no remote I/O, and a slow provider cannot own the network lock.
function activeService(){const io=os(),svc=factory.create(io,lib),a=svc.apply({enabled:'1',expected_revision:'0'});svc.transaction();svc.confirm({token:a.token});return {io,svc};}
const asynchronous=activeService();let fetched=0,scheduled=[];
asynchronous.io.fetch=()=>{fetched++;return subscription;};asynchronous.io.spawn=(action,token)=>{scheduled.push({action,token});return true;};
asynchronous.io.now=()=>86410;asynchronous.svc.guard();
assert.equal(fetched,0,'guard must return without downloading a subscription');
assert.equal(scheduled[0].action,'update');assert.equal(asynchronous.svc.status().updating,true);
const asyncToken=scheduled[0].token;assert.equal(asynchronous.svc.update(asyncToken).updated,true);
assert.equal(fetched,1);assert.equal(asynchronous.svc.status().updating,false);
const durable=activeService(),durableOld=durable.io.read('/etc/cm2012-proxy/active.json'),durableUpdate=durable.svc.update_subscription({expected_revision:'1'});let snapshotSynced=false;
const durableWrite=durable.io.write;durable.io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});
durable.io.sync=()=>{if(!snapshotSynced && durable.io.read('/etc/cm2012-proxy/update-undo/published')==='1'){
 assert.equal(durable.io.read('/etc/cm2012-proxy/update-undo/before0'),durableOld);assert.equal(durable.io.exists('/tmp/cm2012-wifi/apply.lock'),false,'syncing the undo record must not hold the network lock');snapshotSynced=true;
}};
durable.io.write=(p,v)=>{if(p==='/etc/cm2012-proxy/active.json' && v!==durableOld)assert.equal(snapshotSynced,true,'publication must follow durable undo data and marker');durableWrite(p,v);};
assert.equal(durable.svc.update(durableUpdate.token).updated,true);assert.equal(durable.io.exists('/etc/cm2012-proxy/update-undo'),false);

const cancelled=activeService(),kept=cancelled.io.read('/etc/cm2012-proxy/active.json');let cancelledWorker;
cancelled.io.stop_worker=(action,token)=>{cancelledWorker={action,token};return true;};
const queued=cancelled.svc.update_subscription({expected_revision:'1'});assert.equal(queued.updating,true);
cancelled.io.fetch=()=>{
 assert.equal(cancelled.io.exists('/tmp/cm2012-wifi/apply.lock'),false,'download must not hold the shared network lock');
 assert.equal(cancelled.svc.disable({expected_revision:'1'}).disabled,true,'disable must work during a provider download');
 return subscription;
};
assert.ok(cancelled.svc.update(queued.token).error);assert.deepEqual(cancelledWorker,{action:'update',token:queued.token});
assert.equal(cancelled.io.settings.enabled,'0');assert.equal(cancelled.io.read('/etc/cm2012-proxy/active.json'),kept);
assert.equal(cancelled.io.exists('/tmp/cm2012-wifi/apply.lock'),false);assert.equal(cancelled.svc.status().updating,false);
assert.ok(cancelled.svc.update(queued.token).error,'an obsolete worker cannot resurrect a cancelled update');

const lateTransaction=os(),lateTransactionSvc=factory.create(lateTransaction,lib),firstTransaction=lateTransactionSvc.apply({enabled:'1',expected_revision:'0'});let nextTransaction;
lateTransaction.fetch=()=>{
 assert.equal(lateTransactionSvc.disable({expected_revision:'1'}).disabled,true);
 lateTransaction.uuid=()=> 'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee';
 nextTransaction=lateTransactionSvc.apply({enabled:'1',expected_revision:'1'});assert.ok(nextTransaction.token);return subscription;
};
assert.ok(lateTransactionSvc.transaction(firstTransaction.token).error);
assert.equal(lateTransactionSvc.status().pending_token,nextTransaction.token,'an obsolete transaction worker must not roll back a newer transaction');

const duringHealth=activeService(),healthUpdate=duringHealth.svc.update_subscription({expected_revision:'1'});
const healthOld={active:duringHealth.io.read('/etc/cm2012-proxy/active.json'),subscription:duringHealth.io.read('/etc/cm2012-proxy/subscription.json'),environment:duringHealth.io.read('/etc/cm2012-proxy/environment.json')};
duringHealth.io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});
duringHealth.io.health=wait=>{if(wait)assert.equal(duringHealth.svc.disable({expected_revision:'1'}).disabled,true);return true;};
assert.ok(duringHealth.svc.update(healthUpdate.token).error);assert.equal(duringHealth.svc.status().routing_ready,false);assert.equal(duringHealth.io.settings.enabled,'0');
assert.equal(duringHealth.io.read('/etc/cm2012-proxy/active.json'),healthOld.active,'disable during post-publication health must restore the old active file');
assert.equal(duringHealth.io.read('/etc/cm2012-proxy/subscription.json'),healthOld.subscription);assert.equal(duringHealth.io.read('/etc/cm2012-proxy/environment.json'),healthOld.environment);

for(const cause of ['health-failure','deadline','new-revision','power-loss']) {
 const inFlight=activeService(),oldActive=inFlight.io.read('/etc/cm2012-proxy/active.json'),inFlightUpdate=inFlight.svc.update_subscription({expected_revision:'1'});
 inFlight.io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});
 inFlight.io.health=wait=>{
  if(inFlight.io.read('/etc/cm2012-proxy/active.json')===oldActive)return true;
  if(!wait)return false;
  assert.notEqual(inFlight.io.read('/etc/cm2012-proxy/active.json'),oldActive,'the new candidate has already been published');
  if(cause==='new-revision'){inFlight.io.settings.revision='2';inFlight.io.write('/etc/cm2012-proxy/active.json','new-owner-active');inFlight.io.write('/etc/cm2012-proxy/subscription.json','new-owner-subscription');inFlight.io.write('/etc/cm2012-proxy/environment.json','new-owner-environment');}
  if(cause==='power-loss'){inFlight.io.remove_tree('/tmp/cm2012-proxy/update');assert.equal(factory.create(inFlight.io,lib).recover().error,undefined);return false;}
  if(cause==='deadline' || cause==='new-revision'){inFlight.io.now=()=>311;inFlight.svc.guard();}
  else {inFlight.svc.guard();inFlight.svc.guard();inFlight.svc.guard();}
  return false;
 };
 assert.ok(inFlight.svc.update(inFlightUpdate.token).error);assert.equal(inFlight.svc.status().updating,false);
 // Boot and a failed new core may defer activation until the next healthy tick.
 inFlight.svc.guard();
 assert.equal(inFlight.io.read('/etc/cm2012-proxy/active.json'),cause==='new-revision'?'new-owner-active':oldActive,'cancel restores snapshots only while it still owns the configuration revision');
 if(cause==='new-revision'){assert.equal(inFlight.io.read('/etc/cm2012-proxy/subscription.json'),'new-owner-subscription');assert.equal(inFlight.io.read('/etc/cm2012-proxy/environment.json'),'new-owner-environment');}
 assert.equal(inFlight.io.exists('/tmp/cm2012-wifi/apply.lock'),false);
 assert.equal(inFlight.io.exists('/etc/cm2012-proxy/update-undo'),false,'the consumed undo record must not resurrect an obsolete version later');
}

const expired=activeService(),expiring=expired.svc.update_subscription({expected_revision:'1'});expired.io.now=()=>311;expired.svc.guard();
assert.equal(expired.svc.status().updating,false);assert.ok(expired.svc.status().update_error);assert.ok(expired.svc.update(expiring.token).error);
const newUplink=activeService();let uplinkFetches=0;newUplink.io.env=()=>({...env,bootstrap:['9.9.9.9']});newUplink.io.fetch=()=>{uplinkFetches++;return subscription;};
const uplinkReconcile=newUplink.svc.reconcile();assert.equal(uplinkFetches,0);assert.equal(newUplink.svc.update(uplinkReconcile.token).updated,true);
assert.equal(uplinkFetches,1,'uplink DNS changes must recompile bootstrap even when the LAN address stays the same');
assert.deepEqual(JSON.parse(newUplink.io.read('/etc/cm2012-proxy/active.json')).dns['proxy-server-nameserver'],['9.9.9.9']);

const precise=activeService(),installed=JSON.parse(precise.io.read('/etc/cm2012-proxy/routes.json')),beforeWithdrawal=precise.io.commands.length;
precise.svc.disable({expected_revision:'1'});
assert.deepEqual(precise.io.commands.slice(beforeWithdrawal).filter(a=>a[3]==='del'),installed.reverse().map(a=>a.map((v,i)=>i===3?'del':v)),'withdraw only exact persisted route and rule identities, including device, prefix, table, protocol and metric');

const badProvider=activeService(),badBefore=badProvider.io.read('/etc/cm2012-proxy/active.json'),beforeCommands=badProvider.io.commands.length;
badProvider.io.fetch=url=>{if(url.endsWith('/sub'))return providerSource;throw Error('private provider failure token=secret');};
const badUpdate=badProvider.svc.update_subscription({expected_revision:'1'});assert.ok(badProvider.svc.update(badUpdate.token).error);
assert.equal(badProvider.io.read('/etc/cm2012-proxy/active.json'),badBefore);assert.equal(badProvider.io.commands.length,beforeCommands,'failed staging must leave the running core and routes intact');
assert.equal(JSON.stringify(badProvider.svc.status()).includes('secret'),false);assert.ok(badProvider.svc.status().update_error);
const retry=activeService();let retrySpawns=0;retry.io.now=()=>86410;retry.io.spawn=()=>{retrySpawns++;return true;};retry.io.fetch=()=>{throw Error('unavailable')};
retry.svc.guard();const retryToken=retry.io.read('/tmp/cm2012-proxy/update/token');assert.ok(retry.svc.update(retryToken).error);
retry.svc.guard();assert.equal(retrySpawns,1,'a failed scheduled download must not retry on every five-second health tick');
retry.io.now=()=>87310;retry.svc.guard();assert.equal(retrySpawns,2);
const rebooted=activeService();let rebootSpawns=0;rebooted.io.write('/etc/cm2012-proxy/last-update','200000');rebooted.io.now=()=>86410;rebooted.io.spawn=()=>{rebootSpawns++;return true;};
rebooted.svc.guard();assert.equal(rebootSpawns,1,'a last-update uptime from an earlier boot must not suppress daily updates');

const revision=activeService(),revisionBefore=revision.io.read('/etc/cm2012-proxy/active.json'),revisionUpdate=revision.svc.update_subscription({expected_revision:'1'});
revision.io.fetch=()=>{revision.io.settings.revision='2';return {...subscription,proxies:[{...subscription.proxies[0],name:'replacement'}],'proxy-groups':[],rules:[]};};
assert.ok(revision.svc.update(revisionUpdate.token).error);assert.equal(revision.io.read('/etc/cm2012-proxy/active.json'),revisionBefore);

const guardFailure=activeService(),guardUpdate=guardFailure.svc.update_subscription({expected_revision:'1'});guardFailure.io.healthy=false;
guardFailure.svc.guard();guardFailure.svc.guard();guardFailure.svc.guard();
assert.equal(guardFailure.svc.status().routing_ready,false);assert.ok(guardFailure.svc.update(guardUpdate.token).error);
const noGuard=os();noGuard.ensure_guard=()=>false;const noGuardService=factory.create(noGuard,lib);
assert.ok(noGuardService.apply({enabled:'1',expected_revision:'0'}).error);assert.equal(noGuard.exists('/etc/cm2012-proxy-transaction'),false);
console.log('PROXY_ASYNC_UPDATE_OK');

// Exercise the real native cancellation adapter at filesystem/system boundaries.
function nativeAdapter(){
 const files={},dirs=new Set(),commands=[],controls={killExits:true};
 const nativeFile=path.join(__dirname,'../../configs/remote-proxy/cm2012-proxy-native.uc');
 const source=fs.readFileSync(nativeFile,'utf8').replace(/^import .*;\r?$/mg,'').replace(/\b0([0-7]{3})\b/g,'0o$1').replace(/for\(let (\w+) in /g,'for(let $1 of ');
 const native=new Function('readfile','open','mkdir','chmod','popen','lsdir','stat','unlink','rmdir','rename','lstat','cursor','connect','loadfile','system','replace','trim','type','length','match','split','index','int','push','join','json','sprintf','keys','die',source)(
  p=>files[p]??null,(p)=>({write:v=>{files[p]=v;return v.length;},close:()=>true}),p=>{if(dirs.has(p))return false;dirs.add(p);return true;},()=>true,()=>{throw Error('unexpected popen')},
  p=>[...new Set(Object.keys(files).filter(k=>k.startsWith(p+'/')).map(k=>k.slice(p.length+1).split('/')[0]))],p=>files[p]!=null?{type:'file',size:files[p].length}:dirs.has(p)?{type:'directory'}:null,
  p=>{delete files[p];return true;},p=>{dirs.delete(p);return true;},(a,b)=>{files[b]=files[a];delete files[a];return true;},p=>files[p]!=null?{type:'file'}:null,()=>{},()=>{},
  p=>()=>p.endsWith('lib.uc')?lib:{create:io=>io},s=>{commands.push(s);if(controls.killExits && s.includes("'kill' '-KILL'"))for(const key of Object.keys(files))if(key.startsWith('/proc/123/'))delete files[key];return 0;},(s,r,v)=>s.replace(r,v),s=>s.trim(),
  v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,v=>v?.length??Object.keys(v||{}).length,(v,r)=>String(v).match(r),(v,s)=>v.split(s),(v,x)=>v.indexOf(x),
  v=>Number.parseInt(v,10),(a,v)=>a.push(v),(s,a)=>a.join(s),JSON.parse,(s,n)=>s==='%J'?JSON.stringify(n):s==='%c'?String.fromCharCode(n):s.replace('%d',String(n)),Object.keys,m=>{throw Error(m)});
 return {native,files,dirs,commands,controls};
}
const cancellation=nativeAdapter(),pidfile='/tmp/cm2012-proxy/update-'+workerToken+'.pid';
cancellation.files[pidfile]='123';cancellation.files['/proc/123/cmdline']=workerArgs;cancellation.files['/proc/123/stat']='123 (cm2012-proxy) S 1 123 123 0 0 0';
cancellation.dirs.add('/tmp/cm2012-wifi/apply.lock');cancellation.files['/tmp/cm2012-wifi/apply.lock/proxy-owner']=workerToken;
cancellation.native.stop_worker('update',workerToken);
assert.equal(cancellation.commands.filter(s=>s.includes("'kill'")).length,2);assert.equal(cancellation.dirs.has('/tmp/cm2012-wifi/apply.lock'),false);
const stalledGroup=nativeAdapter();stalledGroup.controls.killExits=false;
stalledGroup.files[pidfile]='123';stalledGroup.files['/proc/123/cmdline']=workerArgs;stalledGroup.files['/proc/123/stat']='123 (cm2012-proxy) S 1 123 123 0 0 0';
stalledGroup.files['/proc/124/stat']='124 (fw3) D 123 123 123 0 0 0';
assert.equal(stalledGroup.native.stop_worker('update',workerToken),false);
delete stalledGroup.files[pidfile];delete stalledGroup.files['/proc/123/stat'];delete stalledGroup.files['/proc/123/cmdline'];
assert.equal(stalledGroup.native.stop_worker('update',workerToken),false,'a surviving child is still owned after the leader trap removes its pidfile');
delete stalledGroup.files['/proc/124/stat'];
assert.equal(stalledGroup.native.stop_worker('update',workerToken),true);
for(const wrong of [workerArgs.replace(workerToken,'bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee'),workerArgs.replace('update\0','transaction\0'),'/bin/sh\0-c\0'+workerArgs]){
 const unrelated=nativeAdapter();unrelated.files[pidfile]='123';unrelated.files['/proc/123/cmdline']=wrong;unrelated.files['/proc/123/stat']='123 (cm2012-proxy) S 1 123 123 0 0 0';
 unrelated.native.stop_worker('update',workerToken);assert.equal(unrelated.commands.length,0,'never kill a reused PID or a different worker');
}
const notLeader=nativeAdapter();notLeader.files[pidfile]='123';notLeader.files['/proc/123/cmdline']=workerArgs;notLeader.files['/proc/123/stat']='123 (cm2012-proxy) S 1 100 100 0 0 0';
notLeader.native.stop_worker('update',workerToken);assert.equal(notLeader.commands.length,0);
const parallelHealth=nativeAdapter();parallelHealth.files['/proc/self/stat']='456 (ucode) S 1 456 456 0';parallelHealth.files['/etc/cm2012-proxy/active.json']=JSON.stringify(config);parallelHealth.files['/etc/cm2012-proxy/secret']=env.secret;parallelHealth.dirs.add('/sys/class/net/mihomo0');
parallelHealth.native.health(false);
assert.ok(parallelHealth.commands.some(s=>s.includes("'cm2012-proxy-fetch'") || s.includes("'/usr/libexec/cm2012-proxy-fetch'")),'local API health must use the fixed loopback transport');
assert.equal(parallelHealth.commands.some(s=>s.includes("'curl'")),false,'periodic health checks must not drain /dev/random through system curl initialization');
assert.equal(parallelHealth.commands.some(s=>s.includes(env.secret)),false,'Bearer secrets never enter process arguments');
console.log('PROXY_NATIVE_WORKER_OK');
// A LAN can become ready after the core's first boot-time bind attempt failed.
// Reconciliation must restart its listeners even when the IP/DNS values match.
const lateLan=activeService();lateLan.svc.suspend();lateLan.io.healthy=false;
const lateLanRun=lateLan.io.run;
lateLan.io.run=a=>{if(a[0]==='/etc/init.d/cm2012-mihomo' && a[1]==='restart')lateLan.io.healthy=true;return lateLanRun(a);};
const lateLanUpdate=lateLan.svc.reconcile();
assert.equal(lateLanUpdate.updating,true);
assert.equal(lateLan.svc.update(lateLanUpdate.token).error,undefined,'late LAN readiness must recover the core listeners');
assert.equal(lateLan.svc.status().routing_ready,true);
console.log('PROXY_LATE_LAN_RECOVERY_OK');
// Saving a private subscription is independent of enabling traffic capture.
const saveOnly=os(),saveOnlySvc=factory.create(saveOnly,lib),privateUrl='https://private.example/sub?token=never-display';
assert.equal(typeof saveOnlySvc.save_subscription,'function','saving a subscription must not require an enable transaction');
assert.equal(saveOnlySvc.save_subscription({subscription_url:privateUrl,expected_revision:'0'}).saved,true);
assert.equal(saveOnly.settings.subscription_url,privateUrl);assert.equal(saveOnly.settings.enabled,'0');
assert.equal(saveOnly.exists('/etc/cm2012-proxy-transaction'),false);assert.equal(saveOnlySvc.status().subscription_saved,true);
assert.equal(JSON.stringify(saveOnlySvc.status()).includes('never-display'),false);
assert.ok(saveOnlySvc.save_subscription({subscription_url:'http://unsafe.example',expected_revision:'1'}).error);
assert.equal(saveOnly.settings.subscription_url,privateUrl);
const retained=os(),retainedSvc=factory.create(retained,lib);
const retainedApply=retainedSvc.apply({enabled:'1',subscription_url:privateUrl,expected_revision:'0'});
assert.equal(retained.settings.subscription_url,privateUrl,'apply persists the URL before launching its worker');
retained.fetch=()=>{throw Error('https://private.example/sub?token=never-display');};
assert.ok(retainedSvc.transaction(retainedApply.token).error);
assert.equal(JSON.parse(retained.read('/etc/config/cm2012_proxy')).subscription_url,privateUrl,'failed activation must retain the saved subscription');
assert.equal(retained.settings.enabled,'0');assert.ok(retainedSvc.status().apply_error);
assert.equal(JSON.stringify(retainedSvc.status()).includes('never-display'),false);
const preparing=os(),preparingSvc=factory.create(preparing,lib);let clock=10;preparing.now=()=>clock;
const preparingApply=preparingSvc.apply({enabled:'1',expected_revision:'0'});
preparing.healthy=false;preparing.fetch=()=>{
 clock=100;for(let i=0;i<4;i++)preparingSvc.guard();
 assert.equal(preparingSvc.status().state,'checking','an unstarted core is not a failed running core');
 assert.equal(preparingSvc.status().pending_ready,false);
 preparing.healthy=true;return subscription;
};
assert.equal(preparingSvc.transaction(preparingApply.token).error,undefined,'download preparation must not consume the 90-second confirmation window');
assert.equal(preparingSvc.status().pending_ready,true);assert.equal(preparingSvc.status().remaining,90);
clock=189;preparingSvc.guard();assert.equal(preparingSvc.status().pending,true);
clock=191;preparingSvc.guard();assert.equal(preparingSvc.status().pending,false);
const tlsFailure=os(),tlsFailureSvc=factory.create(tlsFailure,lib),tlsApply=tlsFailureSvc.apply({enabled:'1',expected_revision:'0'});
tlsFailure.fetch=()=>{throw Error('Subscription TLS failed');};tlsFailureSvc.transaction(tlsApply.token);
assert.match(tlsFailureSvc.status().apply_error,/TLS|HTTPS/);
console.log('PROXY_APPLY_FEEDBACK_AND_SAVE_OK');
const savingDuringUpdate=activeService(),savingUpdate=savingDuringUpdate.svc.update_subscription({expected_revision:'1'});
savingDuringUpdate.io.fetch=()=>({...subscription,proxies:[{...subscription.proxies[0],port:8443}]});
savingDuringUpdate.io.health=wait=>{
 if(wait)assert.ok(savingDuringUpdate.svc.save_subscription({subscription_url:privateUrl,expected_revision:'1'}).error,'saving cannot cancel a published candidate whose process is being health checked');
 return true;
};
assert.equal(savingDuringUpdate.svc.update(savingUpdate.token).updated,true);
assert.equal(JSON.parse(savingDuringUpdate.io.read('/etc/cm2012-proxy/active.json')).proxies[0].port,8443);
console.log('PROXY_SAVE_UPDATE_SERIALIZED_OK');

// Rule subscriptions commonly exceed 32 providers; bounded staging must still
// materialize all supported rules before asking Mihomo to check the candidate.
function ruleProviderSubscription(count) {
 const providers={};
 for(let i=0;i<count;i++)providers['rules'+i]={type:'http',url:'https://example.test/rules/'+i,behavior:'domain'};
 return {...subscription,'rule-providers':providers,rules:['RULE-SET,rules0,Chosen']};
}
for(const count of [35,64]) {
 const manyRules=os(),manyRulesSvc=factory.create(manyRules,lib),source=ruleProviderSubscription(count),fetched=[];
 manyRules.fetch=url=>{fetched.push(url);return url===manyRules.settings.subscription_url?source:{payload:['example.org']};};
 const queued=manyRulesSvc.apply({enabled:'1',expected_revision:'0'});
 assert.ok(queued.token);
 assert.equal(manyRulesSvc.transaction(queued.token).error,undefined,count+' HTTP rule providers must prepare successfully');
 assert.equal(manyRulesSvc.status().pending_ready,true);
 assert.equal(fetched.length,count+1,'every rule provider must be downloaded once');
 const generated=JSON.parse(manyRules.read('/etc/cm2012-proxy/active.json'));
 assert.equal(Object.keys(generated['rule-providers']).length,count);
 assert.ok(Object.values(generated['rule-providers']).every(p=>p.type==='inline'&&p.url===undefined));
}
for(const [key,count,message] of [['rule-providers',65,/规则.*64/],['proxy-providers',33,/节点.*32/]]) {
 const limited=os(),limitedSvc=factory.create(limited,lib),providers={},fetched=[];
 for(let i=0;i<count;i++)providers['provider'+i]={type:'http',url:'https://example.test/provider/'+i,behavior:'domain'};
 limited.fetch=url=>{fetched.push(url);return {...subscription,[key]:providers};};
 const queued=limitedSvc.apply({enabled:'1',expected_revision:'0'}),result=limitedSvc.transaction(queued.token);
 assert.ok(result.error,key+' above its limit must be rejected');
 assert.match(limitedSvc.status().apply_error,message,'provider limits need actionable status feedback');
 assert.equal(fetched.length,1,'an excessive provider count must fail before any provider download');
 assert.equal(limited.read('/etc/cm2012-proxy/active.json'),null);
 assert.equal(limitedSvc.status().pending,false);
}
// Each synthetic payload fits the per-download size cap. Their combined JSON
// size crosses 16 MiB at provider six, before the remaining providers are fetched.
const oversized=os(),oversizedSvc=factory.create(oversized,lib),oversizedSource=ruleProviderSubscription(8),oversizedFetches=[];
const boundedPayload={payload:Array(1000).fill('x'.repeat(3000)+'.example.org')};
const payloadBytes=Buffer.byteLength(JSON.stringify(boundedPayload)),providerBudget=16*1024*1024;
assert.ok(payloadBytes<4*1024*1024,'each fixture download must remain individually bounded');
let oversizedChecked=false;oversized.test=()=>{oversizedChecked=true;return true;};
oversized.fetch=url=>{oversizedFetches.push(url);return url===oversized.settings.subscription_url?oversizedSource:boundedPayload;};
const oversizedQueued=oversizedSvc.apply({enabled:'1',expected_revision:'0'});
assert.ok(oversizedSvc.transaction(oversizedQueued.token).error,'aggregate provider payloads must stay bounded');
assert.match(oversizedSvc.status().apply_error,/16\s*(MiB|MB|兆|M)/i,'aggregate size failure must identify its limit');
assert.equal(oversizedFetches.length,1+Math.floor(providerBudget/payloadBytes)+1,'stop downloading as soon as cumulative provider data exceeds the budget');
assert.equal(oversizedChecked,false,'over-budget providers must fail before the core check');
assert.equal(oversized.read('/etc/cm2012-proxy/active.json'),null);
for(const source of [null,[],42,'invalid-root']) {
 const malformed=os(),malformedSvc=factory.create(malformed,lib);let fetches=0;
 malformed.fetch=()=>{fetches++;return source;};
 const queued=malformedSvc.apply({enabled:'1',expected_revision:'0'});
 assert.ok(malformedSvc.transaction(queued.token).error);
 assert.match(malformedSvc.status().apply_error,/格式/,'non-object YAML roots must be reported as invalid subscriptions');
 assert.equal(fetches,1);
}
const unsupportedProvider=os(),unsupportedProviderSvc=factory.create(unsupportedProvider,lib);let unsupportedFetches=0;
unsupportedProvider.fetch=()=>{unsupportedFetches++;return {...subscription,'rule-providers':{local:{type:'file',path:'/etc/private'}}};};
const unsupportedQueued=unsupportedProviderSvc.apply({enabled:'1',expected_revision:'0'});
assert.ok(unsupportedProviderSvc.transaction(unsupportedQueued.token).error);
assert.match(unsupportedProviderSvc.status().apply_error,/HTTP/,'unsupported provider types need configuration feedback');
assert.equal(unsupportedFetches,1,'unsupported provider types must fail before provider downloads');
console.log('PROXY_PROVIDER_STAGING_LIMITS_OK');

// Readiness and external DNS reachability are separate; recovery never bypasses routing.
function dnsMonitor(results) {
 const io=os();let time=1000,probes=0,flushes=0;
 io.settings.enabled='1';io.settings.revision='7';io.now=()=>time;
 io.files['/etc/cm2012-proxy/last-update']='1000';
 io.files['/tmp/cm2012-proxy/routing']=JSON.stringify({lan_device:'br-lan',lan_ip:env.lan_ip});
 io.files['/tmp/cm2012-proxy/status']=JSON.stringify({state:'active'});
 io.external_health=()=>{probes++;return results.length?results.shift():false;};
 io.flush_dns=()=>{flushes++;return true;};
 return {io,svc:factory.create(io,lib),at:t=>{time=t},get probes(){return probes},get flushes(){return flushes}};
}
const dns=dnsMonitor([false,false,true,false,false,false,true]);
assert.equal(dns.svc.status().external_state,'unknown');
dns.svc.guard();assert.equal(dns.probes,1);assert.equal(dns.flushes,0);
assert.equal(dns.svc.status().core_ready,true);assert.equal(dns.svc.status().external_state,'unavailable');
dns.at(1059);dns.svc.guard();assert.equal(dns.probes,1,'one probe per minute');
dns.at(1060);dns.svc.guard();assert.equal(dns.flushes,1);assert.equal(dns.probes,3);
assert.equal(dns.svc.status().external_state,'available');assert.equal(dns.svc.status().dns_recoveries,1);
dns.io.dirs.add('/tmp/cm2012-wifi/pending');
assert.equal(dns.svc.status().external_state,'unknown','pending network change invalidates external evidence immediately');
dns.io.dirs.delete('/tmp/cm2012-wifi/pending');
dns.at(1120);dns.svc.guard();dns.at(1180);dns.svc.guard();
assert.equal(dns.flushes,1,'failed probes cannot bypass the five minute flush cooldown');
assert.equal(dns.svc.status().external_state,'unavailable');
assert.ok(dns.io.exists('/tmp/cm2012-proxy/routing'),'external failures keep interception intact');
assert.ok(!dns.io.commands.some(a=>a.includes('stop')||a.includes('restart')),'no restart storm or direct fallback');
dns.at(1360);dns.svc.guard();assert.equal(dns.flushes,2);assert.equal(dns.svc.status().external_state,'available');
dns.at(1541);assert.equal(dns.svc.status().external_state,'unknown','stale evidence cannot claim availability');
dns.io.settings.revision='8';assert.equal(dns.svc.status().external_state,'unknown','new config invalidates old evidence');
dns.at(1370);dns.svc.guard();assert.equal(dns.probes,8,'a new revision gets a fresh check');
for(const kind of ['disabled','transaction','update','undo','local-failure']) {
 const m=dnsMonitor([true]);
 if(kind==='disabled')m.io.settings.enabled='0';
 if(kind==='transaction'){m.io.dirs.add('/etc/cm2012-proxy-transaction');m.io.files['/etc/cm2012-proxy-transaction/ready']='1';m.io.files['/etc/cm2012-proxy-transaction/deadline']='2000';}
 if(kind==='update'){m.io.dirs.add('/tmp/cm2012-proxy/update');m.io.files['/tmp/cm2012-proxy/update/deadline']='2000';}
 if(kind==='undo'){m.io.dirs.add('/etc/cm2012-proxy/update-undo');m.io.files['/etc/cm2012-proxy/update-undo/revision']='7';}
 if(kind==='local-failure')m.io.healthy=false;
 m.svc.guard();assert.equal(m.probes,0,kind+' must not run external recovery');assert.equal(m.flushes,0);
}
const failedFlush=dnsMonitor([false,false]);failedFlush.io.flush_dns=()=>false;
failedFlush.svc.guard();failedFlush.at(1060);failedFlush.svc.guard();
assert.equal(failedFlush.svc.status().external_state,'unavailable');
assert.equal(failedFlush.svc.status().dns_recovery_error,'cache_flush_failed');
failedFlush.at(1120);failedFlush.svc.guard();assert.equal(failedFlush.probes,3,'failed flush remains rate limited');
const privateProbe=dnsMonitor([]);privateProbe.io.external_health=()=>{throw new Error('https://private.invalid/secret')};
privateProbe.svc.guard();const publicDnsStatus=JSON.stringify(privateProbe.svc.status());
assert.ok(!publicDnsStatus.includes('private.invalid')&&!publicDnsStatus.includes(env.secret)&&!publicDnsStatus.includes(privateProbe.io.settings.subscription_url));
console.log('PROXY_DNS_RECOVERY_OK');
