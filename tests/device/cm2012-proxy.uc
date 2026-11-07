'use strict';
// Isolated pure-policy smoke test; no routes, firewall changes or credentials.
const lib=loadfile('/usr/libexec/cm2012-proxy-lib.uc')();
const env={lan_device:'br-lan',lan_ip:'192.168.50.1',lan_cidr:'192.168.50.0/24',bootstrap:['192.168.1.1'],management:[],secret:'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'};
const raw={proxies:[{name:'test',type:'ss',server:'example.invalid',port:443,cipher:'aes-128-gcm',password:'synthetic'}],rules:[]};
let c=lib.compile(raw,env,{});
if(c.tun['auto-route'] || c.tun.gso || c.ipv6 || c['external-controller']!='127.0.0.1:9090')die('Unsafe generated configuration');
if(c.dns.nameserver[0]!='https://cloudflare-dns.com/dns-query#CM2012-DNS' || c.rules[length(c.rules)-1]!='MATCH,CM2012-DEFAULT')die('Native DNS and default group roles are not separate');
let finalc=lib.compile({proxies:raw.proxies,rules:['MATCH,DIRECT']},env,{});
for(let group in finalc['proxy-groups'])if(group.name=='CM2012-PROXY' || group.name=='CM2012-DEFAULT')die('Native final rule gained an unused local default group');
let legacyc=lib.compile({proxies:raw.proxies,rules:['MATCH,CM2012-PROXY']},env,{});
if(legacyc.rules[length(legacyc.rules)-1]!='MATCH,CM2012-DEFAULT')die('Native legacy fallback reference was not normalized');
let commands=lib.policy(env,'0: from all lookup local\n5270: from all lookup 52\n32766: from all lookup main\n','');
if(length(commands)<10)die('Missing policy');
let failed=false;try{lib.policy(env,'11000: from all lookup 55\n32766: from all lookup main\n','');}catch(e){failed=true;}
if(!failed)die('Policy collision accepted');
let token='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',zero=sprintf('%c',0);
if(!lib.worker_command('/bin/sh'+zero+'/usr/libexec/cm2012-proxy'+zero+'update'+zero+token+zero,'update',token))
 die('Native worker identity mismatch');
let dnsraw={proxies:raw.proxies,rules:[],dns:{'nameserver-policy':{'example.org':'https://dns.google/dns-query','bad.example':'127.0.0.1'}}};
let dnsc=lib.compile(dnsraw,env,{});
if(!dnsc.dns['nameserver-policy']['example.org'] || dnsc.dns['nameserver-policy']['bad.example'])die('Native DNS policy filtering failed');
let geoenv=json(sprintf('%J',env));geoenv.geoip_ready=true;
for(let rule in ['GEOIP,CN','SRC-GEOIP,US']) {
 let source={proxies:raw.proxies,rules:[rule+',DIRECT']};
 let prepared=lib.compile(source,geoenv,{});
 if(prepared['geodata-mode']!==false || prepared['geo-auto-update']!==false || prepared.rules[length(prepared.rules)-2]!=rule+',DIRECT')die('Native GEOIP country compile failed');
 let blocked=false;try{lib.compile(source,env,{});}catch(e){blocked=true;}if(!blocked)die('Native missing GEOIP asset accepted');
}
for(let rule in ['GEOSITE,cn','SRC-GEOSITE,cn','IP-ASN,4134','SRC-IP-ASN,4134']) {
 let blocked=false;try{lib.compile({proxies:raw.proxies,rules:[rule+',DIRECT']},geoenv,{});}catch(e){blocked=true;}if(!blocked)die('Native unsupported geodata accepted');
}
print('CM2012_GEOIP_NATIVE_POLICY_OK\n');
print('CM2012_PROXY_POLICY_OK\n');

// Run the production transaction state machine in real ucode. Every I/O method
// below is in memory: no downloaded URLs, device files, routes or services change.
const factory=loadfile('/usr/libexec/cm2012-proxy-service.uc')();
function service_io(source) {
 let settings={enabled:'0',revision:'0',subscription_url:'https://example.invalid/sub'},files={},dirs={},fetches=[],clock={now:10};
 files['/etc/config/cm2012_proxy']=sprintf('%J',settings);
 function read(path) {return files[path];}
 function write(path,value) {files[path]=value;}
 return {files,fetches,clock,read,write,
  exists:function(path){return files[path]!=null || !!dirs[path];},
  mkdir:function(path){if(dirs[path])return false;dirs[path]=true;return true;},
  remove:function(path){files[path]=null;},
  remove_tree:function(path){for(let name in keys(files))if(index(name,path+'/')==0)files[name]=null;dirs[path]=false;},
  copy:function(from,to){if(files[from]==null)return false;files[to]=files[from];return true;},
  sync:function(){return true;},config:function(){return json(sprintf('%J',settings));},
  save:function(value){settings=json(sprintf('%J',value));files['/etc/config/cm2012_proxy']=sprintf('%J',settings);},
  restore_config:function(){settings=json(files['/etc/config/cm2012_proxy']);return true;},
  uuid:function(){return 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';},now:function(){return clock.now;},
  decision_lock:function(){return true;},decision_unlock:function(){},ensure_guard:function(){return true;},spawn:function(action,value){return true;},stop_worker:function(action,value){return true;},
  env:function(){return json(sprintf('%J',env));},secret:function(){return env.secret;},
  fetch:function(url,work){push(fetches,url);return url=='https://example.invalid/sub'?source:{payload:['example.org']};},
  test:function(path){return true;},run:function(args){return true;},firewall:function(value){},health:function(wait){return true;},
  capture:function(args){return index(args,'rule')>=0?'0: from all lookup local\n5270: from all lookup 52\n32766: from all lookup main\n':'';},
  version:function(){return 'native-fixture';}};
}
for(let provider_maps in [{},{'proxy-providers':null,'rule-providers':null},{'proxy-providers':{},'rule-providers':{}}]) {
 let source=json(sprintf('%J',raw));
 for(let key,value in provider_maps)source[key]=value;
 let io=service_io(source),service=factory.create(io,lib),queued=service.apply({enabled:'1',expected_revision:'0'});
 if(!queued.token)die('Native provider-free transaction was not queued');
 let result=service.transaction(queued.token);
 if(result.error || !service.status().pending_ready || length(io.fetches)!=1)
  die('Native absent, null or empty provider maps failed');
 let restored=service.rollback({token:queued.token});
 if(restored.error || service.status().pending || io.config().enabled!='0')die('Native rollback failed');
}
let native_rules={};
for(let i=0;i<35;i++)native_rules['rule'+i]={type:'http',url:'https://example.invalid/rules/'+i,behavior:'domain'};
let many_source={proxies:raw.proxies,rules:['RULE-SET,rule0,CM2012-PROXY'],'rule-providers':native_rules};
let many_io=service_io(many_source),many_service=factory.create(many_io,lib),many_queued=many_service.apply({enabled:'1',expected_revision:'0'});
if(!many_queued.token)die('Native many-rule transaction was not queued');
let many_result=many_service.transaction(many_queued.token);
if(many_result.error || !many_service.status().pending_ready || length(many_io.fetches)!=36)
 die('Native staging rejected 35 HTTP rule providers');
let native_active=json(many_io.files['/etc/cm2012-proxy/active.json']);
if(length(keys(native_active['rule-providers']))!=35)die('Native staging lost downloaded rule providers');
if(many_service.confirm({token:many_queued.token}).error)die('Native transaction confirmation failed');
for(let defer in [false,true]) {
 let attempt=many_service.update_subscription({expected_revision:many_io.config().revision});
 if(!attempt.token)die('Native update was not queued');
 let first=true;
 many_io.health=function(wait) {
  if(first) {first=false;many_io.clock.now+=301;if(defer)many_io.write('/tmp/cm2012-wifi/pending','1');return false;}
  return true;
 };
 let expired=many_service.update(attempt.token);
 if(!expired.error)die('Native expired update unexpectedly succeeded');
 if(defer) {
  if(!many_io.exists('/etc/cm2012-proxy/update-undo/runtime-pending') || many_io.exists('/tmp/cm2012-proxy/routing'))
   die('Native deferred restoration failed to suspend traffic');
  many_io.remove('/tmp/cm2012-wifi/pending');many_service.guard();
 }
 if(many_io.exists('/etc/cm2012-proxy/update-undo') || many_service.status().state!='active')die('Native update recovery failed');
}
print('CM2012_PROXY_NATIVE_RECOVERY_OK\n');
print('CM2012_PROXY_NATIVE_SERVICE_OK\n');
