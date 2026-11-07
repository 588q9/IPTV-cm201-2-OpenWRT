'use strict';
import { readfile, open, mkdir, chmod, popen, lsdir, stat, lstat, readlink, unlink, rmdir, rename } from 'fs';
import { sha256 } from 'digest';
import { cursor } from 'uci';
import { connect } from 'ubus';
const root='/etc/cm2012-proxy', state='/tmp/cm2012-proxy';
const lib=loadfile('/usr/libexec/cm2012-proxy-lib.uc')();
const factory=loadfile('/usr/libexec/cm2012-proxy-service.uc')();
function quote(v) {return "'"+replace(''+v,/'/g,"'\\''")+"'";}
function command(a) {let s=[];for(let v in a)push(s,quote(v));return join(' ',s);}
function run(a) {return system('CM2012_PROXY_FIREWALL=1 '+command(a)+' </dev/null >/dev/null 2>&1')==0;}
function capture(a) {
 let p=popen(command(a)+' 2>/dev/null');if(!p)die('Command unavailable');
 let v=p.read('all'), code=p.close();if(code!=0)die('Command failed');return v;
}
function write(path,value) {
 let temp=path+'.new',f=open(temp,'w',0600);if(!f)die('File unavailable');
 let n=f.write(value),closed=f.close();
 if(n!=length(value) || !closed || !chmod(temp,0600) || !rename(temp,path))die('Atomic write failed');
}
function remove_tree(path) {
 // All callers pass these fixed module-owned directories, never request paths.
 if(!match(path,/^(\/etc\/cm2012-proxy-transaction(\/decision.lock)?|\/etc\/cm2012-proxy\/update-undo|\/tmp\/cm2012-proxy\/update|\/tmp\/cm2012-wifi\/apply.lock)$/))die('Removal outside module directory');
 for(let name in lsdir(path)||[]) {let p=path+'/'+name,s=stat(p);if(s?.type=='directory') {for(let child in lsdir(p)||[])unlink(p+'/'+child);rmdir(p);}else unlink(p);}
 rmdir(path);
}
function config() {
 let c=cursor();if(!c.load('cm2012_proxy'))die('Configuration unavailable');
 return {enabled:c.get('cm2012_proxy','settings','enabled')||'0',revision:c.get('cm2012_proxy','settings','revision')||'0',subscription_url:c.get('cm2012_proxy','settings','subscription_url')||'',github_rule_api:c.get('cm2012_proxy','settings','github_rule_api')=='1'};
}
function save(value) {
 let c=cursor();if(!c.load('cm2012_proxy'))die('Configuration unavailable');
 for(let key in ['enabled','revision','subscription_url'])if(!c.set('cm2012_proxy','settings',key,value[key]||''))die('Configuration write failed');
 if(!c.commit('cm2012_proxy') || !chmod('/etc/config/cm2012_proxy',0600))die('Configuration commit failed');
}
function geoip_ready() {
 const asset='/usr/share/cm2012/geodata/Country.mmdb';
 try {
  let link=lstat(root+'/Country.mmdb'),file=lstat(asset);
  if(link?.type!='link' || readlink(root+'/Country.mmdb')!=asset || file?.type!='file')return false;
  let locked=json(readfile('/usr/share/cm2012/remote-assets.json')||'{}')['geoip-country-dbip'];
  if(type(locked)!='object' || type(locked.uncompressed_size)!='int' || locked.uncompressed_size<=0 || locked.uncompressed_size>33554432 ||
     file.size!=locked.uncompressed_size || type(locked.uncompressed_sha256)!='string' || !match(locked.uncompressed_sha256,/^[a-f0-9]{64}$/))return false;
  let data=readfile(asset);
  return type(data)=='string' && length(data)==locked.uncompressed_size && sha256(data)==locked.uncompressed_sha256;
 } catch(error) {return false;}
}
function env() {
 let b=connect(),c=cursor();c.load('cm2012');c.load('network');
 let lan=b.call('network.interface.lan','status',{})||{}, uplink=c.get('cm2012','settings','uplink')=='wifi'?'wwan':'wan',interfaces={lan},self_ipv4=[];
 for(let name in ['wan','wwan']) {try {interfaces[name]=b.call('network.interface.'+name,'status',{})||{};}catch(error){interfaces[name]={};}}
 let upper=interfaces[uplink];
 for(let name in ['lan','wan','wwan'])for(let address in interfaces[name]['ipv4-address']||[])if(address.address && index(self_ipv4,address.address)<0)push(self_ipv4,address.address);
 let address=(lan['ipv4-address']||[])[0], device=lan.l3_device||lan.device;
 if(!lan.up || !address || !device)die('LAN unavailable');
 let helper=loadfile('/usr/libexec/cm2012-network-lib.uc')(), cidr=helper.subnet(address.address+'/'+address.mask), management=[];
 c.foreach('network','route',function(s){if(s.interface=='lan' && s.disabled!='1' && s.target && s.target!='0.0.0.0/0')push(management,s.target);});
 return {lan_device:device,lan_ip:address.address,lan_cidr:cidr,bootstrap:upper['dns-server']||[],self_ipv4,management,geoip_ready:geoip_ready(),node_hosts:json(readfile(root+'/node-hosts.json')||'{}'),node_nameservers:json(readfile(root+'/node-dns.json')||'[]')};
}
function secret() {
 if(!readfile(root+'/secret')) {
  if(system('umask 077; openssl rand -hex 32 > '+root+'/secret.new 2>/dev/null')!=0 || !rename(root+'/secret.new',root+'/secret'))die('Secret unavailable');
 }
 let value=trim(readfile(root+'/secret')||'');if(!match(value,/^[a-f0-9]{64}$/))die('Invalid secret');
 if(!stat(root+'/cert.pem') || !stat(root+'/key.pem')) {
  let c=cursor();c.load('uhttpd');let cert=c.get('uhttpd','main','cert')||'/etc/uhttpd.crt',key=c.get('uhttpd','main','key')||'/etc/uhttpd.key';
  // Convert copies only; keep the router's original certificate and key intact.
  let ok=run(['openssl','x509','-in',cert,'-out',root+'/cert.pem.new']) || run(['openssl','x509','-inform','DER','-in',cert,'-out',root+'/cert.pem.new']);
  let keyok=run(['openssl','pkey','-in',key,'-out',root+'/key.pem.new']) || run(['openssl','pkey','-inform','DER','-in',key,'-out',root+'/key.pem.new']);
  if(!ok || !keyok || !chmod(root+'/cert.pem.new',0600) || !chmod(root+'/key.pem.new',0600) || !rename(root+'/cert.pem.new',root+'/cert.pem') || !rename(root+'/key.pem.new',root+'/key.pem'))die('Local TLS certificate unavailable');
 }
 return value;
}
function provider_cache_now() {
 let value=match(readfile('/proc/uptime')||'',/^([0-9]{1,12})(\.[0-9]+)? /);return value?int(value[1]):null;
}
function provider_cache_lock() {
 // A busy or interrupted cache owner only disables this optional optimization.
 try {return mkdir(state+'/provider-cache.lock',0700);}catch(error) {return false;}
}
function provider_cache_unlock() {try {rmdir(state+'/provider-cache.lock');}catch(error) {}}
function provider_cache_drop(key) {
 if(!match(key,/^[a-f0-9]{64}$/))return false;
 let ok=true;
 for(let suffix in ['.body','.meta','.body.new','.meta.new']) {
  let path=state+'/provider-cache/'+key+suffix;if(lstat(path) && !unlink(path))ok=false;
 }
 return ok;
}
function provider_cache_remove(key) {
 if(!provider_cache_lock())return;
 try {provider_cache_drop(key);}catch(error) {}
 provider_cache_unlock();
}
function provider_cache_trim(cache,extra,count) {
 while(cache.bytes+extra>16777216 || cache.count+count>64) {
  let oldest=null;for(let row in cache.rows)if(!row.removed && (!oldest || row.created<oldest.created))oldest=row;
  if(!oldest || !provider_cache_drop(oldest.key))return false;
  oldest.removed=true;cache.bytes-=oldest.bytes;cache.count--;
 }
 return true;
}
function provider_cache_scan(wanted) {
 let directory=state+'/provider-cache',now=provider_cache_now(),s=lstat(directory);
 if(now==null || (s && s.type!='directory'))return null;
 if(!s && !mkdir(directory,0700))return null;
 if(!chmod(directory,0700))return null;
 let files=lsdir(directory),seen={},rows=[],bytes=0;
 if(type(files)!='array' || length(files)>512)return null;
 for(let name in files) {
  let m=match(name,/^([a-f0-9]{64})\.(body|meta)(\.new)?$/);if(!m || m[0]!=name)return null;seen[m[1]]=true;
 }
 for(let key in keys(seen)) {
  let prefix=directory+'/'+key,body=lstat(prefix+'.body'),meta=lstat(prefix+'.meta'),record=null,source=null;
  if(body?.type=='file' && meta?.type=='file' && body.size>0 && body.size<=4194304 && meta.size>0 && meta.size<=512 &&
     !lstat(prefix+'.body.new') && !lstat(prefix+'.meta.new')) {
   try {
    record=json(readfile(prefix+'.meta'));
    if(type(record)!='object' || length(keys(record))!=3 || type(record.created)!='int' || record.created<0 || record.created>now || now-record.created>=3600 ||
       type(record.size)!='int' || record.size!=body.size || type(record.hash)!='string' || !match(record.hash,/^[a-f0-9]{64}$/))record=null;
    if(record) {source=readfile(prefix+'.body');if(type(source)!='string' || length(source)!=record.size || sha256(source)!=record.hash)record=null;}
   } catch(error) {record=null;}
  }
  if(!record) {if(!provider_cache_drop(key))return null;continue;}
  let size=body.size+meta.size;bytes+=size;push(rows,{key,created:record.created,bytes:size,source:key==wanted?source:null});
 }
 let cache={rows,bytes,count:length(rows),now};return provider_cache_trim(cache,0,0)?cache:null;
}
function provider_cache_get(key) {
 if(!provider_cache_lock())return null;
 let source=null;
 try {
  let cache=provider_cache_scan(key);
  if(cache)for(let row in cache.rows)if(!row.removed && row.key==key)source=row.source;
 } catch(error) {}
 provider_cache_unlock();return source;
}
function provider_cache_store(key,source) {
 let cache=provider_cache_scan();if(!cache)return;
 for(let row in cache.rows)if(!row.removed && row.key==key) {if(!provider_cache_drop(key))return;row.removed=true;cache.bytes-=row.bytes;cache.count--;}
 let record=sprintf('%J',{created:cache.now,size:length(source),hash:sha256(source)});
 if(!provider_cache_trim(cache,length(source)+length(record),1))return;
 let prefix=state+'/provider-cache/'+key;
 write(prefix+'.body',source);write(prefix+'.meta',record);
}
function provider_cache_put(key,source) {
 if(!match(key,/^[a-f0-9]{64}$/) || type(source)!='string' || !length(source) || length(source)>4194304 || !provider_cache_lock())return;
 try {
  provider_cache_store(key,source);
 } catch(error) {try {provider_cache_drop(key);}catch(cleanup) {}}
 provider_cache_unlock();
}
function fetch(url,work,format,purpose) {
 if(format==null)format='yaml';
 if(format!='yaml' && format!='text')die('Rule provider format unsupported');
 if(!lib.https(url))die('HTTPS required');
 if(work!=root && work!=state+'/update')die('Invalid download directory');
 function parse() {
  if(format=='text') {
   let source=readfile(work+'/download.yaml');unlink(work+'/download.yaml');return lib.rule_text(source);
  }
  if(!(stat(work+'/download.yaml')?.size||0)) {unlink(work+'/download.yaml');die('Subscription YAML invalid');}
  // ulimit and timeout bound alias expansion / hostile parser resource use.
  let status=system('umask 077; ulimit -t 10; timeout 15 /usr/bin/yq eval -o=json -I=0 \'.\' '+work+'/download.yaml > '+work+'/download.json 2>/dev/null');
  unlink(work+'/download.yaml');
  if(status!=0) {unlink(work+'/download.json');die('Subscription YAML invalid');}
  let source=readfile(work+'/download.json');unlink(work+'/download.json');
  if(!source || length(source)>8388608)die('Subscription size limit');return json(source);
 }
 let api=purpose=='rule' && config().github_rule_api===true?lib.github_rule_api(url):null,key=api?sha256(format+'\n'+url):null;
 if(api) {
  let cached=provider_cache_get(key);
  if(cached!=null) {
   try {write(work+'/download.yaml',cached);return parse();}
   catch(error) {unlink(work+'/download.yaml');unlink(work+'/download.json');provider_cache_remove(key);}
  }
 }
 // Keep the full URL out of process arguments and diagnostics.
 write(work+'/subscription.url',url);
 // The outer limit also covers CRNG initialization before libcurl's timers start.
 let code=system(command(['timeout','45','/usr/libexec/cm2012-proxy-fetch',work+'/subscription.url',work+'/download.yaml','/etc/ssl/certs/ca-certificates.crt'])+' </dev/null >/dev/null 2>&1');unlink(work+'/subscription.url');
 if((code==35 || code==28 || code==124) && api) {
  unlink(work+'/download.yaml');write(work+'/subscription.url',api);
  code=system(command(['timeout','45','/usr/libexec/cm2012-proxy-fetch',work+'/subscription.url',work+'/download.yaml','/etc/ssl/certs/ca-certificates.crt','github-rule'])+' </dev/null >/dev/null 2>&1');unlink(work+'/subscription.url');
 }
 if(code!=0 || (stat(work+'/download.yaml')?.size||0)>4194304) {
  unlink(work+'/download.yaml');
  let failures={'6':'Subscription DNS failed','22':'Subscription HTTP failed','28':'Subscription timed out','124':'Subscription timed out','35':'Subscription TLS failed','60':'Subscription certificate failed','69':'GitHub rule API rate limited'};
  die(failures[''+code] || 'Subscription download failed');
 }
 let source=api?readfile(work+'/download.yaml'):null,result=parse();if(api)provider_cache_put(key,source);return result;
}
function firewall(wanted) {
 let c=cursor();if(!c.load('firewall'))die('Firewall unavailable');
 let previous=[],names=keys(wanted),changed=false;
 c.foreach('firewall',null,function(s){if(s.cm2012_proxy=='1')push(previous,s['.name']);});
 for(let name in previous) {if(!c.delete('firewall',name))die('Firewall deletion failed');changed=true;}
 for(let name in names) {
  if(c.get('firewall',name)!=null)die('Firewall section collision');
  if(!c.set('firewall',name,wanted[name]['.type']))die('Firewall creation failed');
  for(let key in keys(wanted[name]))if(key!='.type' && !c.set('firewall',name,key,wanted[name][key]))die('Firewall write failed');changed=true;
 }
 if(changed && !c.commit('firewall'))die('Firewall commit failed');
}
function health(wait) {
 let tries=wait?10:1;
 while(tries-->0) {
  let active;try {active=json(readfile(root+'/active.json')||'{}');}catch(error){return false;}
  let address=split(active.dns?.listen||'',':')[0];if(!match(address,/^[0-9.]+$/))return false;
  let ok=stat('/sys/class/net/mihomo0') && run(['pidof','mihomo']) && run(['timeout','3','/usr/libexec/cm2012-proxy-fetch','health']);
  if(ok) {
   try {let answer=capture(['timeout','2','drill','-p','1053','@'+address,'cm2012-proxy-health.invalid','A']);if(match(answer,/198\.18\.0\.1/))return true;}catch(error){}
  }
  if(tries>0)run(['sleep','1']);
 }
 return false;
}
function external_health() {
 let active;try {active=json(readfile(root+'/active.json')||'{}');}catch(error){return false;}
 let listener=match(active.dns?.listen||'',/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):1053$/);
 if(!listener)return false;
 let octets=split(listener[1],'.');for(let i=0;i<4;i++)if(+octets[i]>255)return false;
 if(!run(['timeout','5','/usr/libexec/cm2012-proxy-fetch','dns-probe']))return false;
 try {
  let answer=capture(['timeout','2','drill','-p','1053','@'+listener[1],'example.com','A']);
  return !!match(answer,/rcode:[ \t]+NOERROR([, \t\r\n]|$)/) && !!match(answer,/\nexample\.com\.[ \t]+[0-9]+[ \t]+IN[ \t]+A[ \t]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+([ \t\r]*\n|$)/);
 }catch(error){return false;}
}
function flush_dns() {return run(['timeout','3','/usr/libexec/cm2012-proxy-fetch','dns-flush']);}
mkdir(root,0700);chmod(root,0700);mkdir(state,0700);chmod(state,0700);
let decision_handle=null;
function decision_lock() {
 if(decision_handle)return false;
 let path=state+'/decision.lock',s=lstat(path);
 if(s && s.type!='file')return false;
 let f=open(path,'ae',0600);if(!f)return false;
 if(!chmod(path,0600) || !f.lock('xn')){f.close();return false;}
 decision_handle=f;return true;
}
function decision_unlock() {if(decision_handle){decision_handle.lock('u');decision_handle.close();decision_handle=null;}}
let io={read:readfile,write,exists:function(p){return !!stat(p);},mkdir:function(p){return mkdir(p,0700);},remove:unlink,remove_tree,
 copy:function(a,b){let v=readfile(a);if(v==null)return false;write(b,v);return true;},sync:function(){if(!run(['sync']))die('Sync failed');},
 decision_lock,decision_unlock,config,save,restore_config:function(){return true;},uuid:function(){return trim(readfile('/proc/sys/kernel/random/uuid')||'');},
 now:function(){return int(split(readfile('/proc/uptime')||'0',' ')[0]);},run,capture,env,secret,fetch,firewall,health,external_health,flush_dns,
 test:function(file){return system('SAFE_PATHS=/www/metacubexd:/usr/share/cm2012/geodata timeout 20 /usr/bin/mihomo -t -d '+root+' -f '+quote(file)+' </dev/null >/dev/null 2>&1')==0;},
 ensure_guard:function(){
  if(run(['/etc/init.d/cm2012-proxy-guard','running']))return true;
  if(!run(['/etc/init.d/cm2012-proxy-guard','start']))return false;
  for(let i=0;i<3;i++){if(run(['/etc/init.d/cm2012-proxy-guard','running']))return true;run(['sleep','1']);}return false;
 },
 spawn:function(action,token){
  if(!match(token||'',/^[a-f0-9-]{36}$/) || (action!='transaction' && action!='update'))return false;
  return system('setsid /usr/libexec/cm2012-proxy '+quote(action)+' '+quote(token)+' </dev/null >/dev/null 2>&1 &')==0;
 },
 stop_worker:function(action,token){
  if(!match(token||'',/^[a-f0-9-]{36}$/) || (action!='transaction' && action!='update'))return false;
  let file=state+'/'+action+'-'+token+'.pid',stopping=file+'.stopping',record=null;
  try {record=json(readfile(stopping)||'null');}catch(error){return false;}
  let pid=trim(readfile(file)||record?.pid||'');
  if(!pid)return true;
  if(!match(pid,/^[1-9][0-9]{0,6}$/))return false;
  if(record && (record.pid!=pid || type(record.start)!='string'))return false;
  function process(id) {
   let row=match(readfile('/proc/'+id+'/stat')||'',/^[0-9]+ \([^)]*\) (.*)$/);if(!row)return null;
   let f=split(row[1],' ');return {state:f[0],group:f[2],session:f[3],start:f[19]||''};
  }
  function members() {
   let found=[];for(let id in lsdir('/proc')||[])if(match(id,/^[0-9]+$/)) {
    let p=process(id);if(p && p.state!='Z' && p.group==pid && p.session==pid)push(found,id);
   }
   return found;
  }
  let leader=process(pid);
  if(leader && (leader.group!=pid || leader.session!=pid ||
     (record && leader.start!=record.start) ||
     (!record && !lib.worker_command(readfile('/proc/'+pid+'/cmdline'),action,token))))return false;
  // An orphan group without a previously authenticated leader must not be signalled.
  if(!record && !leader && length(members()))return false;
  if(!record && leader){record={pid,start:leader.start};write(stopping,sprintf('%J',record));}
  if(leader)run(['kill','-TERM','-'+pid]);
  for(let i=0;i<=50;i++) {
   let current=process(pid);
   if(current && record && current.start!=record.start)return false;
   if(!length(members())) {
    if(trim(readfile(file)||'')==pid)unlink(file);
    unlink(stopping);
    if(readfile('/tmp/cm2012-wifi/apply.lock/proxy-owner')==token)remove_tree('/tmp/cm2012-wifi/apply.lock');
    return true;
   }
   if(i==20)run(['kill','-KILL','-'+pid]);
   if(i<50)run(['sleep','0.1']);
  }
  return false;
 },
 version:function(){return 'v1.19.32';}};
return factory.create(io,lib);
