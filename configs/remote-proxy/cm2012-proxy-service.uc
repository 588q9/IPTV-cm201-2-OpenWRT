'use strict';
// OS side effects are supplied by the native adapter; this state machine also runs in CI.
function create(io,lib) {
 const root='/etc/cm2012-proxy', journal='/etc/cm2012-proxy-transaction', state='/tmp/cm2012-proxy', lock='/tmp/cm2012-wifi/apply.lock', updating=state+'/update', undo=root+'/update-undo';
 function data(path,fallback) { try {return json(io.read(path) || 'null') || fallback;} catch(e) {return fallback;} }
 function setstate(value,error) {io.write(state+'/status',sprintf('%J',{state:value,error:error || ''}));}
 function stage(value) {io.write(state+'/stage',value);}
 function failure(error,step) {
  let message=type(error)=='string'?error:error?.message||'';
  if(index(message,'Subscription TLS failed')>=0)return step=='providers'?'订阅集合 HTTPS/TLS 握手失败，尚未下载到完整规则；请检查规则源和当前直连出口。':'订阅 HTTPS/TLS 握手失败，尚未下载到配置；请检查订阅服务和当前直连出口。';
  if(index(message,'Subscription certificate failed')>=0)return step=='providers'?'订阅集合 HTTPS 证书校验失败，请检查设备时间和规则源证书。':'订阅 HTTPS 证书校验失败，请检查设备时间和服务证书。';
  if(index(message,'Subscription DNS failed')>=0)return step=='providers'?'订阅集合域名解析失败，请检查当前上联 DNS。':'订阅域名解析失败，请检查当前上联 DNS。';
  if(index(message,'Subscription HTTP failed')>=0)return step=='providers'?'订阅集合服务器拒绝请求，请检查规则地址及服务访问限制。':'订阅服务器拒绝请求，请检查订阅是否有效及服务访问限制。';
  if(index(message,'Subscription timed out')>=0)return step=='providers'?'订阅集合下载超时，请检查当前出口能否直连规则源。':'订阅下载超时，请检查当前出口能否直连订阅服务。';
  if(index(message,'Rule provider limit')>=0)return '订阅规则集合超过上限，最多支持 64 个规则集合；未应用新配置。';
  if(index(message,'Proxy provider limit')>=0)return '订阅节点集合超过上限，最多支持 32 个节点集合；未应用新配置。';
  if(index(message,'Provider payload size limit')>=0)return '订阅集合总大小超过 16 MiB 上限，未应用新配置。';
  if(index(message,'HTTP provider required')>=0 || index(message,'HTTPS required')>=0)return '订阅集合仅支持 HTTP 类型和 HTTPS 下载地址，请检查集合配置。';
  if(index(message,'Invalid provider')>=0)return '订阅中的节点或规则集合格式无效，请检查集合配置。';
  if(index(message,'Rule provider format unsupported')>=0)return '规则集合仅支持 YAML 或文本格式，当前不支持此集合格式。';
  if(index(message,'Subscription rule text invalid')>=0)return '订阅规则文本格式无效，未应用新配置。';
  if(index(message,'GitHub rule API rate limited')>=0)return 'GitHub 官方规则接口拒绝请求或触发频率限制，请稍后重试；未应用新配置。';
  if(index(message,'Geodata rules require locked assets')>=0)return '订阅所需地理数据库未就绪；目前支持经校验的 GEOIP 国家库，GEOSITE 和 IP-ASN 暂不支持。';
  if(index(message,'Subscription YAML invalid')>=0 || index(message,'Invalid subscription')>=0)return '订阅格式无效，需要 Clash/Mihomo YAML 配置。';
  let messages={download:'订阅下载失败，请检查当前出口、订阅有效期及 HTTPS 地址。',providers:'订阅中的节点或规则集合下载失败。',compile:'订阅节点、策略组或规则不受支持。',check:'Mihomo 配置检查失败，未启用分流。',start:'Mihomo、TUN、API 或 DNS 未就绪，已恢复原配置。',routes:'分流规则应用失败，已恢复原配置。'};
  return messages[step] || '代理应用失败，已恢复原配置；订阅地址仍保留。';
 }
 // One process may nest recovery helpers; other processes always try a real file lock.
 // ucode binds local functions at declaration; recovery closures refer forward.
 let decision_depth=0,start_checked,suspend,rollback_body;
 function decided(fn) {
  if(decision_depth)return fn();
  if(!io.decision_lock())return {error:'代理事务正在处理，请稍后重试。'};
  decision_depth=1;let result;
  try {result=fn();}catch(error){decision_depth=0;io.decision_unlock();die(error?.message||'Decision failed');}
  decision_depth=0;io.decision_unlock();return result;
 }
 function mutation(fn) {let result=decided(fn);if(result?.error)die(result.error);return result;}
 function serialized(fn) {return function(a){return decided(function(){return fn(a);});};}
 function busy() {return io.exists('/tmp/cm2012-wifi/pending') || io.exists('/etc/cm2012-transaction');}
 function acquire(owner) {io.mkdir('/tmp/cm2012-wifi');if(!io.mkdir(lock))return false;if(owner)io.write(lock+'/proxy-owner',owner);return true;}
 function release(owner) {if(!owner || io.read(lock+'/proxy-owner')==owner)io.remove_tree(lock);}
 function cmd(a) {if(!io.run(a)) die('Local operation failed');}
 function alive(token) {return io.read(journal+'/token')==token && !io.exists(journal+'/rolling-back') && io.now()<int(io.read(journal+'/deadline') || '0');}
 function update_owned(token) {return !!token && io.read(updating+'/token')==token && io.read(updating+'/revision')==(io.config().revision||'0');}
 function update_alive(token) {return update_owned(token) && !busy() && !io.exists(journal) && io.now()<int(io.read(updating+'/deadline')||'0');}
 function discard_update_undo(token) {if(io.read(undo+'/token')==token){io.remove_tree(undo);io.sync();}}
 function recover_update(token,restart) {
  if(!io.exists(undo) || (token && io.read(undo+'/token')!=token))return {};
  let owner=io.read(undo+'/token'), revision=io.read(undo+'/revision');
  // Live tokens disappear on cancel/reboot: durable undo is the recovery authority.
  if(revision!=(io.config().revision||'0')) {discard_update_undo(owner);return {superseded:true};}
  function owns() {if(io.read(undo+'/token')!=owner || revision!=(io.config().revision||'0'))die('Recovery superseded');}
  if(io.exists(undo+'/published')) {
   if(!io.exists(undo+'/files-restored')) {
    let files=[root+'/active.json',root+'/subscription.json',root+'/environment.json'];
    for(let i=0;i<length(files);i++) {
     owns();if(io.exists(undo+'/absent'+i))io.remove(files[i]);
     else if(!io.copy(undo+'/before'+i,files[i]))die('Update recovery failed');
    }
    io.sync();io.write(undo+'/files-restored','1');io.sync();
   }
   if(io.config().enabled=='1') {
    io.write(undo+'/runtime-pending','1');io.sync();
    if(restart!=true || busy()) {
     if(restart==true) {let stopped=suspend();if(stopped.error)die('Deferred suspension failed');}
     setstate('rolling_back','旧配置文件已恢复，等待网络就绪后恢复服务。');return {deferred:true};
    }
    start_checked(null,null,owns);owns();
   }
  }
  discard_update_undo(owner);return {recovered:true};
 }
 function cancel_update(restart) {
  let token=io.read(updating+'/token')||io.read(updating+'/cancelled-token');if(!token)return {};
  // Invalidate before stopping; no delayed spawn can become a writer afterwards.
  io.write(updating+'/cancelled-token',token);io.remove(updating+'/token');
  if(io.stop_worker('update',token)!==true)die('Update worker still running');
  release(token);
  let result=recover_update(token,restart);
  io.remove_tree(updating);return result;
 }
 function backup() {
  let files=['/etc/config/cm2012_proxy',root+'/active.json',root+'/subscription.json',root+'/environment.json'];
  for(let i=0;i<length(files);i++) {
   if(io.exists(files[i])) {if(!io.copy(files[i],journal+'/before'+i)) die('Backup failed');}
   else io.write(journal+'/absent'+i,'1');
  }
 }
 function save_subscription(a) {
  if(!lib.https(a.subscription_url))return {error:'请输入有效的 HTTPS 订阅地址。'};
  if(a.expected_revision!=(io.config().revision||'0'))return {error:'配置版本已变化，请刷新。'};
  if(!acquire())return {error:'配置事务正忙。'};
  try {
   let c=io.config();
   if(a.expected_revision!=(c.revision||'0') || busy() || io.exists(journal)) {release();return {error:'配置版本已变化或存在待确认事务，请刷新。'};}
   if(io.exists(updating) || io.exists(undo)) {release();return {error:'订阅正在更新或恢复，请完成后再保存地址。'};}
   c.subscription_url=a.subscription_url;c.revision=''+(int(c.revision||'0')+1);io.save(c);io.sync();release();
   stage('saved');return {saved:true,revision:c.revision};
  }catch(e){release();return {error:'订阅地址保存失败，请重试。'};}
 }
 function prepare(a) {
  if(!io.ensure_guard())return {error:'健康守护未运行，无法安全应用代理。'};
  let checked=lib.request(a,io.config().revision||'0');if(checked.error)return checked;
  let cancelled=cancel_update(true);if(cancelled.deferred || io.exists(undo))return {error:'上次更新等待恢复。'};
  if(!acquire()) return {error:'配置事务正忙。'};
  let prepared=false;
  try {
   let c=io.config(), checked=lib.request(a,c.revision || '0');
   if(checked.error) {release();return checked;}
   if(busy() || io.exists(journal)) {release();return {error:'已有网络或代理设置等待确认。'};}
   // Saving the source is independent of the reversible traffic activation.
   if(checked.subscription_url) {c.subscription_url=checked.subscription_url;io.save(c);io.sync();}
   if(checked.enabled=='1' && !lib.https(c.subscription_url)) {release();return {error:'请先保存有效的 HTTPS 订阅地址。'};}
   if(!io.mkdir(journal)) die('Journal unavailable');
   backup();let token=io.uuid();if(!match(token || '',/^[a-f0-9-]{36}$/)) die('Token unavailable');
   io.write(journal+'/token',token);io.write(journal+'/deadline',''+(io.now()+300));
   io.write(journal+'/request',sprintf('%J',checked));io.sync();io.write(journal+'/prepared','1');io.sync();prepared=true;
   io.remove(state+'/apply-error');io.write(state+'/failures','0');stage('queued');setstate('checking');
   release();return {token,timeout:90};
  } catch(e) {release();if(!prepared)io.remove_tree(journal);return {error:'无法保存代理事务，未应用更改。'};}
 }
 function withdraw(reload) {
  let manifest=data(root+'/routes.json',[]);
  // Exact inverse entries only: no table flush or priority-only deletions.
  for(let i=length(manifest)-1;i>=0;i--) {let a=manifest[i];a[3]='del';io.run(a);}
  io.remove(root+'/routes.json');io.firewall({});if(reload!=false)cmd(['/sbin/fw3','reload']);io.remove(state+'/routing');
 }
 function install() {
  if(busy()) die('Network transaction pending');
  let env=io.env(), plan=lib.policy(env,io.capture(['ip','-4','rule','show']),io.capture(['ip','-4','route','show','table','2022']));
  io.firewall(lib.firewall(env));cmd(['/sbin/fw3','reload']);
  // Persist intentions before mutation so an abrupt reboot is recoverable.
  io.write(root+'/routes.json',sprintf('%J',plan));io.sync();
  for(let i=0;i<length(plan);i++)cmd(plan[i]);
  io.write(state+'/routing',sprintf('%J',{lan_device:env.lan_device,lan_ip:env.lan_ip}));
 }
 function download(url,work,format,purpose) {if(!lib.https(url))die('HTTPS required');return io.fetch(url,work,format||'yaml',purpose);}
 function candidate(check,work) {
  check();
  stage('download');let c=io.config(), env=io.env(), raw=download(c.subscription_url,work), payloads={},environment=sprintf('%J',env);
  if(type(raw)!='object')die('Invalid subscription');env.secret=io.secret();
  check();
  stage('providers');
  function providers(key) {
   let value=raw[key];if(value==null)return {};if(type(value)!='object')die('Invalid provider');return value;
  }
  let proxies=providers('proxy-providers'), rules=providers('rule-providers');
  if(length(keys(proxies))>32)die('Proxy provider limit');
  if(length(keys(rules))>64)die('Rule provider limit');
  // Preflight both maps before downloading dependencies; malformed input must
  // not become an incidental property-access error or a misleading TLS error.
  for(let group in [proxies,rules])for(let name in keys(group)) {
   let provider=group[name];if(type(provider)!='object')die('Invalid provider');
   if(provider.type!='http')die('HTTP provider required');if(!lib.https(provider.url))die('HTTPS required');
  }
  for(let name in keys(rules))if(rules[name].format && index(['yaml','text'],rules[name].format)<0)die('Rule provider format unsupported');
  let payload_bytes=0;
  function collect(group,prefix) {
   for(let name in keys(group)) {
    check();let item=group[name],data=download(item.url,work,prefix?(item.format||'yaml'):'yaml',prefix?'rule':'proxy');check();
    let size=length(sprintf('%J',data));
    if(size>16777216-payload_bytes)die('Provider payload size limit');
    payload_bytes+=size;payloads[prefix+name]=data;
   }
  }
  collect(proxies,'');collect(rules,'rule:');
  stage('compile');let compiled=lib.compile(raw,env,payloads);
  check();
  io.write(work+'/candidate.json',sprintf('%J',compiled));
  stage('check');if(!io.test(work+'/candidate.json'))die('Candidate configuration rejected');
  check();
  let saved={};for(let key in ['proxies','proxy-providers','proxy-groups','rules','rule-providers'])if(raw[key]!=null)saved[key]=raw[key];
  return {compiled,saved,environment};
 }
 function publish(value) {
  if(io.exists(root+'/active.json') && !io.copy(root+'/active.json',root+'/previous.json'))die('Previous configuration unavailable');
  io.write(root+'/active.json',sprintf('%J',value.compiled));
  io.write(root+'/subscription.json',sprintf('%J',value.saved));io.write(root+'/environment.json',value.environment);io.sync();
 }
 function compile_current(token) {
  function check() {if(token && !alive(token))die('Transaction expired');}
  let value=candidate(check,root);mutation(function(){check();publish(value);io.remove(root+'/candidate.json');});
 }
 start_checked=function(token,update_token,recovery_check) {
  function check() {if(token && !alive(token))die('Transaction expired');if(update_token && !update_alive(update_token))die('Update cancelled');if(recovery_check)recovery_check();}
  mutation(function(){check();stage('start');io.remove(state+'/external-health');io.remove(state+'/local-ready');withdraw();cmd(['/etc/init.d/cm2012-mihomo','restart']);});
  if(!io.health(true))die('Core is not ready');
  mutation(function(){check();stage('routes');install();io.write(state+'/failures','0');setstate('active');});
 };
 function rollback_internal(restart,cancel) {return decided(function(){return rollback_body(restart,cancel);});}
 rollback_body=function(restart,cancel) {
  if(!io.exists(journal+'/prepared'))return {error:'没有可恢复的完整事务。'};
  if(io.exists(journal+'/confirmed'))return {error:'事务已确认。'};
  let owner=io.read(journal+'/token');
  function owns() {if(io.read(journal+'/token')!=owner || !io.exists(journal+'/rolling-back'))die('Recovery superseded');}
  io.write(journal+'/rolling-back','1');io.remove(journal+'/ready');io.sync();setstate('rolling_back');
  try {
   if(cancel && io.stop_worker('transaction',owner)!==true)die('Transaction worker still running');
   if(restart!=false) {withdraw();cmd(['/etc/init.d/cm2012-mihomo','stop']);}
   if(!io.exists(journal+'/files-restored')) {
    let files=['/etc/config/cm2012_proxy',root+'/active.json',root+'/subscription.json',root+'/environment.json'];
    for(let i=0;i<length(files);i++) {
     owns();if(io.exists(journal+'/absent'+i))io.remove(files[i]);
     else if(!io.copy(journal+'/before'+i,files[i]))die('Recovery failed');
    }
    io.restore_config();io.sync();io.write(journal+'/files-restored','1');io.sync();
   }
   if(restart==false)withdraw(false);
   if(io.config().enabled=='1') {
    io.write(journal+'/runtime-pending','1');io.sync();
    // START=17 precedes netifd: boot must never wait for LAN or Mihomo here.
    if(restart==false || busy())return {rollback:true,deferred:true};
    start_checked(null,null,owns);owns();
   } else setstate('disabled');
   io.remove_tree(journal);io.sync();stage('idle');io.write(state+'/failures','0');return {rollback:true};
  }catch(e){setstate('failed','恢复未完成，记录已保留，守卫将重试。');return {error:'恢复未完成，记录已保留，守卫将重试。'};}
 };
 function apply(a) {
  let result=prepare(a);if(result.error)return result;
  if(!io.spawn('transaction',result.token)) {rollback_internal();return {error:'无法启动代理事务。'};}
  return result;
 }
 function transaction(expected_token) {
  let token=io.read(journal+'/token'), a=data(journal+'/request',{});
  if((expected_token && expected_token!=token) || !alive(token) || !io.exists(journal+'/prepared'))return {error:'事务已过期。'};
  try {
   setstate('checking');let c=io.config();c.enabled=a.enabled;c.revision=''+(int(c.revision || '0')+1);
   if(a.subscription_url)c.subscription_url=a.subscription_url;
   mutation(function(){if(!alive(token))die('Transaction expired');io.save(c);});
   if(c.enabled=='1') {compile_current(token);start_checked(token);} else {withdraw();cmd(['/etc/init.d/cm2012-mihomo','stop']);setstate('disabled');}
   return mutation(function(){if(!alive(token))die('Transaction expired');io.write(journal+'/deadline',''+(io.now()+90));io.write(journal+'/ready','1');stage('confirm');return {};});
  }catch(e){
   let message=failure(e,io.read(state+'/stage'));
   if(io.read(journal+'/token')==token) {rollback_internal();io.write(state+'/apply-error',message);stage('idle');}
   return {error:message};
  }
 }
 function confirm(a) {
  if(!a.token || a.token!=io.read(journal+'/token') || !alive(a.token) || !io.exists(journal+'/ready'))return {error:'令牌无效、服务未就绪或事务已过期。'};
  if(io.config().enabled=='1' && !io.health(false))return {error:'服务未就绪。'};
  if(!alive(a.token))return {error:'事务已进入恢复。'};
  io.write(journal+'/confirmed','1');io.sync();io.remove_tree(journal);stage('idle');return {confirmed:true};
 }
 function rollback(a) {
  if(!a.token || a.token!=io.read(journal+'/token'))return {error:'事务令牌无效。'};
  return rollback_internal(null,true);
 }
 function recover() {
  cancel_update(false);recover_update(null,false);
  if(io.exists(journal)) {
   if(io.exists(journal+'/prepared') && !io.exists(journal+'/confirmed'))return rollback_internal(false,true);
   io.remove_tree(journal);
  }
  // A tmpfs manifest is never assumed; remove persistent exact intentions first.
  try {withdraw(false);return {};}catch(e){return {error:'代理规则恢复失败。'};}
 }
 suspend=function() {try {withdraw();setstate(io.config().enabled=='1'?'degraded':'disabled');return {};}catch(e){return {error:'撤销代理接管失败。'};}};
 function reconcile() {
  if(busy() || io.exists(journal))return suspend();
  if(io.config().enabled!='1')return suspend();
  return update_subscription({expected_revision:io.config().revision||'0',reconcile:true});
 }
 function disable(a) {
  let before=io.config();if(a.expected_revision!=null && a.expected_revision!=(before.revision||'0'))return {error:'配置版本已变化。'};
  cancel_update(false);
  if(!acquire())return {error:'配置事务正忙。'};
  try {
   let c=io.config();if(a.expected_revision!=null && a.expected_revision!=(c.revision||'0'))die('Stale revision');
   if(io.exists(journal)) {
    if(rollback_internal(false,true).error)die('Rollback failed');c=io.config();
   }
   c.enabled='0';c.revision=''+(int(c.revision||'0')+1);io.save(c);io.sync();release();suspend();cmd(['/etc/init.d/cm2012-mihomo','stop']);
   if(io.exists(journal+'/files-restored'))io.remove_tree(journal);recover_update(null,false);stage('idle');return {disabled:true};
  }
  catch(e){release();return {error:'停用失败，请刷新后重试。'};}
 }
 function update_subscription(a) {
  if(!io.ensure_guard())return {error:'健康守护未运行，无法安全更新。'};
  if(!acquire())return {error:'配置事务正忙。'};
  if(busy() || io.exists(journal)) {release();return {error:'存在待确认事务。'};}
  if(a.expected_revision!=(io.config().revision||'0')) {release();return {error:'配置版本已变化。'};}
  if(io.exists(undo)) {release();return {error:'上次订阅更新等待恢复。'};}
  if(io.exists(updating)) {let token=io.read(updating+'/token');release();return {updating:true,token:token||''};}
  let token=io.uuid();
  try {
   if(!match(token||'',/^[a-f0-9-]{36}$/) || !io.mkdir(updating))die('Update unavailable');
   io.write(updating+'/revision',io.config().revision||'0');io.write(updating+'/deadline',''+(io.now()+300));
   io.write(updating+'/mode',a.reconcile?'reconcile':'subscription');io.write(updating+'/token',token);io.write(state+'/last-update-attempt',''+io.now());
   release();
   if(!io.spawn('update',token)) {cancel_update();return {error:'无法启动订阅更新。'};}
   return {updating:true,token};
  }catch(e){release();if(io.read(updating+'/token')==token)io.remove_tree(updating);return {error:'无法准备订阅更新。'};}
 }
 function update(token) {
  if(!update_alive(token))return {error:'订阅更新已取消。'};
  let previous=io.read(root+'/active.json'), subscription=io.read(root+'/subscription.json'), environment=io.read(root+'/environment.json'), published=false,locked=false;
  function check() {if(!update_alive(token))die('Update cancelled');}
  try {
   let mode=io.read(updating+'/mode'), active=data(root+'/active.json',{}), env=io.env();
   if(mode=='reconcile' && active['external-controller-tls']==env.lan_ip+':9091' && environment==sprintf('%J',env)) {
    // Route restoration never needs a remote provider download.
    check();
    // A core started before LAN readiness may have failed to bind its listeners.
    if(!io.health(false)) {check();cmd(['/etc/init.d/cm2012-mihomo','restart']);}
    if(!io.health(true))die('Core unavailable');check();withdraw();install();setstate('active');
   } else {
    let value=candidate(check,updating);check();
    mutation(function(){check();if(!io.mkdir(undo))die('Undo record unavailable');
    io.write(undo+'/token',token);io.write(undo+'/revision',io.read(updating+'/revision'));
    let before=[previous,subscription,environment];
    for(let i=0;i<length(before);i++) {if(before[i]!=null)io.write(undo+'/before'+i,before[i]);else io.write(undo+'/absent'+i,'1');}
    // Persist undo data and publication intent before any active file changes.
    // Sync runs outside the network writer lock as well as all remote I/O.
    io.write(undo+'/published','1');io.sync();check();
    // Only publication owns the shared short lock; download/test/health never do.
    if(!acquire(token))die('Configuration busy');locked=true;check();
    if(value.environment!=sprintf('%J',io.env()))die('LAN changed');
    published=true;publish(value);release(token);locked=false;});
    if(io.config().enabled=='1')start_checked(null,token);
    check();io.write(root+'/last-update',''+io.now());
   }
   return mutation(function(){check();discard_update_undo(token);io.remove_tree(updating);io.remove(state+'/update-error');stage('idle');return {updated:true};});
  }catch(e){
   if(locked)release(token);
   return decided(function(){
    if(io.read(updating+'/token')!=token)return {error:'订阅更新已取消。'};
    let message=failure(e,io.read(state+'/stage'));
    if(published && update_owned(token)) {
     // A deadline forbids publication, not recovery. Do not pass it to old-core startup.
     io.write(updating+'/cancelled-token',token);io.remove(updating+'/token');
     try {
      let recovery=recover_update(token,true);
      if(recovery.deferred) {
       let reason='旧配置文件已恢复，等待网络就绪后恢复服务。';io.remove_tree(updating);io.write(state+'/update-error',reason);return {error:reason};
      }
     }
     catch(error){let reason='恢复未完成，备份已保留，守卫将重试。';io.write(state+'/update-error',reason);setstate('failed',reason);return {error:reason};}
    } else if(io.read(undo+'/token')==token)discard_update_undo(token);
    io.remove_tree(updating);io.write(state+'/update-error',message+' 现有配置已保留。');stage('idle');
    return {error:message};
   });
  }
 }
 function external_check() {
  let c=io.config(),now=io.now(),record=data(state+'/external-health',{});
  if(record.revision!=(c.revision||'0') || int(record.checked||'0')>now)record={};
  if(type(record.checked)=='int' && now-record.checked<60)return;
  function probe() {try {return io.external_health()===true;}catch(error){return false;}}
  let healthy=probe(),failures=healthy?0:int(record.failures||'0')+1;
  if(failures>2)failures=2;
  record.revision=c.revision||'0';record.checked=now;record.state=healthy?'available':'unavailable';record.failures=failures;
  if(failures>=2 && (type(record.attempted)!='int' || now-record.attempted>=300)) {
   // Persist the attempt before I/O: a killed probe cannot defeat the cooldown.
   record.attempted=now;record.error='';io.write(state+'/external-health',sprintf('%J',record));
   let flushed=false;try {flushed=io.flush_dns()===true;}catch(error){}
   if(flushed) {
    let count=int(record.recoveries||'0');record.recoveries=count<1000000?count+1:1000000;
    healthy=probe();record.state=healthy?'available':'unavailable';record.failures=healthy?0:2;
    record.error=healthy?'':'still_unavailable';
   } else record.error='cache_flush_failed';
  }
  if(healthy)record.error='';
  record.checked=io.now();io.write(state+'/external-health',sprintf('%J',record));
 }
 function guard() {
  if(io.exists(journal+'/rolling-back'))return rollback_internal(true,true);
  if(io.exists(updating+'/cancelled-token')) {try {cancel_update(true);}catch(error){setstate('failed','更新恢复未完成，记录已保留。');}return;}
  if(io.exists(undo) && !io.exists(updating)) {try {let result=recover_update(null,true);if(!result.deferred)io.remove(state+'/update-error');}catch(error){setstate('failed','更新恢复未完成，记录已保留。');}return;}
  if(io.exists(journal+'/prepared') && io.now()>=int(io.read(journal+'/deadline')||'0')) {
   let ready=io.exists(journal+'/ready');
   let result=rollback_internal(null,true);
   if(!result.error)io.write(state+'/apply-error',ready?'90 秒内未确认，已恢复上一配置；订阅地址仍保留。':'代理准备超过 5 分钟，已恢复上一配置；订阅地址仍保留。');
   return;
  }
  if(io.exists(updating) && io.now()>=int(io.read(updating+'/deadline')||'0')) {try {cancel_update(true);io.write(state+'/update-error','订阅更新超时，正在保留或恢复上一配置。');}catch(error){setstate('failed','更新恢复未完成，记录已保留。');}return;}
  if(busy()) {cancel_update(false);suspend();return;}
  if(io.config().enabled!='1'){io.remove(state+'/local-ready');return;}
  if(io.exists(journal) && !io.exists(journal+'/ready')) {
   // The new core is not expected before download/validation completes.
   // Continue protecting an already active old core while it is still routed.
   if(io.exists(state+'/routing')) {
    let failures=lib.guard(int(io.read(state+'/failures')||'0'),io.health(false));io.write(state+'/failures',''+failures);
    if(failures>=3){suspend();setstate('checking','上一核心异常，准备新配置期间暂时恢复直连。');}
   } else io.write(state+'/failures','0');
   return;
  }
  let n=lib.guard(int(io.read(state+'/failures')||'0'),io.health(false));io.write(state+'/failures',''+n);
  io.write(state+'/local-ready',n==0?'1':'0');
  if(n>=3){cancel_update(false);suspend();setstate('degraded','核心、TUN、API 或 DNS 异常，已恢复直连。');return;}
  if(n==0 && !io.exists(state+'/routing') && !io.exists(journal)) {reconcile();return;}
  if(n==0 && io.exists(state+'/routing') && !io.exists(journal) && !io.exists(updating) && !io.exists(undo))external_check();
  let last=int(io.read(root+'/last-update')||'0');if(last>io.now())last=0;
  if(!io.exists(journal) && !io.exists(updating) && io.now()-last>=86400 && io.now()-int(io.read(state+'/last-update-attempt')||'-900')>=900)update_subscription({expected_revision:io.config().revision||'0'});
 }
 function status() {
  let s=data(state+'/status',{state:'disabled'}), c=io.config(), route=data(state+'/routing',{}), active=data(root+'/active.json',{});
  let ready=io.exists(journal+'/ready'), remaining=ready?int(io.read(journal+'/deadline')||'0')-io.now():0;
  let external=data(state+'/external-health',{}),core_ready=c.enabled=='1' && io.read(state+'/local-ready')=='1' && io.exists(state+'/routing');
  let fresh=core_ready && !busy() && !io.exists(journal) && !io.exists(updating) && !io.exists(undo) && external.revision==(c.revision||'0') && type(external.checked)=='int' && external.checked<=io.now() && io.now()-external.checked<=180;
  let external_state=fresh && (external.state=='available' || external.state=='unavailable')?external.state:'unknown';
  return {state:s.state,error:s.error || '',revision:c.revision||'0',enabled:c.enabled=='1',version:io.version(),lan_device:route.lan_device||'',lan_ip:route.lan_ip||'',
   core_ready,external_state,external_checked_at:fresh?external.checked:0,dns_recoveries:fresh?int(external.recoveries||'0'):0,
   dns_recovery_error:fresh && (external.error=='cache_flush_failed' || external.error=='still_unavailable')?external.error:'',
   subscription_saved:lib.https(c.subscription_url||'')?true:false,pending_ready:ready,remaining:remaining>0?remaining:0,stage:io.read(state+'/stage')||'idle',apply_error:io.read(state+'/apply-error')||'',
   routing_ready:io.exists(state+'/routing'),tun_ready:io.exists('/sys/class/net/mihomo0'),pending:io.exists(journal),pending_token:io.read(journal+'/token')||'',updating:io.exists(updating),update_error:io.read(state+'/update-error')||'',
   timeout:90,dashboard:active['external-controller-tls']?'https://'+active['external-controller-tls']+'/ui/':'',ipv6_covered:false,failure_policy:'restore_direct'};
 }
 return {save_subscription:serialized(save_subscription),apply:serialized(apply),transaction,confirm:serialized(confirm),rollback:serialized(rollback),disable:serialized(disable),
  update_subscription:serialized(update_subscription),update,status,guard:serialized(guard),recover:serialized(recover),suspend:serialized(suspend),reconcile:serialized(reconcile)};
}
return {create};
