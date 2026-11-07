'use strict';
// This file is deliberately independent of UCI, RPC and shell execution.
function member(a,v) { return index(a,v) >= 0; }
function array(a) { return type(a) == 'array' ? a : []; }
function object(a) { return type(a) == 'object' ? a : {}; }
function text(v) { return type(v) == 'string' && length(v) && length(v) < 4096 && !match(v, /[[:cntrl:]]/); }
function rule_text(source) {
 if(type(source)!='string' || length(source)>4194304)die('Subscription rule text invalid');
 // The literal leading character below is a UTF-8 BOM, not rule content.
 let lines=split(replace(source,/^﻿/,''),'\n'),payload=[];
 for(let line in lines) {
  let rule=trim(line);if(!length(rule) || match(rule,/^#/))continue;
  if(!text(rule) || length(payload)>=65536)die('Subscription rule text invalid');
  push(payload,rule);
 }
 if(!length(payload))die('Subscription rule text invalid');return {payload};
}
function https(v) { return text(v) && match(v,/^https:\/\/[^\/@?# ]+([\/?#].*)?$/) && !match(v,/["\\]/); }
function github_rule_api(url) {
 if(!text(url))return null;
 let pieces=match(url,/^https:\/\/raw\.githubusercontent\.com\/([A-Za-z0-9_.-]{1,128})\/([A-Za-z0-9_.-]{1,128})\/([A-Za-z0-9_.-]{1,128})\/([A-Za-z0-9_.%\/-]+)$/);
 if(!pieces)return null;
 for(let i=1;i<=3;i++)if(pieces[i]=='.' || pieces[i]=='..')return null;
 let ref=pieces[3],path=pieces[4];
 if(ref=='refs') {
  let explicit=match(path,/^(heads|tags)\/([A-Za-z0-9_.-]{1,128})\/([A-Za-z0-9_.%\/-]+)$/);
  if(!explicit || explicit[2]=='.' || explicit[2]=='..')return null;
  ref='refs%2F'+explicit[1]+'%2F'+explicit[2];path=explicit[3];
 }
 for(let segment in split(path,'/')) {
  if(!match(segment,/^([A-Za-z0-9_.-]|%[A-Fa-f0-9]{2})+$/) ||
     length(replace(segment,/%[A-Fa-f0-9]{2}/g,'x'))>255 ||
     match(segment,/^(\.|%2e){1,2}$/i) ||
     match(segment,/%(0[0-9a-f]|1[0-9a-f]|7f|2f|5c|3f|23|25)/i))return null;
 }
 return 'https://api.github.com/repos/'+pieces[1]+'/'+pieces[2]+'/contents/'+path+'?ref='+ref;
}
function ipv4(v) {
 if (type(v) != 'string' || !match(v,/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/)) return false;
 let p = split(v,'.'); for (let i=0;i<4;i++) if (int(p[i]) > 255) return false; return true;
}
function cidr(v) {
 if (type(v) != 'string') return false;
 let p=split(v,'/'); return length(p)==2 && ipv4(p[0]) && match(p[1],/^([0-9]|[12][0-9]|3[0-2])$/);
}
function request(a,revision) {
 if (a.expected_revision != revision) return {error:'配置版本已变化，请刷新。'};
 if (!member(['0','1'],a.enabled) || (a.subscription_url && !https(a.subscription_url)))
  return {error:'需要有效的 HTTPS 订阅和启停参数。'};
 return {enabled:a.enabled,subscription_url:a.subscription_url || null};
}
function safe(value,depth,parent) {
 if (depth > 12) die('Subscription nesting limit');
 if (type(value)=='array') { if(length(value)>4096) die('Subscription size limit'); for(let i=0;i<length(value);i++) safe(value[i],depth+1,parent); }
 else if(type(value)=='object') {
  let names=keys(value); if(length(names)>128) die('Subscription object size limit');
  for(let i=0;i<length(names);i++) {
   let k=names[i];
   if(match(k,/^(script|exec|command|plugin|plugin-opts|client-key|client-certificate|certificate|private-key-path|ca|ca-str|interface-name|routing-mark|ip-version|dialer-proxy|smux|remote-dns-resolve)$/) ||
      (k=='path' && !member(['ws-opts','http-opts','h2-opts','grpc-opts'],parent))) die('Unsafe subscription option');
   safe(value[k],depth+1,k);
  }
 } else if(type(value)=='string' && (length(value)>16384 || match(value,/[[:cntrl:]]/))) die('Invalid subscription value');
}
function proxy(p) {
 let protocols=['ss','ssr','vmess','vless','trojan','socks5','http','snell','hysteria','hysteria2','tuic','wireguard'];
 if(type(p)!='object' || !text(p.name) || !member(protocols,p.type) || !text(p.server) ||
    int(p.port)<1 || int(p.port)>65535) die('Invalid proxy');
 safe(p,0); return p;
}
function exclusions(env) {
 let values=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4'];
 let extra=[env.lan_cidr]; for(let i=0;i<length(array(env.management));i++) push(extra,env.management[i]);
 for(let i=0;i<length(extra);i++) { if(!cidr(extra[i])) die('Invalid management prefix'); if(!member(values,extra[i])) push(values,extra[i]); }
 if(length(values)>30) die('Too many exclusions'); return values;
}
function environment(env) {
 if(!ipv4(env.lan_ip) || !cidr(env.lan_cidr) || !text(env.lan_device) || !match(env.lan_device,/^[a-zA-Z0-9_.:-]{1,15}$/)) die('LAN unavailable');
 let bootstrap=[];
 for(let i=0;i<length(array(env.bootstrap));i++) {
  let v=env.bootstrap[i]; if(ipv4(v) && v!=env.lan_ip && !member(array(env.self_ipv4),v) && !match(v,/^(0\.|127\.|169\.254\.)/) && int(split(v,'.')[0])<224 && !member(bootstrap,v)) push(bootstrap,v);
 }
 if(!length(bootstrap)) die('No independent uplink DNS');
 return bootstrap;
}
function domain(v) {return text(v) && length(v)<=253 && !ipv4(v) && !!match(v,/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i);}
function covers(pattern,host) {
 let p=split(lc(pattern),'.'), h=split(lc(host),'.'), offset=(p[0]=='+' || p[0]=='*')?1:0;
 if(length(h)<length(p)-offset)return false;
 for(let i=length(p)-1,j=length(h)-1;i>=offset;i--,j--)if(p[i]!=h[j])return false;
 return true;
}
function dns_upstream(value,env) {
 if(!text(value))return false;
 let host=value;
 if(!ipv4(value)) {
  if(!https(value) || match(value,/#/))return false;
  let authority=split(split(value,'/')[2],':');host=authority[0];
  if(length(authority)>2 || (length(authority)==2 && (!match(authority[1],/^[0-9]{1,5}$/) || int(authority[1])<1 || int(authority[1])>65535)))return false;
  if(!ipv4(host) && !domain(host))return false;
 }
 if(ipv4(host))return host!=env.lan_ip && !member(array(env.self_ipv4),host) && !match(host,/^(0\.|127\.|169\.254\.)/) && int(split(host,'.')[0])<224;
 return !covers('lan',host) && !covers('localhost',host) && !covers('local',host);
}
function dns_policy(raw,env,ps,providers) {
 let result={},source=object(object(raw.dns)['nameserver-policy']),protected_hosts=['lan','in-addr.arpa','ip6.arpa'],names=keys(source);
 for(let i=0;i<length(ps);i++)push(protected_hosts,ps[i].server);
 for(let name in keys(providers))for(let node in providers[name].payload)push(protected_hosts,node.server);
 if(length(names)>256)die('DNS policy limit');
 for(let name in names) {
  let pieces=split(name,'.'),bare=join('.',(pieces[0]=='+' || pieces[0]=='*')?slice(pieces,1):pieces);
  if(!domain(bare))continue;
  let blocked=covers('lan',bare) || covers('in-addr.arpa',bare) || covers('ip6.arpa',bare);
  for(let host in protected_hosts)if(covers(name,host))blocked=true;
  if(blocked)continue;
  let upstreams=type(source[name])=='string'?[source[name]]:array(source[name]),usable=[];
  if(length(upstreams)>8)continue;
  for(let v in upstreams)if(dns_upstream(v,env) && !member(usable,v))push(usable,v);
  if(length(usable))result[name]=usable;
 }
 result['+.lan']=['127.0.0.1:53'];result['+.in-addr.arpa']=['127.0.0.1:53'];return result;
}
function node_nameservers(env,bootstrap) {
 let source=env.node_nameservers==null?[]:env.node_nameservers,result=[];
 if(type(source)!='array' || length(source)>4)die('Invalid node nameservers');
 for(let value in source) {
  // A literal IP and no proxy fragment keep node bootstrap independent of the tunnel.
  if(!https(value) || !dns_upstream(value,env) || !ipv4(split(split(value,'/')[2],':')[0]))die('Invalid node nameserver');
  if(!member(result,value))push(result,value);
 }
 return length(result)?result:bootstrap;
}
function node_hosts(env,ps,providers) {
 let source=env.node_hosts==null?{}:env.node_hosts,result={'cm2012-proxy-health.invalid':'198.18.0.1'},nodes=[];
 if(type(source)!='object' || length(keys(source))>2048)die('Invalid node host mappings');
 for(let p in ps)push(nodes,p);
 for(let name in keys(providers))for(let p in providers[name].payload)push(nodes,p);
 for(let p in nodes) {
  let host=p.server;if(!domain(host) || !member(keys(source),host))continue;
  let values=source[host],addresses=[];
  if(type(values)!='array' || !length(values) || length(values)>8)die('Invalid node host addresses');
  for(let value in values) {
   if(!ipv4(value))die('Invalid node host address');
   let octets=split(value,'.'),a=int(octets[0]),b=int(octets[1]);
   if(a==0 || a==10 || a==127 || a>=224 || (a==100 && b>=64 && b<=127) ||
      (a==169 && b==254) || (a==172 && b>=16 && b<=31) || (a==192 && b==168) ||
      (a==198 && (b==18 || b==19)) || value==env.lan_ip || member(array(env.self_ipv4),value))die('Invalid node host address');
   if(!member(addresses,value))push(addresses,value);
  }
  result[host]=addresses;
 }
 return result;
}
function geodata(rule,env) {
 let dependent=!!match(rule,/^ *((SRC-)?GEO[A-Z0-9_-]*|(SRC-)?IP-ASN) *,/i) ||
  (!!match(rule,/^ *(AND|OR|NOT) *,/i) && !!match(rule,/\( *((SRC-)?GEO[A-Z0-9_-]*|(SRC-)?IP-ASN) *,/i));
 if(!dependent)return false;
 if(env.geoip_ready!==true)return true;
 // A country MMDB cannot satisfy GEOSITE, ASN or other GEO families.
 for(let clause in split(rule,'('))if(match(clause,/^ *((SRC-)?GEO[A-Z0-9_-]*|(SRC-)?IP-ASN) *,/i) &&
    !match(clause,/^ *(SRC-)?GEOIP *,/i))return true;
 return false;
}
function compile(raw,env,payloads) {
 const dns_group='CM2012-DNS',default_group='CM2012-DEFAULT',legacy_group='CM2012-PROXY';
 let bootstrap=environment(env), node_dns=node_nameservers(env,bootstrap), ps=[], groups=[], source_groups=array(raw['proxy-groups']), provider_names=keys(object(raw['proxy-providers'])), names=['DIRECT','REJECT','REJECT-DROP','PASS','COMPATIBLE',dns_group,default_group,legacy_group], providers={},needs_default=false;
 if(type(raw)!='object' || length(array(raw.proxies))>2048 || length(provider_names)>32 || length(source_groups)>256) die('Invalid subscription');
 function destination(name) {
  if(name==legacy_group)name=default_group;
  if(name==default_group)needs_default=true;
  return name;
 }
 // Preserve saved input while normalizing references to the old local fallback.
 for(let source in source_groups) {
  let g={};for(let key in keys(source))g[key]=source[key];
  if(type(g.proxies)=='array') {let choices=[];for(let name in g.proxies)push(choices,destination(name));g.proxies=choices;}
  if(g['default-selected']!=null)g['default-selected']=destination(g['default-selected']);
  push(groups,g);
 }
 for(let i=0;i<length(array(raw.proxies));i++) { let p=proxy(raw.proxies[i]); if(member(names,p.name)) die('Duplicate proxy'); push(names,p.name); push(ps,p); }
 for(let i=0;i<length(provider_names);i++) {
  let name=provider_names[i], p=raw['proxy-providers'][name], data=payloads[name];
  if(!text(name) || p.type!='http' || !https(p.url) || !data || !length(array(data.proxies))) die('Invalid HTTP provider');
  let nodes=[];
  for(let j=0;j<length(data.proxies);j++) push(nodes,proxy(data.proxies[j]));
  // Materialize downloaded, validated nodes: Mihomo never fetches unfiltered proxy YAML itself.
  providers[name]={type:'inline',payload:nodes};
 }
 if(!length(ps) && !length(provider_names)) die('Empty proxy set');
 for(let i=0;i<length(groups);i++) { if(!text(groups[i].name) || member(names,groups[i].name)) die('Duplicate group'); push(names,groups[i].name); }
 let graph={};
 for(let i=0;i<length(groups);i++) {
  let g=groups[i]; safe(g,0);
  if(!member(['select','url-test','fallback','load-balance','relay'],g.type) || (!length(array(g.proxies)) && !length(array(g.use)))) die('Invalid proxy group');
  for(let j=0;j<length(array(g.proxies));j++) if(!member(names,g.proxies[j])) die('Missing proxy reference');
  for(let j=0;j<length(array(g.use));j++) if(!member(provider_names,g.use[j])) die('Missing provider reference');
  graph[g.name]=array(g.proxies);
 }
 function cycle(name,trail) {
  if(member(trail,name)) die('Cyclic proxy group');
  let next=[]; for(let i=0;i<length(trail);i++) push(next,trail[i]); push(next,name);
  for(let i=0;i<length(array(graph[name]));i++) if(graph[graph[name][i]]) cycle(graph[name][i],next);
 }
 for(let i=0;i<length(groups);i++) cycle(groups[i].name,[]);
 let nodes=[]; for(let i=0;i<length(ps);i++) push(nodes,ps[i].name);
 function local_group(name) {
  let group={name,type:'select'};
  if(name==dns_group) {
   group.type='fallback';group.url='https://1.1.1.1/cdn-cgi/trace';
   group.interval=60;group.timeout=3000;group.lazy=false;
   group['expected-status']='200';group['empty-fallback']='REJECT';
  }
  if(length(nodes))group.proxies=nodes;if(length(provider_names))group.use=provider_names;
  return group;
 }
 let clean_groups=[]; for(let i=0;i<length(groups);i++) push(clean_groups,groups[i]); push(clean_groups,local_group(dns_group));
 let rules=[], excluded=exclusions(env), rule_providers={}, rule_names=keys(object(raw['rule-providers']));
 for(let i=0;i<length(excluded);i++) push(rules,'IP-CIDR,'+excluded[i]+',DIRECT,no-resolve');
 for(let i=0;i<length(rule_names);i++) {
  let n=rule_names[i], p=raw['rule-providers'][n], data=payloads['rule:'+n];
  if(!text(n) || p.type!='http' || !https(p.url) || !member(['domain','ipcidr','classical'],p.behavior) || !data || !length(array(data.payload))) die('Invalid rule provider');
  for(let j=0;j<length(data.payload);j++) {
   if(!text(data.payload[j]) || match(data.payload[j],/^(SCRIPT|SUB-RULE),/)) die('Unsafe rule provider');
   if(p.behavior=='classical' && geodata(data.payload[j],env))die('Geodata rules require locked assets');
  }
  rule_providers[n]={type:'inline',behavior:p.behavior,payload:data.payload};
 }
 let final=false, allowed=['GEOIP','SRC-GEOIP','DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','DOMAIN-WILDCARD','DOMAIN-REGEX','IP-CIDR','IP-CIDR6','IP-SUFFIX','SRC-IP-CIDR','SRC-IP-SUFFIX','DST-PORT','SRC-PORT','IN-PORT','NETWORK','DSCP','RULE-SET','MATCH'];
 if(length(array(raw.rules))>20000) die('Rule count limit');
 for(let i=0;i<length(array(raw.rules));i++) {
  let r=raw.rules[i]; if(!text(r)) die('Invalid rule'); if(geodata(r,env))die('Geodata rules require locked assets'); let f=split(r,','), kind=f[0];
  if(!member(allowed,kind) || length(f)<2) die('Unsupported rule');
  let target_index=f[length(f)-1]=='no-resolve'?length(f)-2:length(f)-1,target=destination(f[target_index]);
  if(!member(names,target) || (kind=='RULE-SET' && !member(rule_names,f[1]))) die('Invalid rule reference');
  f[target_index]=target;
  if(kind=='MATCH') final=true; push(rules,join(',',f));
 }
 if(!final) {needs_default=true;push(rules,'MATCH,'+default_group);}
 if(needs_default)push(clean_groups,local_group(default_group));
 if(!match(env.secret || '',/^[a-f0-9]{64}$/)) die('Missing local secret');
 return {mode:'rule','geodata-mode':false,'geo-auto-update':false,'geox-url':{mmdb:'https://127.0.0.1:1/disabled-geodata'},ipv6:false,'allow-lan':false,'bind-address':'127.0.0.1',port:0,'socks-port':0,'mixed-port':0,'redir-port':0,'tproxy-port':0,
  'log-level':'silent','find-process-mode':'off','external-controller':'127.0.0.1:9090','external-controller-tls':env.lan_ip+':9091',
  'external-ui':'/www/metacubexd',secret:env.secret,tls:{certificate:'/etc/cm2012-proxy/cert.pem','private-key':'/etc/cm2012-proxy/key.pem'},
  profile:{'store-selected':true,'store-fake-ip':false},hosts:length(array(env.node_nameservers))?{'cm2012-proxy-health.invalid':'198.18.0.1'}:node_hosts(env,ps,providers),
  tun:{enable:true,stack:'gvisor',device:'mihomo0',mtu:1280,gso:false,'auto-route':false,'auto-redirect':false,'auto-detect-interface':false,'inet6-address':[]},
  dns:{enable:true,ipv6:false,listen:env.lan_ip+':1053','enhanced-mode':'redir-host','use-hosts':true,'use-system-hosts':false,
   'default-nameserver':bootstrap,'proxy-server-nameserver':node_dns,'direct-nameserver':bootstrap,
   nameserver:['https://cloudflare-dns.com/dns-query#'+dns_group],'nameserver-policy':dns_policy(raw,env,ps,providers)},
  proxies:ps,'proxy-providers':providers,'proxy-groups':clean_groups,'rule-providers':rule_providers,rules};
}
function policy(env,rule_text,table) {
 environment(env); if(length(table || '')) die('Policy table already occupied');
 let lines=split(rule_text || '', '\n'), main=false;
 for(let i=0;i<length(lines);i++) {
  let m=match(lines[i],/^([0-9]+):/); if(!m) continue; let priority=int(m[1]);
  if(priority>=11000 && priority<=11031) die('Policy priorities already occupied');
  if(match(lines[i],/lookup (52|tailscale)( |$)/) && priority>=11000) die('Tailscale priority conflict');
  if(match(lines[i],/from all lookup main$/) && priority>11031) main=true;
 }
 if(!main) die('Main policy order unavailable');
 let result=[['ip','-4','route','add','table','2022','default','dev','mihomo0','proto','186','metric','2022']], excluded=exclusions(env);
 for(let i=0;i<length(excluded);i++) push(result,['ip','-4','rule','add','priority',''+(11000+i),'iif',env.lan_device,'to',excluded[i],'lookup','main']);
 push(result,['ip','-4','rule','add','priority','11031','iif',env.lan_device,'lookup','2022']); return result;
}
function firewall(env) {
 environment(env);
 return {
  cmproxy_zone:{'.type':'zone',cm2012_proxy:'1',name:'cmproxy',device:['mihomo0'],input:'REJECT',output:'ACCEPT',forward:'REJECT',family:'ipv4'},
  cmproxy_lan:{'.type':'forwarding',cm2012_proxy:'1',src:'lan',dest:'cmproxy',family:'ipv4'},
  cmproxy_dns_tcp:{'.type':'redirect',cm2012_proxy:'1',name:'CM proxy TCP DNS',src:'lan',src_dport:'53',dest:'lan',dest_ip:env.lan_ip,dest_port:'1053',proto:'tcp',target:'DNAT',family:'ipv4',reflection:'0'},
  cmproxy_dns_udp:{'.type':'redirect',cm2012_proxy:'1',name:'CM proxy UDP DNS',src:'lan',src_dport:'53',dest:'lan',dest_ip:env.lan_ip,dest_port:'1053',proto:'udp',target:'DNAT',family:'ipv4',reflection:'0'},
  cmproxy_dns_input:{'.type':'rule',cm2012_proxy:'1',name:'CM proxy LAN DNS',src:'lan',dest_ip:env.lan_ip,dest_port:'1053',proto:'tcp udp',target:'ACCEPT',family:'ipv4'},
  // fw3 global INPUT rules precede zone rules; accept LAN API before the global deny.
  cmproxy_api:{'.type':'rule',cm2012_proxy:'1',name:'CM proxy LAN API',src:'*',device:env.lan_device,direction:'in',dest_ip:env.lan_ip,dest_port:'9091',proto:'tcp',target:'ACCEPT',family:'ipv4'},
  cmproxy_dns_reject:{'.type':'rule',cm2012_proxy:'1',name:'CM proxy non-LAN DNS deny',src:'*',dest_port:'1053',proto:'tcp udp',extra:'! -i '+env.lan_device,target:'REJECT',family:'ipv4'},
  // tailscale0 must continue to cm2012_ts INPUT for source and management-port authorization.
  cmproxy_api_reject:{'.type':'rule',cm2012_proxy:'1',name:'CM proxy non-LAN API deny',src:'*',dest_port:'9091',proto:'tcp udp',extra:'! -i tailscale0',target:'REJECT',family:'ipv4'}
 };
}
function guard(failures,healthy) { return healthy ? 0 : failures+1; }
function worker_command(line,action,token) {
 if(!member(['transaction','update'],action) || !match(token||'',/^[a-f0-9-]{36}$/))return false;
 let args=split(line||'',sprintf('%c',0)), offset=member(['/bin/sh','/bin/ash'],args[0])?1:0;
 return length(args)==offset+4 && args[offset]=='/usr/libexec/cm2012-proxy' && args[offset+1]==action && args[offset+2]==token && args[offset+3]=='';
}
return {request,https,rule_text,github_rule_api,compile,policy,firewall,guard,worker_command};
