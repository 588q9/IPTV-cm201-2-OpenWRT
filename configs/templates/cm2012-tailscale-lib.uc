'use strict';
// Pure policy: all topology comes from the current netifd LAN status.
function values(v) { return type(v) == 'array' ? v : v ? [v] : []; }
function ipv4(v) {
 if (type(v) != 'string' || !match(v,/^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/)) return null;
 let n = 0, a = split(v,'.');
 for (let i = 0; i < 4; i++) { let p = int(a[i]); if (p > 255) return null; n = n * 256 + p; }
 return n;
}
function dotted(n) {
 let a = [];
 for (let i = 0; i < 4; i++) { push(a,'' + (n % 256)); n = int(n / 256); }
 return a[3] + '.' + a[2] + '.' + a[1] + '.' + a[0];
}
function source(v) {
 if (type(v) != 'string') return false;
 let a = split(v,'/');
 if (length(a) != 2 || !match(a[1],/^(1[0-9]|2[0-9]|3[0-2])$/)) return false;
 let n = ipv4(a[0]), p = int(a[1]), block = 1;
 for (let i = p; i < 32; i++) block *= 2;
 return n != null && n >= 1681915904 && n + block <= 1686110208 && n % block == 0;
}
function pending(v) { return !!v.prepared && !v.confirmed; }
function state(enabled, paused, backend) {
 if (enabled != '1') return 'disabled';
 if (paused) return 'paused';
 if (backend == 'NeedsLogin' || backend == 'NeedsMachineAuth') return 'needs_login';
 if (backend == 'Running') return 'check_route_approval';
 return 'starting';
}
function validate(settings) {
 if (settings.enabled != '0' && settings.enabled != '1') return {error:'启停参数无效。'};
 let sources = values(settings.allowed_sources), ports = values(settings.management_ports), seen = [];
 if (length(sources) > 32 || length(ports) > 16) return {error:'授权来源或管理端口过多。'};
 for (let i = 0; i < length(sources); i++) {
  if (!source(sources[i]) || index(seen,sources[i]) >= 0) return {error:'来源须为 Tailscale IPv4 范围内不重复的规范 CIDR。'};
  push(seen,sources[i]);
 }
 seen = [];
 for (let i = 0; i < length(ports); i++) {
  let p = ports[i];
  if (type(p) != 'string' || !match(p,/^[1-9][0-9]{0,4}$/) || int(p) > 65535 || p == '9090' || index(seen,p) >= 0)
   return {error:'管理端口须为不重复的 1–65535 TCP 端口；9090 仅限回环。'};
  push(seen,p);
 }
 return {enabled:settings.enabled,allowed_sources:sources,management_ports:ports};
}
function render(settings, lan) {
 let cfg = validate(settings);
 if (cfg.error) return cfg;
 let plan = {settings:cfg,firewall:{},daemon:{version:'alpha0',locked:false,enabled:true,
  acceptDNS:false,acceptRoutes:false,advertiseRoutes:[],advertiseExitNode:false,exitNode:'',disableSNAT:false,
  netfilterMode:'off',runSSHServer:false,runWebClient:true,remoteConfig:false}};
 if (cfg.enabled == '0') return plan;
 let addresses = lan['ipv4-address'];
 if (!lan.up || type(lan.l3_device) != 'string' || !match(lan.l3_device,/^[a-zA-Z0-9_.:-]{1,32}$/) ||
     type(addresses) != 'array' || length(addresses) != 1) return {error:'LAN 尚未稳定或有多个 IPv4 地址，未启用子网路由。'};
 let a = addresses[0], n = ipv4(a.address), prefix = a.mask, block = 1;
 if (n == null || type(prefix) != 'int' || prefix < 1 || prefix > 30 || n < 16777216 || n >= 3758096384 ||
     (n >= 2130706432 && n < 2147483648) || (n >= 1681915904 && n < 1686110208))
  return {error:'LAN IPv4 网段不适用于子网发布。'};
 for (let i = prefix; i < 32; i++) block *= 2;
 let network = n - n % block;
 if (n == network || n == network + block - 1 || (network < 1686110208 && network + block > 1681915904))
  return {error:'LAN IPv4 网段与 Tailscale 或保留地址冲突。'};
 plan.lan_cidr = dotted(network) + '/' + prefix;
 plan.lan_ip = a.address; plan.lan_device = lan.l3_device;
 plan.daemon.advertiseRoutes = [plan.lan_cidr];
 plan.firewall.cm2012_ts_zone = {'.type':'zone',name:'cm2012_ts',device:['tailscale0'],
  input:'REJECT',forward:'REJECT',output:'ACCEPT',family:'ipv4',cm2012_remote:'tailscale'};
 for (let i = 0; i < length(cfg.allowed_sources); i++) {
  let ip = cfg.allowed_sources[i];
  plan.firewall['cm2012_ts_lan_' + i] = {'.type':'rule',name:'CM201-2 Tailscale LAN',src:'cm2012_ts',dest:'lan',
   src_ip:ip,dest_ip:plan.lan_cidr,proto:'all',target:'ACCEPT',family:'ipv4',cm2012_remote:'tailscale'};
  plan.firewall['cm2012_ts_nat_' + i] = {'.type':'nat',name:'CM201-2 Tailscale LAN SNAT',src:'lan',
   src_ip:ip,dest_ip:plan.lan_cidr,snat_ip:plan.lan_ip,proto:'all',target:'SNAT',family:'ipv4',cm2012_remote:'tailscale'};
  if (length(cfg.management_ports)) plan.firewall['cm2012_ts_manage_' + i] = {'.type':'rule',name:'CM201-2 Tailscale management',
   src:'cm2012_ts',src_ip:ip,proto:'tcp',dest_port:cfg.management_ports,target:'ACCEPT',family:'ipv4',cm2012_remote:'tailscale'};
 }
 return plan;
}
function clear(c) {
 try {
  if (!c.load('firewall')) return {error:'无法读取防火墙配置。'};
  let remove = [];
  c.foreach('firewall',null,function(s) { if (s.cm2012_remote == 'tailscale') push(remove,s['.name']); });
  for (let i = 0; i < length(remove); i++) if (!c.delete('firewall',remove[i])) die('UCI delete failed');
  return {changed:!!length(remove)};
 } catch (e) { return {error:'无法清理 Tailscale 自有防火墙规则。'}; }
}
function equal(a, b) {
 if (type(a) != type(b)) return false;
 if (type(a) != 'array') return a == b;
 if (length(a) != length(b)) return false;
 for (let i = 0; i < length(a); i++) if (a[i] != b[i]) return false;
 return true;
}
function configure(c, plan) {
 if (plan.error) return plan;
 try {
  if (!c.load('firewall')) return {error:'无法读取防火墙配置。'};
  let names = keys(plan.firewall), old = {}, same = true;
  c.foreach('firewall',null,function(s) { if (s.cm2012_remote == 'tailscale') old[s['.name']] = s; });
  if (length(keys(old)) != length(names)) same = false;
  for (let i = 0; i < length(names); i++) {
   let name = names[i];
   if (c.get('firewall',name) && c.get('firewall',name,'cm2012_remote') != 'tailscale')
    return {error:'防火墙节名称已被其他配置使用。'};
   let wanted = plan.firewall[name], previous = old[name] || {}, options = keys(wanted);
   for (let j = 0; j < length(options); j++) if (!equal(wanted[options[j]],previous[options[j]])) same = false;
   options = keys(previous);
   for (let j = 0; j < length(options); j++) {
    let option = options[j];
    if (option != '.type' && !match(option,/^\./) && wanted[option] == null) same = false;
   }
  }
  if (same) return {changed:false};
  let result = clear(c); if (result.error) return result;
  for (let i = 0; i < length(names); i++) {
   let name = names[i], section = plan.firewall[name], options = keys(section);
   if (!c.set('firewall',name,section['.type'])) die('UCI set failed');
   for (let j = 0; j < length(options); j++) {
    let option = options[j];
    if (option != '.type' && !c.set('firewall',name,option,section[option])) die('UCI set failed');
   }
  }
  return {changed:result.changed || !!length(names)};
 } catch (e) { return {error:'无法生成 Tailscale 自有防火墙规则。'}; }
}
return {validate,render,configure,clear,pending,state};
