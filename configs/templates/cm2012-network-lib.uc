'use strict';
// Keep validation and UCI rendering independent of RPC and service execution.
function member(values, value) { return index(values, value) >= 0; }
function list(value) { return type(value) == 'array' ? value : value ? [value] : []; }
function ipv4(value) {
 if (type(value) != 'string' || !match(value, /^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$/)) return null;
 let parts = split(value, '.'), n = 0;
 for (let i = 0; i < 4; i++) {
  let part = int(parts[i]); if (part > 255) return null; n = n * 256 + part;
 }
 return n;
}
function cidr(value) {
 if (type(value) != 'string') return null;
 let parts = split(value, '/');
 if (length(parts) != 2 || !match(parts[1], /^([1-9]|[12][0-9]|3[0-2])$/)) return null;
 let address = ipv4(parts[0]), prefix = int(parts[1]), block = 1;
 if (address == null) return null;
 for (let p = prefix; p < 32; p++) block *= 2;
 if (address % block != 0) return null;
 return { address, prefix, block };
}
function subnet(address, netmask) {
 // Accept both legacy ipaddr/netmask and the standard CIDR address form.
 let parts = split(address || '', '/'), n = ipv4(parts[0]), mask = ipv4(netmask || '255.255.255.0');
 if (n == null) return null;
 let block = 1, prefix = 32;
 if (length(parts) == 2) {
  if (!match(parts[1], /^([1-9]|[12][0-9]|3[0-2])$/)) return null;
  prefix = int(parts[1]); for (let p = prefix; p < 32; p++) block *= 2;
 } else {
  while (prefix > 0 && 4294967296 - block != mask) { prefix--; block *= 2; }
  if (!prefix) return null;
 }
 n -= n % block;
 let octets = [];
 for (let i = 0; i < 4; i++) { push(octets, '' + (n % 256)); n = int(n / 256); }
 return octets[3] + '.' + octets[2] + '.' + octets[1] + '.' + octets[0] + '/' + prefix;
}
function validate(a) {
 let routes, sources;
 try { routes = json(a.routes_json || '[]'); sources = json(a.upstream_sources_json || '[]'); }
 catch (e) { return { error: '路由和来源网段格式无效。' }; }
 if (!member(['wan','lan'], a.eth_role) || !member(['ethernet','wifi'], a.uplink) ||
     (a.eth_role == 'lan' && a.uplink != 'wifi') || !member(['0','1'], a.allow_upstream) ||
     type(routes) != 'array' || length(routes) > 32 || type(sources) != 'array' || length(sources) > 16)
  return { error: '网口角色、上联或路由参数无效；LAN 模式必须使用无线上联。' };
 let clean = [], seen = [];
 for (let i = 0; i < length(routes); i++) {
  let r = routes[i];
  if (type(r) != 'object' || !cidr(r.target) || type(r.gateway) != 'string' ||
      (r.gateway != '' && (ipv4(r.gateway) == null || ipv4(r.gateway) == 0 || ipv4(r.gateway) >= 3758096384)) ||
      !member(['lan','wan','wwan'], r.interface) || type(r.metric) != 'string' ||
      !match(r.metric, /^(0|[1-9][0-9]{0,4})$/) || int(r.metric) > 65535 || !member(['0','1'], r.enabled))
   return { error: '静态路由需要规范 IPv4 CIDR、下一跳、逻辑接口及 0–65535 的 metric；不支持额外默认路由。' };
  let key = r.target + ':' + r.interface + ':' + r.metric;
  if (member(seen, key)) return { error: '静态路由重复。' };
  push(seen, key);
  push(clean, { target: r.target, gateway: r.gateway, interface: r.interface, metric: r.metric, enabled: r.enabled });
 }
 seen = [];
 for (let i = 0; i < length(sources); i++) {
  if (!cidr(sources[i]) || member(seen, sources[i])) return { error: '上游来源必须是互不重复的规范 IPv4 CIDR。' };
  push(seen, sources[i]);
 }
 if (a.allow_upstream == '1' && !length(sources)) return { error: '允许上游访问时必须指定来源网段。' };
 return { eth_role: a.eth_role, uplink: a.uplink, allow_upstream: a.allow_upstream, routes: clean, sources };
}
function hex32le(n) {
 let result = '';
 for (let i = 0; i < 4; i++) { result += sprintf('%02X',n % 256); n = int(n / 256); }
 return result;
}
function installed(route, device, table) {
 let target = cidr(route.target);
 if (!target || !device) return false;
 let lines = split(table || '', '\n');
 for (let i = 1; i < length(lines); i++) {
  let f = split(lines[i], /[\t ]+/);
  if (length(f) >= 8 && f[0] == device && f[1] == hex32le(target.address) &&
      f[7] == hex32le(4294967296 - target.block) && f[6] == route.metric &&
      f[2] == hex32le(route.gateway ? ipv4(route.gateway) : 0) && (int(f[3],16) & 1)) return true;
 }
 return false;
}
function remove_owned(c, config, section_type) {
 let names = [];
 c.foreach(config, section_type, function(s) { if (s.cm2012 == '1') push(names, s['.name']); });
 for (let i = 0; i < length(names); i++) c.delete(config, names[i]);
}
function available(c, config, prefix) {
 let n = 0;
 while (c.get(config, prefix + n)) n++;
 return prefix + n;
}
function routes(c) {
 let result = [];
 c.foreach('network', 'route', function(s) {
  if (s.cm2012 == '1') push(result, { target: s.target, gateway: s.gateway || '',
   interface: s.interface, metric: s.metric || '0', enabled: s.disabled == '1' ? '0' : '1' });
 });
 return result;
}
function configure(c, cfg) {
 let address = c.get('network','lan','ipaddr');
 if (type(address) == 'array') address = address[0];
 let destination = subnet(address, c.get('network','lan','netmask'));
 if (!destination) return { error: '当前 LAN 地址无效，不能修改网络。' };
 let bridge = c.get('network','cm2012_bridge');
 if (bridge && c.get('network','cm2012_bridge','cm2012') != '1') return { error: '项目桥接配置名称已被其他配置占用。' };
 c.set('cm2012','settings','eth_role',cfg.eth_role);
 c.set('cm2012','settings','allow_upstream',cfg.allow_upstream);
 if (length(cfg.sources)) c.set('cm2012','settings','upstream_sources',cfg.sources);
 else c.delete('cm2012','settings','upstream_sources');
 c.set('network','lan','device',cfg.eth_role == 'lan' ? 'br-lan' : 'ap0');
 if (cfg.eth_role == 'lan') {
  c.delete('network','wan','device');
  c.set('network','cm2012_bridge','device');
  c.set('network','cm2012_bridge','name','br-lan');
  c.set('network','cm2012_bridge','type','bridge');
  c.set('network','cm2012_bridge','cm2012','1');
  c.set('network','cm2012_bridge','bridge_empty','1');
  c.set('network','cm2012_bridge','ports',['eth0','ap0']);
 } else {
  c.set('network','wan','device','eth0');
  if (bridge) c.delete('network','cm2012_bridge');
 }
 remove_owned(c,'network','route');
 let destinations = [destination];
 for (let i = 0; i < length(cfg.routes); i++) {
  let r = cfg.routes[i], name = available(c,'network','cm2012_route_');
  c.set('network',name,'route'); c.set('network',name,'cm2012','1');
  c.set('network',name,'target',r.target); c.set('network',name,'interface',r.interface);
  c.set('network',name,'metric',r.metric); c.set('network',name,'disabled',r.enabled == '1' ? '0' : '1');
  if (r.gateway) c.set('network',name,'gateway',r.gateway);
  if (r.enabled == '1' && r.interface == 'lan' && !member(destinations,r.target)) push(destinations,r.target);
 }
 remove_owned(c,'firewall','rule');
 let upper = cfg.uplink == 'wifi' ? 'wwan' : 'wan', zone_name = null;
 c.foreach('firewall','zone',function(s) {
  // Anonymous UCI cfg names change after edits. Keep an explicit identity.
  if (!s.cm2012_zone_id) c.set('firewall',s['.name'],'cm2012_zone_id',s.name);
  let exclusions = list(s.masq_dest), previous = list(s.cm2012_masq_exempt), remaining = [];
  for (let i = 0; i < length(exclusions); i++) if (!member(previous,exclusions[i])) push(remaining,exclusions[i]);
  let added = [];
  if (member(list(s.network),upper)) {
   zone_name = s.name;
   if (cfg.allow_upstream == '1') for (let i = 0; i < length(cfg.sources); i++) {
    let exemption = '!' + cfg.sources[i];
    if (!member(remaining,exemption)) { push(remaining,exemption); push(added,exemption); }
   }
  }
  if (length(remaining)) c.set('firewall',s['.name'],'masq_dest',remaining);
  else c.delete('firewall',s['.name'],'masq_dest');
  if (length(added)) c.set('firewall',s['.name'],'cm2012_masq_exempt',added);
  else c.delete('firewall',s['.name'],'cm2012_masq_exempt');
 });
 if (cfg.allow_upstream == '1') {
  if (!zone_name) return { error: '找不到所选上联的防火墙区域。' };
  for (let i = 0; i < length(cfg.sources); i++) for (let j = 0; j < length(destinations); j++) {
   let name = available(c,'firewall','cm2012_forward_');
   c.set('firewall',name,'rule'); c.set('firewall',name,'cm2012','1');
   c.set('firewall',name,'name','CM2012 upstream routing');
   c.set('firewall',name,'src',zone_name); c.set('firewall',name,'dest','lan');
   c.set('firewall',name,'src_ip',cfg.sources[i]); c.set('firewall',name,'dest_ip',destinations[j]);
   c.set('firewall',name,'family','ipv4'); c.set('firewall',name,'proto','all'); c.set('firewall',name,'target','ACCEPT');
  }
 }
 return {};
}
function equal(a,b) {
 if (a == null || b == null) return a == b;
 if (type(a) != type(b)) return false;
 if (type(a) == 'array') {
  if (length(a) != length(b)) return false;
  for (let i = 0; i < length(a); i++) if (!equal(a[i],b[i])) return false;
  return true;
 }
 if (type(a) == 'object') {
  let names = keys(a), others = keys(b);
  // UCI indexing metadata is not configuration and may change on edits.
  for (let i = 0; i < length(names); i++) if (names[i] == '.type' || index(names[i],'.') != 0)
   if (!equal(a[names[i]],b[names[i]])) return false;
  for (let i = 0; i < length(others); i++) if (others[i] == '.type' || index(others[i],'.') != 0)
   if (!equal(a[others[i]],b[others[i]])) return false;
  return true;
 }
 return a == b;
}
function restore_diff(before,applied,current) {
 let result = [], names = keys(before), after_names = keys(applied);
 for (let i = 0; i < length(after_names); i++) if (!member(names,after_names[i])) push(names,after_names[i]);
 for (let i = 0; i < length(names); i++) {
  let name = names[i], b = before[name], a = applied[name], live = current[name];
  if (equal(b,a)) continue;
  if (!b && equal(live,a)) { push(result,{section:name,remove:true}); continue; }
  if (!a && live) continue;
  let options = b ? keys(b) : [], after_options = a ? keys(a) : [];
  for (let j = 0; j < length(after_options); j++) if (!member(options,after_options[j])) push(options,after_options[j]);
  for (let j = 0; j < length(options); j++) {
   let key = options[j];
   if (key != '.type' && index(key,'.') == 0) continue;
   let old = b ? b[key] : null, changed = a ? a[key] : null, now = live ? live[key] : null;
   if (!equal(old,changed) && equal(now,changed)) push(result,{section:name,option:key,value:old == null ? null : old});
   else if (!equal(old,changed) && type(now) == 'array' && (type(old) == 'array' || type(changed) == 'array')) {
    let previous = list(old), added = list(changed), merged = [];
    for (let k = 0; k < length(now); k++)
     if (!member(added,now[k]) || member(previous,now[k])) push(merged,now[k]);
    for (let k = 0; k < length(previous); k++)
     if (!member(added,previous[k]) && !member(merged,previous[k])) push(merged,previous[k]);
    if (!equal(merged,now)) push(result,{section:name,option:key,value:length(merged) ? merged : null});
   }
  }
 }
 return result;
}
function section_key(s) { return s['.type'] == 'zone' ? '@zone:' + (s.cm2012_zone_id || s.name) : s['.name']; }
return { validate, configure, routes, subnet, installed, restore_diff, section_key };
