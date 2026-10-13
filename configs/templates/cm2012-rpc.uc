'use strict';
import { readfile, open, mkdir, chmod, popen, lsdir } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';

const pending = '/tmp/cm2012-wifi/pending';
const wireless = loadfile('/usr/libexec/cm2012-wireless-lib.uc')();
const network = loadfile('/usr/libexec/cm2012-network-lib.uc')();
const journal = '/etc/cm2012-transaction';
function write(path, value) {
 let f = open(path, 'w', 0600);
 if (!f) die('无法写入事务文件');
 f.write(value); f.close(); chmod(path, 0600);
}
function control(command) {
 let f = popen('/usr/libexec/cm2012-wpa-control ' + command + ' 2>/dev/null');
 if (!f) return '';
 let value = f.read('all'); f.close(); return value;
}
function valid_text(value, min, max) {
 return type(value) == 'string' && length(value) >= min && length(value) <= max &&
  index(value, '\u0000') < 0 && !match(value, /[[:cntrl:]]/);
}
function token_ok(token) {
 return type(token) == 'string' && match(token, /^[a-f0-9-]{36}$/) &&
  trim(readfile(pending + '/token') || '') == token && trim(readfile(journal + '/token') || '') == token;
}
function route_status(c,b) {
 let result = [], routes = network.routes(c), table = readfile('/proc/net/route') || '';
 for (let r in routes) {
  let status = b.call('network.interface.' + r.interface,'status',{}) || {};
  push(result,{ target: r.target, interface: r.interface, metric: r.metric,
   state: r.enabled != '1' ? 'disabled' : !status.up ? 'inactive' :
    network.installed(r,status.l3_device || status.device,table) ? 'installed' : 'not-installed' });
 }
 return result;
}
return { cm2012: {
 status: { call: function() {
  let c = cursor(), b = connect();
  let sta = {};
  for (let line in split(control('STATUS'), '\n')) {
   let m = match(line, /^(wpa_state|ssid|freq)=(.*)$/);
   if (m) sta[m[1]] = m[2];
  }
  return {
   config: { ssid: c.get('cm2012', 'ap', 'ssid'), enabled: c.get('cm2012', 'ap', 'enabled'),
    channel: c.get('cm2012', 'ap', 'channel'), uplink: c.get('cm2012', 'settings', 'uplink'),
    upstream_ssid: c.get('cm2012', 'sta', 'ssid'),
    eth_role: c.get('cm2012','settings','eth_role') || 'wan',
    allow_upstream: c.get('cm2012','settings','allow_upstream') || '0',
    upstream_sources: c.get('cm2012','settings','upstream_sources') || [],
    routes: network.routes(c) },
   ap: b.call('hostapd.ap0', 'get_status', {}) || {}, clients: b.call('hostapd.ap0', 'get_clients', {}) || {},
   ethernet: b.call('network.interface.wan', 'status', {}) || {},
   lan: b.call('network.interface.lan','status',{}) || {},
   bridge_members: lsdir('/sys/class/net/br-lan/brif') || [],
   route_status: route_status(c,b),
   wireless: b.call('network.interface.wwan', 'status', {}) || {}, sta,
   pending: !!readfile(pending + '/token'),
   pending_token: trim(readfile(pending + '/token') || '')
  };
 } },
 scan: { call: function() {
  let result = control('SCAN_RESULTS');
  control('SCAN');
  let networks = [];
  for (let line in split(result, '\n')) {
   let fields = split(line, '\t');
   if (length(fields) >= 5 && match(fields[0], /^[a-fA-F0-9:]{17}$/))
    push(networks, { bssid: fields[0], frequency: fields[1], signal: fields[2], security: fields[3], ssid: wireless.decode_ssid(join('\t', slice(fields, 4))) });
  }
  return { networks };
 } },
 apply: { args: { ssid: '', key: '', channel: '', enabled: '', uplink: '', upstream_ssid: '', upstream_key: '',
   eth_role: '', allow_upstream: '', routes_json: '', upstream_sources_json: '' }, call: function(request) {
  let a = request.args, c = cursor();
  let apkey = a.key || c.get('cm2012', 'ap', 'key');
  let stakey = a.upstream_key || c.get('cm2012', 'sta', 'key');
  // Missing new arguments from an older client preserve existing settings.
  let cfg = network.validate({ eth_role: a.eth_role || c.get('cm2012','settings','eth_role') || 'wan',
   uplink: a.uplink, allow_upstream: a.allow_upstream || c.get('cm2012','settings','allow_upstream') || '0',
   routes_json: a.routes_json || sprintf('%J', network.routes(c)),
   upstream_sources_json: a.upstream_sources_json || sprintf('%J', c.get('cm2012','settings','upstream_sources') || []) });
  if (cfg.error) return cfg;
  let channels = ['1','2','3','4','5','6','7','8','9','10','11','12','13','36','40','44','48','149','153','157','161','165'];
  if (!valid_text(a.ssid, 1, 32) || !valid_text(apkey, 8, 63) || !(a.channel in channels) ||
      !(a.enabled in ['0','1']) || !(a.uplink in ['ethernet','wifi']) ||
      !valid_text(a.upstream_ssid, 0, 32) ||
      (stakey && !valid_text(stakey, 8, 63)) ||
      (a.uplink == 'wifi' && (!valid_text(a.upstream_ssid, 1, 32) || !valid_text(stakey, 8, 63))))
   return { error: '参数无效：SSID 最多 32 字节，WPA2 密码 8–63 字节，禁止控制字符。' };
  // 每次申请独占锁；拒绝覆盖尚未确认的事务。
  mkdir('/tmp/cm2012-wifi', 0700);
  if (!mkdir(pending, 0700)) return { error: '已有设置等待确认或回滚' };
  let token = trim(readfile('/proc/sys/kernel/random/uuid'));
  if (!match(token, /^[a-f0-9-]{36}$/) || system('/usr/libexec/cm2012-network prepare ' + token) != 0) {
   system('rm -rf /tmp/cm2012-wifi/pending'); return { error: '无法备份配置，未应用更改。' };
  }
  let rendered = network.configure(c,cfg);
  if (rendered.error) { system('/usr/libexec/cm2012-network abort'); return rendered; }
  write(pending + '/token', token);
  c.set('cm2012', 'ap', 'ssid', a.ssid); c.set('cm2012', 'ap', 'key', apkey);
  c.set('cm2012', 'ap', 'enabled', a.enabled); c.set('cm2012', 'ap', 'channel', a.channel);
  c.set('cm2012', 'settings', 'uplink', a.uplink);
  c.set('cm2012', 'sta', 'ssid', a.upstream_ssid); c.set('cm2012', 'sta', 'key', stakey || '');
  if (!c.commit('cm2012') || !c.commit('network') || !c.commit('firewall')) {
   system('/usr/libexec/cm2012-network abort'); return { error: '配置提交失败，已恢复全部配置。' };
  }
  chmod('/etc/config/cm2012', 0600);
  if (system('/usr/libexec/cm2012-network snapshot') != 0) {
   system('/usr/libexec/cm2012-network abort'); return { error: '无法记录已应用配置，已恢复。' };
  }
  system('/usr/libexec/cm2012-network transaction </dev/null >/tmp/cm2012-wifi/transaction.log 2>&1 &');
  return { token, timeout: 90 };
 } },
 confirm: { args: { token: '' }, call: function(request) {
  if (!token_ok(request.args.token)) return { error: '事务令牌无效' };
  let ready = trim(readfile(pending + '/ready') || '');
  if (!ready || ready != trim(readfile('/tmp/cm2012-wifi/ready') || '') ||
      system('/usr/libexec/cm2012-network ready') != 0)
   return { error: '无线服务或上联尚未就绪，不能确认。' };
  if (system('/usr/libexec/cm2012-network confirm ' + request.args.token) != 0)
   return { error: '事务已进入回滚，不能确认。' };
  return { confirmed: true };
 } },
 rollback: { args: { token: '' }, call: function(request) {
  if (!token_ok(request.args.token)) return { error: '事务令牌无效' };
  if (system('/usr/libexec/cm2012-network request-rollback') != 0)
   return { error: '事务已确认或正在结束，不能回滚。' };
  return { rollback: true };
 } }
} };
