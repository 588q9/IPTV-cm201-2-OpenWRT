'use strict';
import { readfile, open, mkdir, chmod, popen } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';

const pending = '/tmp/cm2012-wifi/pending';
const wireless = loadfile('/usr/libexec/cm2012-wireless-lib.uc')();
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
 return type(token) == 'string' && match(token, /^[a-f0-9-]{36}$/) && trim(readfile(pending + '/token') || '') == token;
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
    upstream_ssid: c.get('cm2012', 'sta', 'ssid') },
   ap: b.call('hostapd.ap0', 'get_status', {}) || {}, clients: b.call('hostapd.ap0', 'get_clients', {}) || {},
   ethernet: b.call('network.interface.wan', 'status', {}) || {},
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
 apply: { args: { ssid: '', key: '', channel: '', enabled: '', uplink: '', upstream_ssid: '', upstream_key: '' }, call: function(request) {
  let a = request.args, c = cursor();
  let apkey = a.key || c.get('cm2012', 'ap', 'key');
  let stakey = a.upstream_key || c.get('cm2012', 'sta', 'key');
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
  write(pending + '/backup', readfile('/etc/config/cm2012'));
  write(pending + '/token', token);
  c.set('cm2012', 'ap', 'ssid', a.ssid); c.set('cm2012', 'ap', 'key', apkey);
  c.set('cm2012', 'ap', 'enabled', a.enabled); c.set('cm2012', 'ap', 'channel', a.channel);
  c.set('cm2012', 'settings', 'uplink', a.uplink);
  c.set('cm2012', 'sta', 'ssid', a.upstream_ssid); c.set('cm2012', 'sta', 'key', stakey || '');
  if (!c.commit('cm2012')) {
   system('rm -rf /tmp/cm2012-wifi/pending'); return { error: '配置提交失败' };
  }
  chmod('/etc/config/cm2012', 0600);
  system('/usr/libexec/cm2012-wifi transaction </dev/null >/dev/null 2>&1 &');
  return { token, timeout: 90 };
 } },
 confirm: { args: { token: '' }, call: function(request) {
  if (!token_ok(request.args.token)) return { error: '事务令牌无效' };
  let ready = trim(readfile(pending + '/ready') || '');
  if (!ready || ready != trim(readfile('/tmp/cm2012-wifi/ready') || ''))
   return { error: '无线服务或上联尚未就绪，不能确认。' };
  write(pending + '/confirmed', '1'); return { confirmed: true };
 } },
 rollback: { args: { token: '' }, call: function(request) {
  if (!token_ok(request.args.token)) return { error: '事务令牌无效' };
  write(pending + '/rollback', '1'); return { rollback: true };
 } }
} };
