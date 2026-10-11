'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var status = rpc.declare({ object: 'cm2012', method: 'status' });
var scan = rpc.declare({ object: 'cm2012', method: 'scan' });
var apply = rpc.declare({ object: 'cm2012', method: 'apply', params: ['ssid', 'key', 'channel', 'enabled', 'uplink', 'upstream_ssid', 'upstream_key'] });
var confirm = rpc.declare({ object: 'cm2012', method: 'confirm', params: ['token'] });
var rollback = rpc.declare({ object: 'cm2012', method: 'rollback', params: ['token'] });

return view.extend({
 load: function() { return status(); },
 render: function(data) {
  var c = data.config, token = sessionStorage.getItem('cm2012-token');
  var fields = {};
  function input(name, value, type) { return fields[name] = E('input', { 'class': 'cbi-input-text', type: type || 'text', value: value || '', autocomplete: type == 'password' ? 'new-password' : 'off' }); }
  function select(name, value, choices) {
   return fields[name] = E('select', { 'class': 'cbi-input-select' }, choices.map(function(choice) { return E('option', { value: choice[0], selected: choice[0] == value ? '' : null }, choice[1]); }));
  }
  function row(label, control) { return E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, label), E('div', { 'class': 'cbi-value-field' }, control)]); }
  var result = E('pre', {}), networks = E('div', {}), transaction = E('div', {});
  function refresh(s) {
   if (s.pending_token) {
    token = s.pending_token; sessionStorage.setItem('cm2012-token', token);
   }
   else if (!s.pending) {
    token = null; sessionStorage.removeItem('cm2012-token');
   }
   result.textContent = '热点：' + (s.ap.status || s.ap.state || '未运行') + '，信道 ' + (s.ap.channel || '—') +
    '\n有线：' + (s.ethernet.up ? '已获取地址' : '等待链路或 DHCP') +
    '\n无线：' + (s.sta.wpa_state || '未连接') +
    '\n客户端：' + Object.keys(s.clients.clients || {}).join(', ');
   transaction.textContent = s.pending ? '设置待确认；90 秒内未确认会自动恢复。重新连接热点后确认。' : '配置已稳定。';
  }
  refresh(data);
  poll.add(function() { return status().then(refresh); }, 5);
  return E('div', {}, [
   E('h2', {}, 'CM201-2 无线与上联'),
   E('p', {}, '手动选择有线或 WPA2 无线上联。无线上联与热点共用信道；密码留空表示保留已有密码。'), result,
   row('热点名称', input('ssid', c.ssid)), row('热点密码', input('key', '', 'password')),
   row('热点开关', select('enabled', c.enabled, [['1','启用'],['0','停用']])),
   row('热点信道（有线模式）', select('channel', c.channel, ['1','2','3','4','5','6','7','8','9','10','11','12','13','36','40','44','48','149','153','157','161','165'].map(function(n) { return [n,n]; }))),
   row('上联方式', select('uplink', c.uplink, [['ethernet','有线（可信网络）'],['wifi','无线（限制入站）']])),
   row('上游 SSID', input('upstream_ssid', c.upstream_ssid)), row('上游密码', input('upstream_key', '', 'password')),
   E('button', { 'class': 'btn', click: function() {
    scan().then(function() { return new Promise(function(resolve) { setTimeout(resolve, 2500); }); }).then(scan).then(function(s) {
     networks.replaceChildren();
     s.networks.forEach(function(n) { networks.appendChild(E('button', { 'class': 'btn', click: function() { fields.upstream_ssid.value = n.ssid; fields.uplink.value = 'wifi'; } }, n.ssid + ' (' + n.signal + ' dBm, ' + n.security + ')')); });
    }).catch(function(e) { ui.addNotification(null, E('p', {}, e.message)); });
   } }, '扫描上游'), networks, E('hr'), transaction,
   E('button', { 'class': 'btn cbi-button-apply', click: function() {
    apply.apply(null, ['ssid','key','channel','enabled','uplink','upstream_ssid','upstream_key'].map(function(n) { return fields[n].value; })).then(function(r) {
     if (r.error) throw new Error(r.error);
     token = r.token; sessionStorage.setItem('cm2012-token', token);
     fields.key.value = ''; fields.upstream_key.value = '';
     transaction.textContent = '正在应用。重新连接热点后，90 秒内点击确认。';
    }).catch(function(e) { ui.addNotification(null, E('p', {}, e.message)); });
   } }, '应用设置'),
   E('button', { 'class': 'btn', click: function() { confirm(token || '').then(function(r) { if (r.error) ui.addNotification(null, E('p', {}, r.error)); else sessionStorage.removeItem('cm2012-token'); }); } }, '确认可访问'),
   E('button', { 'class': 'btn', click: function() { rollback(token || '').then(function(r) { if (r.error) ui.addNotification(null, E('p', {}, r.error)); }); } }, '立即回滚')
  ]);
 },
 handleSaveApply: null, handleSave: null, handleReset: null
});
