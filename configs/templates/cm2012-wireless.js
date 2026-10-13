'use strict';
'require view';
'require rpc';
'require ui';
'require poll';

var status = rpc.declare({ object: 'cm2012', method: 'status' });
var scan = rpc.declare({ object: 'cm2012', method: 'scan' });
var apply = rpc.declare({ object: 'cm2012', method: 'apply', params: ['ssid', 'key', 'channel', 'enabled', 'uplink', 'upstream_ssid', 'upstream_key', 'eth_role', 'allow_upstream', 'routes_json', 'upstream_sources_json'] });
var confirm = rpc.declare({ object: 'cm2012', method: 'confirm', params: ['token'] });
var rollback = rpc.declare({ object: 'cm2012', method: 'rollback', params: ['token'] });

return view.extend({
 load: function() { return status(); },
 render: function(data) {
  var c = data.config, token = sessionStorage.getItem('cm2012-token');
  var fields = {};
  function input(name, value, type) { return fields[name] = E('input', { 'class': 'cbi-input-text', type: type || 'text', value: value || '', autocomplete: type == 'password' ? 'new-password' : 'off' }); }
  function select(name, value, choices) {
   var control = E('select', { 'class': 'cbi-input-select' }, choices.map(function(choice) { return E('option', { value: choice[0], selected: choice[0] == value ? '' : null }, choice[1]); }));
   control.value = value; return fields[name] = control;
  }
  function row(label, control) { return E('div', { 'class': 'cbi-value' }, [E('label', { 'class': 'cbi-value-title' }, label), E('div', { 'class': 'cbi-value-field' }, control)]); }
  var result = E('pre', {}), networks = E('div', {}), transaction = E('div', {});
  var routeRows = [], routeTable = E('div', {});
  function addRoute(r) {
   var controls = {};
   ['target','gateway','metric'].forEach(function(name) {
    controls[name] = E('input', { 'class': 'cbi-input-text', value: r[name] || (name == 'metric' ? '0' : ''),
     placeholder: name == 'target' ? '192.168.60.0/24' : name == 'gateway' ? '192.168.50.2' : '0' });
   });
   ['interface','enabled'].forEach(function(name) {
    var choices = name == 'interface' ? [['lan','LAN'],['wan','有线 WAN'],['wwan','无线 WAN']] : [['1','启用'],['0','停用']];
    controls[name] = E('select', { 'class': 'cbi-input-select' }, choices.map(function(v) { return E('option', {value:v[0]},v[1]); }));
    controls[name].value = r[name] || (name == 'interface' ? 'lan' : '1');
   });
   var item = E('div', { 'class': 'cbi-section' }, [row('目标 CIDR',controls.target), row('下一跳（可留空）',controls.gateway),
    row('逻辑接口',controls.interface),row('Metric',controls.metric),row('状态',controls.enabled),
    E('button', { 'class':'btn', click:function() { routeRows.splice(routeRows.indexOf(controls),1); item.remove(); } },'删除路由')]);
   routeRows.push(controls); routeTable.appendChild(item);
  }
  (c.routes || []).forEach(addRoute);
  function refresh(s) {
   if (s.pending_token) {
    token = s.pending_token; sessionStorage.setItem('cm2012-token', token);
   }
   else if (!s.pending) {
    token = null; sessionStorage.removeItem('cm2012-token');
   }
   result.textContent = '热点：' + (s.ap.status || s.ap.state || '未运行') + '，信道 ' + (s.ap.channel || '—') +
    '\n网口：' + ((s.config.eth_role || 'wan') == 'lan' ? 'LAN，桥成员 ' + (s.bridge_members || []).join(', ') : 'WAN，' + (s.ethernet.up ? '已获取地址' : '未启用或等待 DHCP')) +
    '\n无线：' + (s.sta.wpa_state || '未连接') +
    '\n客户端：' + Object.keys(s.clients.clients || {}).join(', ') +
    '\n静态路由：' + (s.route_status || []).map(function(r) { return r.target + ' (' + r.interface + ')：' +
      ({installed:'已生效',inactive:'接口不可用，未生效',disabled:'已停用','not-installed':'未生效'}[r.state] || r.state); }).join('\n');
   transaction.textContent = s.pending ? '设置待确认；90 秒内未确认会自动恢复。重新连接热点后确认。' : '配置已稳定。';
  }
  refresh(data);
  poll.add(function() { return status().then(refresh); }, 5);
  var page = E('div', {}, [
   E('h2', {}, 'CM201-2 无线、网口与路由'),
   E('p', {}, '手动选择有线或 WPA2 无线上联。无线上联与热点共用信道；密码留空表示保留已有密码。'), result,
   row('热点名称', input('ssid', c.ssid)), row('热点密码', input('key', '', 'password')),
   row('热点开关', select('enabled', c.enabled, [['1','启用'],['0','停用']])),
   row('热点信道（有线模式）', select('channel', c.channel, ['1','2','3','4','5','6','7','8','9','10','11','12','13','36','40','44','48','149','153','157','161','165'].map(function(n) { return [n,n]; }))),
   row('上联方式', select('uplink', c.uplink, [['ethernet','有线（可信网络）'],['wifi','无线（限制入站）']])),
   row('网口角色', select('eth_role', c.eth_role || 'wan', [['wan','WAN（有线上联）'],['lan','LAN（连接下游设备）']])),
   row('上游 SSID', input('upstream_ssid', c.upstream_ssid)), row('上游密码', input('upstream_key', '', 'password')),
   E('button', { 'class': 'btn', click: function() {
    scan().then(function() { return new Promise(function(resolve) { setTimeout(resolve, 2500); }); }).then(scan).then(function(s) {
     networks.replaceChildren();
     s.networks.forEach(function(n) { networks.appendChild(E('button', { 'class': 'btn', click: function() { fields.upstream_ssid.value = n.ssid; fields.uplink.value = 'wifi'; } }, n.ssid + ' (' + n.signal + ' dBm, ' + n.security + ')')); });
    }).catch(function(e) { ui.addNotification(null, E('p', {}, e.message)); });
   } }, '扫描上游'), networks, E('hr'),
   E('h3',{},'IPv4 静态路由'),
   E('p',{},'只管理本页创建的路由；接口未启用时配置保留。下游为 AP 模式、共用 LAN 网段时无需额外路由。'),
   routeTable, E('button', { 'class':'btn',click:function(){addRoute({});} },'新增路由'),
   E('p',{},E('a', {href:'/cgi-bin/luci/admin/network/routes'},'打开标准路由页面')),
   row('允许上游访问下游',select('allow_upstream',c.allow_upstream || '0',[['0','关闭'],['1','仅允许指定来源网段']])),
   row('上游来源 CIDR',input('upstream_sources',(Array.isArray(c.upstream_sources) ? c.upstream_sources : [c.upstream_sources]).filter(Boolean).join(', '))),
   E('p',{},'来源网段用逗号或空格分隔。开启后仍需上游主路由具备回程路由；独立下游路由器也需允许对应转发。'),
   E('hr'), transaction,
   E('button', { 'class': 'btn cbi-button-apply', click: function() {
    if (fields.eth_role.value == 'lan') fields.uplink.value = 'wifi';
    var values = ['ssid','key','channel','enabled','uplink','upstream_ssid','upstream_key','eth_role','allow_upstream'].map(function(n) { return fields[n].value; });
    values.push(JSON.stringify(routeRows.map(function(controls){
     var r={}; ['target','gateway','interface','metric','enabled'].forEach(function(n){r[n]=controls[n].value.trim();}); return r;
    })),JSON.stringify(fields.upstream_sources.value.split(/[,\s]+/).filter(Boolean)));
    apply.apply(null, values).then(function(r) {
     if (r.error) throw new Error(r.error);
     token = r.token; sessionStorage.setItem('cm2012-token', token);
     fields.key.value = ''; fields.upstream_key.value = '';
     transaction.textContent = '正在应用。重新连接热点后，90 秒内点击确认。';
    }).catch(function(e) { ui.addNotification(null, E('p', {}, e.message)); });
   } }, '应用设置'),
   E('button', { 'class': 'btn', click: function() { confirm(token || '').then(function(r) { if (r.error) ui.addNotification(null, E('p', {}, r.error)); else sessionStorage.removeItem('cm2012-token'); }); } }, '确认可访问'),
   E('button', { 'class': 'btn', click: function() { rollback(token || '').then(function(r) { if (r.error) ui.addNotification(null, E('p', {}, r.error)); }); } }, '立即回滚')
  ]);
  fields.eth_role.addEventListener('change',function() { if (fields.eth_role.value == 'lan') fields.uplink.value = 'wifi'; });
  return page;
 },
 handleSaveApply: null, handleSave: null, handleReset: null
});
