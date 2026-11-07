'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
var status = rpc.declare({object:'cm2012_tailscale',method:'status'});
var apply = rpc.declare({object:'cm2012_tailscale',method:'apply',params:['enabled','allowed_sources_json','management_ports_json']});
return view.extend({
 load:function() { return status(); },
 render:function(data) {
  var enabled = E('input',{type:'checkbox',checked:data.enabled == '1' ? '' : null});
  var sources = E('textarea',{'class':'cbi-input-text',rows:4},(data.allowed_sources || []).join('\n'));
  var ports = E('input',{'class':'cbi-input-text',value:(data.management_ports || []).join(',')});
  var output = E('pre',{});
  function refresh(s) {
   var names = {disabled:'已停用',paused:'网络事务中，已暂停',needs_login:'未登录或等待设备批准',
    starting:'等待服务启动',check_route_approval:'已登录；路由批准及异地访问待核验'};
   output.textContent = '状态：' + (names[s.state] || '状态不可用') + '\n实际 LAN：' + (s.lan_cidr || '未就绪') +
    '（' + (s.lan_device || '—') + '）\n' + (s.error || s.route_approval || '');
  }
  function list(value) { return value.split(/[\s,]+/).filter(Boolean); }
  refresh(data); poll.add(function(){return status().then(refresh);},5);
  return E('div',{},[
   E('h2',{},'CM201-2 异地访问'),
   E('p',{},'仅发布当前 IPv4 LAN；不接管系统 DNS，不接受异地路由，不提供退出节点。授权来源留空时不允许访问 LAN 或管理端口。'),output,
   E('label',{},[enabled,' 启用 Tailscale']),
   E('p',{},'获准客户端来源（每行一个 Tailscale IPv4 CIDR，例如 100.80.0.2/32）'),sources,
   E('p',{},'允许这些来源访问的本机 TCP 管理端口（逗号分隔，例如 22,443,5252；留空全部拒绝）'),ports,
   E('p',{},'保存并启用后，在本机 SSH 终端运行 /usr/libexec/cm2012-tailscale login 完成交互登录。随后在 Tailscale 控制台批准本机 LAN 路由并设置访问策略。请使用手机蜂窝网络验证 LAN TCP/UDP；页面在线不代表已验收。'),
   E('button',{'class':'btn cbi-button-apply',click:function(){
    return apply(enabled.checked?'1':'0',JSON.stringify(list(sources.value)),JSON.stringify(list(ports.value))).then(function(s){
     if(s.error)throw Error(s.error);return status().then(refresh);
    }).catch(function(e){ui.addNotification(null,E('p',{},e.message));});
   }},'保存并应用')
  ]);
 },handleSaveApply:null,handleSave:null,handleReset:null
});
