'use strict';
'require view';
'require rpc';
'require ui';
'require poll';
var status=rpc.declare({object:'cm2012_proxy',method:'status'});
var save=rpc.declare({object:'cm2012_proxy',method:'save_subscription',params:['subscription_url','expected_revision']});
var apply=rpc.declare({object:'cm2012_proxy',method:'apply',params:['enabled','subscription_url','expected_revision']});
var confirm=rpc.declare({object:'cm2012_proxy',method:'confirm',params:['token']});
var rollback=rpc.declare({object:'cm2012_proxy',method:'rollback',params:['token']});
var disable=rpc.declare({object:'cm2012_proxy',method:'disable',params:['expected_revision']});
var update=rpc.declare({object:'cm2012_proxy',method:'update_subscription',params:['expected_revision']});
return view.extend({
 load:function(){return status().then(function(s){if(!s || (s.error && !s.state))throw new Error(s && s.error || '无法读取代理状态。');return s;});},
 render:function(initial){
  var current=initial,requesting=false,statusFailed=false,buttons=[],output=E('pre',{}),pending=E('p',{}),saved=E('p',{}),feedback=E('p',{role:'status','aria-live':'polite'}),dashboard=E('a',{target:'_blank',rel:'noopener noreferrer'},'打开 MetaCubeXD');
  var subscription=E('input',{type:'password',class:'cbi-input-text',autocomplete:'new-password',placeholder:'HTTPS 订阅；留空保留已有地址'});
  var enabled=E('select',{class:'cbi-input-select'},[E('option',{value:'0'},'停用'),E('option',{value:'1'},'启用 LAN 自动分流')]);
  var stages={queued:'已受理，等待准备',download:'正在下载订阅',providers:'正在下载订阅依赖',compile:'正在生成配置',check:'正在检查核心配置',start:'正在启动核心',routes:'正在接入分流规则',confirm:'已就绪，等待确认',saved:'订阅地址已保存',idle:'空闲'};
  enabled.value=initial.enabled?'1':'0';
  function controls(){
   buttons.forEach(function(b){b.disabled=requesting || (b!==disableButton && !!current.pending);});
   confirmButton.disabled=requesting || !current.pending || !current.pending_ready || !(current.remaining>0);
   rollbackButton.disabled=requesting || !current.pending;
   subscription.disabled=requesting;enabled.disabled=requesting;
  }
  function refresh(s){
   if(!s || (s.error && !s.state))throw new Error(s && s.error || '无法读取代理状态。');
   current=s;
   if(statusFailed){feedback.textContent='状态读取已恢复。';statusFailed=false;}
   output.textContent='状态：'+({disabled:'已停用',checking:'检查中',active:'已启用',degraded:'异常，已恢复直连',rolling_back:'正在回滚',failed:'恢复失败'}[s.state]||s.state)+
    '\n阶段：'+(stages[s.stage] || '处理中')+'\nLAN：'+(s.lan_device||'—')+' '+(s.lan_ip||'')+'\n分流规则：'+(s.routing_ready?'已就绪':'未接管')+
    '\n本地核心：'+(s.core_ready?'已就绪':'尚未就绪')+'\n公网代理和 DNS：'+({available:'最近检查通过',unavailable:'不可用，保留接管并尝试恢复',unknown:'尚未验证'}[s.external_state]||'尚未验证')+
    (s.dns_recovery_error==='cache_flush_failed'?'\n缓存刷新失败，将限频重试。':'')+'\nIPv6：未覆盖\n'+(s.error||'');
   saved.textContent=s.subscription_saved?'订阅已保存；无需确认，不回显地址。':'尚未保存订阅地址。';
   pending.textContent=(s.pending?(s.pending_ready?'更改已就绪，确认剩余 '+Math.max(0,Math.min(90,parseInt(s.remaining,10)||0))+' 秒；检查下游终端 TCP、UDP、DNS 后点击确认正常。':'正在准备代理；核心和分流规则就绪后开始 90 秒确认，当前无需确认。'):'没有待确认更改。')+
    (s.updating?'\n订阅更新或网络协调正在后台执行，可随时恢复直连。':'')+(s.apply_error?'\n'+s.apply_error:'')+(s.update_error?'\n'+s.update_error:'');
   if(s.dashboard){dashboard.href=s.dashboard;dashboard.style.display='';}else{dashboard.removeAttribute('href');dashboard.style.display='none';}
   controls();
  }
  function readStatus(){return status().then(refresh).catch(function(e){statusFailed=true;feedback.textContent='状态读取失败：'+e.message;});}
  function action(message,work,success,accepted){
   if(requesting)return Promise.resolve();
   requesting=true;statusFailed=false;feedback.textContent=message;controls();
   return Promise.resolve().then(work).then(function(r){
    if(r && r.error)throw new Error(r.error);
    if(accepted)accepted(r);feedback.textContent=success;return readStatus();
   }).catch(function(e){feedback.textContent=e.message;ui.addNotification(null,E('p',{},e.message));}).then(function(){requesting=false;controls();});
  }
  function button(label,className,click){var b=E('button',{class:className||'btn',click:click},label);buttons.push(b);return b;}
  var saveButton=button('保存订阅','btn',function(){var url=subscription.value;return action('正在保存订阅地址…',function(){return save(url,current.revision);},'订阅已保存，无需确认；启用自动分流时另行应用。',function(){if(subscription.value===url)subscription.value='';});});
  var applyButton=button('应用（90 秒确认）','btn cbi-button-apply',function(){var url=subscription.value;return action('正在提交代理应用…',function(){return apply(enabled.value,url,current.revision);},'应用已受理，正在准备；核心和分流规则就绪后开始 90 秒确认。',function(){if(subscription.value===url)subscription.value='';});});
  var confirmButton=button('确认正常','btn',function(){return action('正在确认代理…',function(){return confirm(current.pending_token||'');},'已确认当前代理设置。');});
  var rollbackButton=button('回滚本次更改','btn',function(){return action('正在回滚本次更改…',function(){return rollback(current.pending_token||'');},'本次更改已回滚，订阅地址仍保留。');});
  var disableButton=button('立即恢复直连','btn cbi-button-negative',function(){return action('正在恢复直连…',function(){return disable(current.revision);},'已恢复直连，订阅地址仍保留。',function(){enabled.value='0';});});
  var updateButton=button('更新订阅','btn',function(){return action('正在提交订阅更新…',function(){return update(current.revision);},'订阅更新已受理，后台正在下载和检查。');});
  refresh(initial);poll.add(readStatus,5);
  return E('div',{},[
   E('h2',{},'CM201-2 代理'),
   E('p',{},'下游设备的默认网关和 DNS 必须指向本机。核心或接管异常时恢复直连；公网节点或 DNS 故障保留接管并尝试恢复。已有连接可能需要重连。IPv6、应用内置 DoH/DoT 不在此接管范围。'),
   output,E('div',{class:'cbi-value'},[E('label',{},'自动分流'),enabled]),
   E('div',{class:'cbi-value'},[E('label',{},'订阅地址'),subscription]),saveButton,saved,
   E('p',{},'保存订阅只保存地址，不接管流量；应用、回滚、超时或恢复直连均保留已保存地址。90 秒确认只决定是否保留本次启用或分流更改。'),
   applyButton,feedback,pending,confirmButton,rollbackButton,disableButton,updateButton,
   E('p',{},dashboard),
   E('p',{},'面板中的 CM2012-DNS 为主 DoH 查询选择健康的代理节点，首选失效时自动切换，不代表全部上网流量。CM2012-DEFAULT 是普通流量的兜底出口，仅在订阅缺少兜底规则或明确引用时出现。'),
   E('p',{},'面板使用设备本地 HTTPS 证书和独立 API 密钥。密钥保存在设备私有配置和事务备份中，由管理员在设备本地读取；状态和诊断不显示密钥。')
  ]);
 },handleSaveApply:null,handleSave:null,handleReset:null
});
