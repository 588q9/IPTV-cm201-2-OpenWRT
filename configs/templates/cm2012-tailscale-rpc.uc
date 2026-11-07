'use strict';
import { readfile, mkdir, rmdir, stat, popen } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
const lib = loadfile('/usr/libexec/cm2012-tailscale-lib.uc')();
const lock = '/tmp/cm2012-wifi/apply.lock';
function pending() {
 for (let dir in ['/etc/cm2012-transaction','/etc/cm2012-proxy-transaction'])
  if (lib.pending({prepared:!!stat(dir),confirmed:!!stat(dir + '/confirmed')})) return true;
 return false;
}
function status() {
 let f = popen('/usr/libexec/cm2012-tailscale status 2>/dev/null');
 if (!f) return {error:'无法读取 Tailscale 状态。'};
 let value = null;
 try { value = json(f.read('all')); } catch (e) {}
 f.close(); return value || {error:'无法读取 Tailscale 状态。'};
}
return {cm2012_tailscale:{
 status:{call:status},
 apply:{args:{enabled:'',allowed_sources_json:'',management_ports_json:''},call:function(request) {
  let a = request.args, cfg;
  try { cfg = lib.validate({enabled:a.enabled,allowed_sources:json(a.allowed_sources_json || '[]'),
   management_ports:json(a.management_ports_json || '[]')}); }
  catch (e) { return {error:'授权来源和管理端口格式无效。'}; }
  if (cfg.error) return cfg;
  // A JSON string must not silently become a one-element UCI list.
  if (type(json(a.allowed_sources_json || '[]')) != 'array' || type(json(a.management_ports_json || '[]')) != 'array')
   return {error:'授权来源和管理端口必须是列表。'};
  mkdir('/tmp/cm2012-wifi',0700);
  if (!mkdir(lock,0700)) return {error:'网络配置操作忙，请稍后重试。'};
  let result = {}, c = cursor();
  try {
   if (pending()) result = {error:'网络或代理设置尚未确认，未应用 Tailscale。'};
   else {
    let b = connect(), lan = b ? b.call('network.interface.lan','status',{}) || {} : {};
    let plan = lib.render(cfg,lan);
    if (plan.error) result = plan;
    else if (!c.load('cm2012_tailscale') ||
     !c.set('cm2012_tailscale','main','enabled',cfg.enabled) ||
     !c.set('cm2012_tailscale','main','allowed_sources',cfg.allowed_sources) ||
     !c.set('cm2012_tailscale','main','management_ports',cfg.management_ports) ||
     !c.commit('cm2012_tailscale')) result = {error:'无法保存 Tailscale 配置。'};
   }
  } catch (e) { result = {error:'Tailscale 配置失败。'}; }
  if (!rmdir(lock)) return {error:'无法释放网络配置锁，请本地检查。'};
  if (result.error) return result;
  if (system('/usr/libexec/cm2012-tailscale reconcile >/dev/null 2>&1') != 0)
   return {error:'配置已保存，服务启动失败；请本地检查兼容性与网络状态。'};
  return {saved:true,enabled:cfg.enabled,verification:'未验收；登录后仍须控制台批准路由及蜂窝网访问验证。'};
 }}
}};
