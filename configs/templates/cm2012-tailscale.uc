'use strict';
import { readfile, open, mkdir, chmod, unlink, stat, popen } from 'fs';
import { cursor } from 'uci';
import { connect } from 'ubus';
const lib = loadfile('/usr/libexec/cm2012-tailscale-lib.uc')();
const directory = '/var/run/cm2012-tailscale';
function pending() {
 for (let dir in ['/etc/cm2012-transaction','/etc/cm2012-proxy-transaction'])
  if (lib.pending({prepared:!!stat(dir),confirmed:!!stat(dir + '/confirmed')})) return true;
 return false;
}
function settings(c) {
 if (!c.load('cm2012_tailscale')) die('无法读取 Tailscale 配置。');
 return {enabled:c.get('cm2012_tailscale','main','enabled') || '0',
  allowed_sources:c.get('cm2012_tailscale','main','allowed_sources') || [],
  management_ports:c.get('cm2012_tailscale','main','management_ports') || []};
}
function write(path, value) {
 let f = open(path,'w',0600);
 if (!f) die('无法创建 Tailscale 运行配置。');
 let written = f.write(value), closed = f.close();
 if (written != length(value) || !closed || !chmod(path,0600)) die('无法保存 Tailscale 运行配置。');
}
function clear(c) {
 unlink(directory + '/ready');
 unlink(directory + '/restart-required');
 let result = lib.clear(c);
 if (result.error) die(result.error);
 if (result.changed && (!c.commit('firewall') || system('/sbin/fw3 reload >/dev/null 2>&1') != 0))
  die('无法撤销 Tailscale 防火墙，请保持服务停用并本地修复。');
}
let action = ARGV[0] || 'status', c = cursor();
if (action == 'suspend' || action == 'clear') { clear(c); exit(0); }
let cfg = settings(c), b = connect(), lan = b ? b.call('network.interface.lan','status',{}) || {} : {};
if (action == 'status') {
 let backend = '', self = [], f = popen('/usr/sbin/tailscale --socket=/var/run/tailscale/tailscaled.sock status --json 2>/dev/null');
 if (f) { try { let s = json(f.read('all')); backend = s.BackendState || ''; self = s.TailscaleIPs || []; } catch (e) {} f.close(); }
 let plan = lib.render(cfg,lan);
 // Never return AuthURL, peers, identities, daemon output, or state file content.
 printf('%J\n',{enabled:cfg.enabled,state:lib.state(cfg.enabled,pending(),backend),backend,
  allowed_sources:cfg.allowed_sources,management_ports:cfg.management_ports,
  lan_cidr:plan.lan_cidr || '',lan_device:plan.lan_device || '',tailscale_ips:self,
  ready:!!stat(directory + '/ready'),error:plan.error || '',
  route_approval:'请在 Tailscale 控制台核对路由批准及访问策略；尚未完成端到端验收。'});
 exit(0);
}
if (action == 'check-login') {
 if (cfg.enabled != '1' || pending() || !stat('/var/run/tailscale/tailscaled.sock')) die('先启用服务，并等待网络事务完成后在本地登录。');
 exit(0);
}
if (action != 'prepare') die('未知 Tailscale 操作。');
if (pending() || cfg.enabled != '1') { clear(c); exit(0); }
let plan = lib.render(cfg,lan);
if (plan.error || !stat('/usr/sbin/tailscaled') || !stat('/usr/sbin/tailscale')) {
 clear(c); die(plan.error || '固定版本 Tailscale 程序尚未安装。');
}
mkdir(directory,0700);
if (!chmod(directory,0700)) { clear(c); die('无法保护运行目录。'); }
// Retain a running daemon when its launch preferences did not change.
let daemon = sprintf('%J\n',plan.daemon), changed = readfile(directory + '/daemon.json') != daemon;
if (changed) { write(directory + '/daemon.json',daemon); write(directory + '/restart-required','1\n'); }
let result = lib.configure(c,plan);
if (result.error || (result.changed && (!c.commit('firewall') || system('/sbin/fw3 reload >/dev/null 2>&1') != 0))) {
 c = cursor(); clear(c); die(result.error || '防火墙应用失败，已停止子网服务。');
}
write(directory + '/ready',plan.lan_cidr + '\n' + plan.lan_device + '\n');
