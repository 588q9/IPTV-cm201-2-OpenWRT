// Native RPC validation in isolated /tmp config/state; no live config writes.
'use strict';
import { cursor } from 'uci';
import { mkdir, open, unlink, rmdir, readfile, writefile, chmod } from 'fs';
let root=ARGV[0], source=ARGV[1] || '/usr/libexec';
if (!match(root,/^\/tmp\/cm2012-build-[a-z0-9]+\/rpc-test$/) || !match(source,/^\/[a-zA-Z0-9_\/-]+$/)) die('Isolated test directory required');
mkdir(root,0700);
for (let name in ['config','saved','state']) mkdir(root + '/' + name,0700);
let files={
 cm2012:"config settings 'settings'\n option uplink 'ethernet'\n option eth_role 'wan'\n option allow_upstream '0'\nconfig ap 'ap'\n option key 'fixture-password'\n option ssid 'fixture'\n option enabled '1'\nconfig sta 'sta'\n option key ''\n",
 network:"config interface 'lan'\n option ipaddr '192.168.50.1'\n option device 'ap0'\nconfig interface 'wan'\n option device 'eth0'\n",
 dhcp:"config dhcp 'lan'\n option start '100'\n",
 firewall:"config zone 'wan'\n option name 'wan'\n list network 'wan'\n"
};
for (let name,data in files) if (!writefile(root+'/config/'+name,data)) die('Fixture write failed');
// A bad request must stop before preparing a transaction, not merely fail at
// the redirected process boundary after validation has accidentally accepted it.
if (!writefile(root+'/network-boundary', '#!/bin/sh\n: > "'+root+'/boundary-reached"\nexit 1\n') ||
    !chmod(root+'/network-boundary',0700)) die('Boundary fixture write failed');
// Only redirect filesystem and process boundaries; execute shipped RPC/library code.
let code=readfile(source+'/cm2012-rpc.uc');
if (!code) die('Production RPC source unavailable');
code=replace(code,/cursor\(\)/g,"cursor('"+root+"/config','"+root+"/saved')");
code=replace(code,/\/tmp\/cm2012-wifi/g,root+'/state');
code=replace(code,/\/etc\/cm2012-transaction/g,root+'/journal');
code=replace(code,/\/usr\/libexec\/cm2012-network-lib.uc/g,source+'/cm2012-network-lib.uc');
code=replace(code,/\/usr\/libexec\/cm2012-wireless-lib.uc/g,source+'/cm2012-wireless-lib.uc');
code=replace(code,/\/usr\/libexec\/cm2012-network /g,root+'/network-boundary ');
code=replace(code,/\/usr\/libexec\/cm2012-wpa-control /g,'/bin/false ');
if (!writefile(root+'/rpc.uc',code)) die('Isolated RPC write failed');
let plugin = loadfile(root+'/rpc.uc')().cm2012;
let c=cursor(root+'/config',root+'/saved'), before=c.get('cm2012','settings','uplink');
let cases = [
 { ssid: '' }, { ssid: '012345678901234567890123456789012' + '34' },
 { ssid: 'a\nb' }, { ssid: 'a\u0000b' }, { ssid: 'a\u007fb' },
 { key: 'short' }, { key: '1234567\r89' }, { channel: '14' },
 { uplink: 'automatic' }, { enabled: 'yes' },
 { upstream_key: 'short' }, { upstream_key: '1234567\n89' },
 { uplink: 'wifi', upstream_ssid: '' },
 { eth_role: 'invalid' }, { eth_role: 'lan', uplink: 'ethernet' },
 { routes_json: '{}' }, { routes_json: 'invalid' },
 { allow_upstream: '1', upstream_sources_json: '[]' },
 { upstream_sources_json: '["0.0.0.0/0"]' }
];
for (let edit in cases) {
 let args = { ssid: 'CM2012-validation', key: '', channel: '153', enabled: '1',
              uplink: 'ethernet', upstream_ssid: '', upstream_key: '',
              eth_role:'wan',allow_upstream:'0',routes_json:'[]',upstream_sources_json:'[]' };
 for (let name in edit) args[name] = edit[name];
 let result = plugin.apply.call({ args });
 if (!result.error) die('无效输入没有被拒绝');
 if (readfile(root+'/boundary-reached') != null) die('无效输入在验证后执行了事务操作');
}
if (!plugin.confirm.call({ args: { token: '../../etc/config' } }).error)
 die('无效确认令牌没有被拒绝');
if (!plugin.rollback.call({ args: { token: '' } }).error)
 die('无效回滚令牌没有被拒绝');
let status = plugin.status.call();
if ('key' in status.config || 'upstream_key' in status.config || 'psk' in status.sta)
 die('状态泄露密码字段');
c = cursor(root+'/config',root+'/saved');
if (before != c.get('cm2012', 'settings', 'uplink')) die('拒绝的请求改变配置');
// 模拟新管理地址/新浏览器的已登录状态读取；只创建临时事务文件，
// 不提交配置、不重启无线。已有真实事务时拒绝干扰。
let path = root+'/state/pending';
if (!mkdir(path, 0700)) die('已有事务，不能运行隔离令牌测试');
let token = '12345678-1234-1234-1234-123456789abc';
let f = open(path + '/token', 'w', 0600); f.write(token); f.close();
let observed = plugin.status.call().pending_token;
let busy = plugin.apply.call({args:{ssid:'CM2012-validation',key:'',channel:'153',enabled:'1',
 uplink:'ethernet',upstream_ssid:'',upstream_key:'',eth_role:'wan',allow_upstream:'0',
 routes_json:'[]',upstream_sources_json:'[]'}});
unlink(path + '/token'); rmdir(path);
if (observed != token) die('新管理地址不能获取当前确认事务');
if (!busy.error || index(busy.error,'已有设置')<0) die('并发事务没有被拒绝');
printf('CM_RPC_VALIDATION_OK (%d invalid apply cases)\n', length(cases));
