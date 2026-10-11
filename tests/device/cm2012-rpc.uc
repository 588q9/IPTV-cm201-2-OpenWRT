// 在 NAND 只读 RAM 系统运行：ucode /tmp/cm2012-rpc-test.uc
// 所有 apply 输入均应在提交前被拒绝；不输出配置或密码。
'use strict';
import { cursor } from 'uci';
import { mkdir, open, unlink, rmdir } from 'fs';
let plugin = loadfile('/usr/share/rpcd/ucode/cm2012')().cm2012;
let c = cursor(), before = c.get('cm2012', 'settings', 'uplink');
let cases = [
 { ssid: '' }, { ssid: '012345678901234567890123456789012' + '34' },
 { ssid: 'a\nb' }, { ssid: 'a\u0000b' }, { ssid: 'a\u007fb' },
 { key: 'short' }, { key: '1234567\r89' }, { channel: '14' },
 { uplink: 'automatic' }, { enabled: 'yes' },
 { upstream_key: 'short' }, { upstream_key: '1234567\n89' },
 { uplink: 'wifi', upstream_ssid: '' }
];
for (let edit in cases) {
 let args = { ssid: 'CM2012-validation', key: '', channel: '153', enabled: '1',
              uplink: 'ethernet', upstream_ssid: '', upstream_key: '' };
 for (let name in edit) args[name] = edit[name];
 let result = plugin.apply.call({ args });
 if (!result.error) die('无效输入没有被拒绝');
}
if (!plugin.confirm.call({ args: { token: '../../etc/config' } }).error)
 die('无效确认令牌没有被拒绝');
if (!plugin.rollback.call({ args: { token: '' } }).error)
 die('无效回滚令牌没有被拒绝');
let status = plugin.status.call();
if ('key' in status.config || 'upstream_key' in status.config || 'psk' in status.sta)
 die('状态泄露密码字段');
c = cursor();
if (before != c.get('cm2012', 'settings', 'uplink')) die('拒绝的请求改变配置');
// 模拟新管理地址/新浏览器的已登录状态读取；只创建临时事务文件，
// 不提交配置、不重启无线。已有真实事务时拒绝干扰。
let path = '/tmp/cm2012-wifi/pending';
if (!mkdir(path, 0700)) die('已有事务，不能运行隔离令牌测试');
let token = '12345678-1234-1234-1234-123456789abc';
let f = open(path + '/token', 'w', 0600); f.write(token); f.close();
let observed = plugin.status.call().pending_token;
unlink(path + '/token'); rmdir(path);
if (observed != token) die('新管理地址不能获取当前确认事务');
printf('CM_RPC_VALIDATION_OK (%d invalid apply cases)\n', length(cases));
