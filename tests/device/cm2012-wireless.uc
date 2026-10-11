'use strict';
let w = loadfile('/usr/libexec/cm2012-wireless-lib.uc')();
// 公共测试向量；不使用实机凭据。
if (w.psk('password', 'IEEE') != 'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e')
 die('WPA2 PSK 测试向量不匹配');
if (w.decode_ssid('WiFi\\xE4\\xB8\\xAD\\xE6\\x96\\x87\\\\\\"') != 'WiFi中文\\"')
 die('扫描 SSID 字节解码不匹配');
if (w.psk('pass"\\word#end', '测试"\\#') != '16347997bb4caf348fcaa8b93a0cd2ae91477060ff80c694bbb83a536b7e5a67')
 die('特殊字符 PSK 测试向量不匹配');
printf('CM_WIRELESS_ENCODING_OK\n');
