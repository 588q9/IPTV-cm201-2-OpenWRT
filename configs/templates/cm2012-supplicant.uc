'use strict';
import { cursor } from 'uci';
import { open, chmod } from 'fs';
let c = cursor(), w = loadfile('/usr/libexec/cm2012-wireless-lib.uc')();
let text = 'ctrl_interface=/var/run/wpa_supplicant\n';
let ssid = c.get('cm2012', 'sta', 'ssid');
if (c.get('cm2012', 'settings', 'uplink') == 'wifi' && ssid) {
 let key = c.get('cm2012', 'sta', 'key');
 text += sprintf('network={\n ssid=%s\n psk=%s\n key_mgmt=WPA-PSK\n proto=RSN\n pairwise=CCMP\n scan_ssid=1\n}\n',
                 hexenc(ssid), w.psk(key, ssid));
}
let path = '/tmp/cm2012-wifi/supplicant.conf', f = open(path, 'w', 0600);
if (!f) die('无法写入 supplicant 配置');
f.write(text); f.close(); chmod(path, 0600);
