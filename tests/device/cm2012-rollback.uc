// Real libuci anonymous sections and three-way rollback, isolated from /etc/config.
'use strict';
import { cursor } from 'uci';
import { readfile, writefile, mkdir } from 'fs';
let root = ARGV[0];
if (!match(root, /^\/tmp\/cm2012-build-[a-z0-9]+\/rollback-test$/)) die('Isolated test directory required');
let lib = loadfile('/usr/libexec/cm2012-network-lib.uc')();
mkdir(root,0700);
for (let path in ['config','saved','journal','journal/applied','journal/save-before','journal/save-applied','journal/save-live'])
 mkdir(root + '/' + path,0700);
let files = {
 cm2012: "config settings 'settings'\n option uplink 'wifi'\n option eth_role 'wan'\n",
 network: "config interface 'lan'\n option device 'ap0'\n option ipaddr '192.168.50.1'\n option netmask '255.255.255.0'\nconfig interface 'wan'\n option device 'eth0'\nconfig route 'user_route'\n option target '10.23.0.0/16'\n option interface 'lan'\n",
 dhcp: "config dhcp 'lan'\n option start '100'\n",
 firewall: "config zone\n option name 'lan'\n list network 'lan'\nconfig zone\n option name 'wan'\n list network 'wwan'\n option masq '1'\n list masq_dest '!10.0.0.0/8'\nconfig rule 'user_rule'\n option name 'Existing rule'\n option target 'REJECT'\n"
};
for (let name,data in files) {
 if (!writefile(root + '/config/' + name,data) || !writefile(root + '/journal/' + name,data)) die('Fixture write failed');
}
let c=cursor(root + '/config',root + '/saved');
let cfg=lib.validate({eth_role:'lan',uplink:'wifi',allow_upstream:'1',
 routes_json:'[{"target":"192.168.60.0/24","gateway":"192.168.50.2","interface":"lan","metric":"10","enabled":"1"}]',
 upstream_sources_json:'["192.168.1.0/24"]'});
if (cfg.error || lib.configure(c,cfg).error) die('Fixture configuration failed');
for (let name in ['cm2012','network','firewall']) if (!c.commit(name)) die('Commit failed');
for (let name,data in files) writefile(root + '/journal/applied/' + name,readfile(root + '/config/' + name));
// Independent edits while confirmation is pending must survive rollback.
c=cursor(root + '/config',root + '/saved');
c.foreach('firewall','zone',function(s) {
 if (s.name=='wan') c.set('firewall',s['.name'],'masq_dest',['!10.0.0.0/8','!192.168.1.0/24','!172.16.0.0/12']);
});
c.set('network','later_user_route','route');
c.set('network','later_user_route','target','10.24.0.0/16');
c.set('network','later_user_route','interface','lan');
c.set('dhcp','lan','start','120');
for (let name in ['network','firewall','dhcp']) if (!c.commit(name)) die('Independent commit failed');
if (system('/usr/bin/ucode /usr/libexec/cm2012-network-restore.uc ' + root + '/journal ' + root + '/config') != 0)
 die('Production restore failed');
c=cursor(root + '/config',root + '/saved');
if (c.get('network','lan','device')!='ap0' || c.get('network','wan','device')!='eth0' ||
 c.get('network','cm2012_bridge') || length(lib.routes(c))) die('Network rollback failed');
if (!c.get('network','user_route') || !c.get('network','later_user_route') ||
 c.get('dhcp','lan','start')!='120' || !c.get('firewall','user_rule')) die('Independent changes lost');
let zones=0;
c.foreach('firewall','zone',function(s) {
 zones++;
 if (s.cm2012_zone_id || s.cm2012_masq_exempt) die('Transaction metadata not restored');
 if (s.name=='wan' && (length(s.masq_dest)!=2 || s.masq_dest[0]!='!10.0.0.0/8' || s.masq_dest[1]!='!172.16.0.0/12'))
  die('List rollback failed: ' + sprintf('%J',s.masq_dest));
});
if (zones!=2) die('Anonymous zones duplicated');
c.foreach('firewall','rule',function(s) {if (s.cm2012=='1') die('Owned rule not removed');});
printf('NATIVE_ANONYMOUS_LIST_ROLLBACK_OK\n');
