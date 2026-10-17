// Native ARM/ucode and UCI contract checks in an isolated /tmp directory.
'use strict';
import { cursor } from 'uci';
import { readfile } from 'fs';
let root = ARGV[0];
if (!match(root,/^\/tmp\/cm2012-build-[a-z0-9]+(\/[a-z0-9-]+)?$/)) die('Isolated test directory required');
let lib = loadfile((ARGV[1] || '/usr/libexec') + '/cm2012-network-lib.uc')();
let route = {target:'192.168.60.0/24',gateway:'192.168.50.2',interface:'lan',metric:'10',enabled:'1'};
let args = {eth_role:'lan',uplink:'wifi',allow_upstream:'1',routes_json:sprintf('%J',[route]),
 upstream_sources_json:'["192.168.1.0/24"]'};
let cfg = lib.validate(args);
if (cfg.error) die(cfg.error);
let bad = [ {eth_role:'invalid'}, {eth_role:'lan',uplink:'ethernet'}, {routes_json:'{}'},
 {routes_json:'invalid'}, {upstream_sources_json:'["0.0.0.0/0"]'},
 {routes_json:sprintf('%J',[route,route])} ];
for (let edit in bad) {
 let a = {};
 for (let key, value in args) a[key] = value;
 for (let key, value in edit) a[key] = value;
 if (!lib.validate(a).error) die('Invalid input accepted');
}
let c = cursor(root + '/config',root + '/saved');
let result = lib.configure(c,cfg);
if (result.error) die(result.error);
if (!c.commit('network') || !c.commit('firewall') || !c.commit('cm2012')) die('Isolated commit failed');
c = cursor(root + '/config',root + '/saved');
if (c.get('network','lan','device') != 'br-lan' || c.get('network','wan','device')) die('LAN ownership failed');
if (c.get('network','user_route','target') != '10.23.0.0/16') die('User route lost');
if (length(lib.routes(c)) != 1) die('Managed route missing');
let table = 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n' +
 'br-lan\t003CA8C0\t0232A8C0\t0003\t0\t0\t10\t00FFFFFF\t0\t0\t0\n';
if (!lib.installed(route,'br-lan',table)) die('Kernel route matching failed');
args.eth_role = 'wan'; args.routes_json = '[]'; args.allow_upstream = '0';
result = lib.configure(c,lib.validate(args));
if (result.error) die(result.error);
if (c.get('network','lan','device') != 'ap0' || c.get('network','wan','device') != 'eth0') die('WAN ownership failed');
if (length(lib.routes(c)) != 0) die('Managed route not removed');
let before={lan:{'.type':'interface',device:'ap0'}};
let applied={lan:{'.type':'interface',device:'br-lan'},owned:{'.type':'route',target:'192.0.2.0/24'}};
let current={lan:{'.type':'interface',device:'br-lan'},owned:{'.type':'route',target:'192.0.2.0/24'},
 user:{'.type':'route',target:'10.23.0.0/16'}};
let changes=lib.restore_diff(before,applied,current);
if (length(changes)!=2 || changes[0].option!='device' || changes[0].value!='ap0' || !changes[1].remove)
 die('Three-way rollback did not preserve foreign changes');
let all={};c.foreach('network',null,function(s){all[s['.name']]=s;});
if (!all.lan || !all.user_route) die('UCI all-section enumeration failed');
printf('NATIVE_NETWORK_CONTRACT_OK (%d invalid cases)\n',length(bad));
