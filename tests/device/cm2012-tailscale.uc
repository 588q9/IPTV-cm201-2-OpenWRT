// Native ucode/UCI contract. Only the supplied isolated /tmp config is edited.
'use strict';
import { cursor } from 'uci';
let root = ARGV[0];
if (!match(root,/^\/tmp\/cm2012-build-[a-z0-9]+(\/[a-z0-9-]+)?$/)) die('Isolated test directory required');
let lib = loadfile((ARGV[1] || '/usr/libexec') + '/cm2012-tailscale-lib.uc')();
let lan = {up:true,l3_device:'br-lan','ipv4-address':[{address:'192.168.50.1',mask:24}]};
let settings = {enabled:'1',allowed_sources:['100.80.0.2/32'],management_ports:['22','5252']};
let plan = lib.render(settings,lan);
if (plan.error || plan.lan_cidr != '192.168.50.0/24' || plan.daemon.acceptDNS || plan.daemon.acceptRoutes ||
 plan.daemon.netfilterMode != 'off' || plan.daemon.advertiseExitNode || plan.daemon.runSSHServer)
 die('Unsafe subnet preferences');
for (let sources in [['0.0.0.0/0'],['192.168.50.2/32'],['100.80.0.1/24']])
 if (!lib.validate({enabled:'1',allowed_sources:sources,management_ports:[]}).error) die('Unsafe source accepted');
let c = cursor(root + '/config',root + '/saved');
if (!c.load('firewall') || !c.set('firewall','tailscale_fixture_foreign','rule') ||
 !c.set('firewall','tailscale_fixture_foreign','name','isolated-user-rule') || !c.commit('firewall'))
 die('Isolated fixture preparation failed');
let result = lib.configure(c,plan);
if (result.error || !c.commit('firewall')) die('Isolated configuration failed');
c = cursor(root + '/config',root + '/saved');
if (lib.configure(c,plan).changed) die('Repeated reconcile changed firewall');
if (c.get('firewall','cm2012_ts_lan_0','src_ip') != '100.80.0.2/32' ||
 c.get('firewall','cm2012_ts_nat_0','dest_ip') != '192.168.50.0/24' ||
 c.get('firewall','cm2012_ts_nat_0','snat_ip') != '192.168.50.1') die('Scoped forwarding or SNAT failed');
if (lib.clear(c).error || !c.commit('firewall')) die('Isolated cleanup failed');
if (c.get('firewall','tailscale_fixture_foreign','name') != 'isolated-user-rule' || c.get('firewall','cm2012_ts_zone'))
 die('Cleanup changed foreign ownership');
printf('NATIVE_TAILSCALE_POLICY_OK\n');
