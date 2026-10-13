'use strict';
import { cursor } from 'uci';
const root = ARGV[0], config_dir = ARGV[1];
const lib = loadfile('/usr/libexec/cm2012-network-lib.uc')();
let before = cursor(root,root + '/save-before'), applied = cursor(root + '/applied',root + '/save-applied');
let live = cursor(config_dir,root + '/save-live');
function sections(c,config) {
 let result = {}, anonymous = [];
 c.foreach(config,null,function(s) {
  if (s['.type'] == 'zone' && !s.cm2012_zone_id) push(anonymous,s);
  else result[lib.section_key(s)] = s;
 });
 for (let s in anonymous) {
  let key=lib.section_key(s);
  result[result[key] ? s['.name'] : key] = s;
 }
 return result;
}
for (let config in ['cm2012','network','dhcp','firewall']) {
 let old=sections(before,config), changed=sections(applied,config), current=sections(live,config);
 let changes = lib.restore_diff(old,changed,current);
 for (let change in changes) {
  let record=current[change.section] || old[change.section] || changed[change.section];
  let section=record ? record['.name'] : change.section;
  if (change.remove) live.delete(config,section);
  else if (change.option == '.type') live.set(config,section,change.value);
  else if (change.value == null) live.delete(config,section,change.option);
  else live.set(config,section,change.option,change.value);
 }
 if (!live.commit(config)) die('Failed to restore configuration');
}
