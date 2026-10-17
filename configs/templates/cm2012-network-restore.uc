'use strict';
import { cursor } from 'uci';
const root = ARGV[0], config_dir = ARGV[1];
const lib = loadfile((ARGV[2] || '/usr/libexec') + '/cm2012-network-lib.uc')();
let before = cursor(root,root + '/save-before'), applied = cursor(root + '/applied',root + '/save-applied');
let live = cursor(config_dir,root + '/save-live');
function sections(c,config) {
 if (!c.load(config)) die('Failed to read configuration; journal retained');
 let result = {}, anonymous = [];
 c.foreach(config,null,function(s) {
  if (s['.type'] == 'zone' && !s.cm2012_zone_id) push(anonymous,s);
  else {
   let key = lib.section_key(s);
   if (result[key]) die('Ambiguous section identity; journal retained');
   result[key] = s;
  }
 });
 for (let s in anonymous) {
  let key=lib.section_key(s);
  if (result[key]) die('Ambiguous zone identity; journal retained');
  result[key] = s;
 }
 return result;
}
let plans = [];
for (let config in ['cm2012','network','dhcp','firewall']) {
 let old=sections(before,config), changed=sections(applied,config), current=sections(live,config);
 let changes = lib.restore_diff(old,changed,current);
 push(plans,{config,old,changed,current,changes});
}
// Resolve every identity before any configuration is committed.
for (let plan in plans) {
 let config=plan.config, old=plan.old, changed=plan.changed, current=plan.current;
 for (let change in plan.changes) {
  let record=current[change.section] || old[change.section] || changed[change.section];
  let section=record ? record['.name'] : change.section;
  let ok = true;
  if (change.remove) { if (live.get(config,section) != null) ok=live.delete(config,section); }
  else if (change.option == '.type') {
   if (!change.value) die('Invalid section restoration; journal retained');
   ok=live.set(config,section,change.value);
  }
  else if (change.value == null) { if (live.get(config,section,change.option) != null) ok=live.delete(config,section,change.option); }
  else ok=live.set(config,section,change.option,change.value);
  if (!ok) die('Failed to restore UCI option; journal retained');
 }
}
for (let plan in plans) {
 if (!live.commit(plan.config)) die('Failed to restore configuration; journal retained');
}
