'use strict';
import { readfile, open, lstat, readlink, mkdir, rmdir, chmod, rename, unlink, symlink } from 'fs';
import { sha256 } from 'digest';

const action = ARGV[0] || 'check', base = ARGV[1];
const saved = '/etc/cm2012-network-update';
let policy;
function fail(message) { die(message + '\n'); }
function write(path, value, mode) {
 let f = open(path, 'w', mode);
 if (!f || f.write(value) != length(value) || !f.close() || !chmod(path,mode)) fail('无法保存更新文件');
}
function equal(a,b) {
 if (!a || !b) return a == b;
 return a.kind == b.kind && a.mode == b.mode &&
  (a.kind == 'link' ? a.target == b.target : a.sha256 == b.sha256);
}
function info(path) {
 let s = lstat(path);
 if (!s) return null;
 if (s.type == 'link') return {mode:s.mode & 07777,kind:'link',target:readlink(path)};
 if (s.type != 'file') fail('目标存在不支持的文件类型');
 return {mode:s.mode & 07777,kind:'file',sha256:sha256(readfile(path))};
}
function parents(path, create) {
 let current = '';
 let parts = split(path,'/'); pop(parts);
 for (let p in parts) {
  if (!p) continue;
  current += '/' + p;
  let s = lstat(current);
  if (s && s.type != 'directory') fail('拒绝通过链接目录安装');
  if (!s && create && (!mkdir(current,0755) || !chmod(current,0755))) fail('无法创建安装目录');
 }
}
function under(path, roots) {
 for (let root in roots) if (path == substr(root,0,length(root)-1) || index(path,root) == 0) return true;
 return false;
}
function allowed(path) {
 if (type(path) != 'string' || !length(path) || length(path) > policy.limits.path_bytes ||
     !match(path,/^[A-Za-z0-9_+.\/@~-]+$/) || index(path,'/') == 0) return false;
 for (let part in split(path,'/')) if (!length(part) || part == '.' || part == '..') return false;
 if (under(path,policy.forbidden_roots)) return false;
 for (let root in policy.allowed_roots) if (index(path,root) == 0) return true;
 return contains(policy.allowed_files,path);
}
function exact(object, fields) {
 if (type(object) != 'object' || length(keys(object)) != length(fields)) return false;
 for (let field in fields) if (!(field in object)) return false;
 return true;
}
function contains(values, wanted) {
 for (let value in values) if (value == wanted) return true;
 return false;
}
function target(name, value) {
 let exception = false;
 for (let path in policy.public_link_targets) {
  let source_parts = split(name,'/'); pop(source_parts);
  let target_parts = split(path,'/'), filename = pop(target_parts);
  if (value == '/' + path || (join('/',source_parts) == join('/',target_parts) && value == filename)) exception = true;
 }
 if (type(value) != 'string' || !length(value) || length(value) > policy.limits.path_bytes ||
     (!exception && !match(value,/^[A-Za-z0-9_+.\/@~-]+$/))) fail('更新链接非法');
 let parts = index(value,'/') == 0 ? [] : split(name,'/');
 if (index(value,'/') != 0) pop(parts);
 for (let part in split(value,'/')) {
  if (!length(part) || part == '.') continue;
  if (part == '..') { if (!length(parts)) fail('更新链接越界'); pop(parts); }
  else push(parts,part);
 }
 let path = join('/',parts);
 if ((!allowed(path) && !contains(policy.public_link_targets,path)) || under(path,policy.web_roots) ||
     (!under(path,policy.link_roots) && !contains(policy.link_files,path))) fail('更新链接目标不公开');
 return path;
}
function record(path, r, before) {
 if (type(r) != 'object' || type(r.mode) != 'int' || r.mode < 0 || r.mode > 0777) fail('更新类型或权限错误');
 if (r.kind == 'file') {
  if (!exact(r,['kind','mode','sha256']) || type(r.sha256) != 'string' || !match(r.sha256,/^[a-f0-9]{64}$/)) fail('更新摘要非法');
 } else if (r.kind == 'link') {
  if (!exact(r,['kind','mode','target']) || r.mode != 0777 || under(path,policy.web_roots) ||
      (!under(path,policy.link_roots) && !contains(policy.link_files,path) && !policy.fixed_links[path])) fail('更新链接非法');
  if (policy.fixed_links[path] && r.target != policy.fixed_links[path]) fail('地理数据库链接非法');
  target(path,r.target);
 } else fail('更新记录类型非法');
 if (!before && policy.fixed_links[path] && (r.kind != 'link' || r.target != policy.fixed_links[path])) fail('地理数据库链接非法');
}
function planned_directory(path, m, phase) {
 for (let name, row in m.files)
  if (row[phase] != null && index(name,path + '/') == 0) return true;
 return false;
}
function chain(path, r, m, phase) {
 let seen = {}; seen[path] = true;
 for (let hop = 0; hop < policy.limits.link_hops; hop++) {
  // Inspect the original traversal too: normalizing symlink/../x first is unsafe.
  let absolute = r.target;
  if (index(absolute,'/') != 0) {
   let directory = split(path,'/'); pop(directory);
   absolute = '/' + join('/',directory) + '/' + absolute;
  }
  parents(absolute,false);
  let walked = [], original = split(absolute,'/'); pop(original);
  for (let part in original) {
   if (!length(part) || part == '.') continue;
   if (part == '..') pop(walked); else push(walked,part);
   let parent = join('/',walked);
   if (m.files[parent]) fail('更新链接经过非目录');
   let state = lstat('/' + parent);
   if (state && state.type != 'directory') fail('更新链接经过非目录');
   if (!state && !planned_directory(parent,m,phase)) fail('更新链接遍历目录不存在');
  }
  let next = target(path,r.target);
  if (seen[next]) fail('更新链接循环');
  seen[next] = true;
  // A current parent symlink is never followed, even if another row replaces it.
  parents('/' + next,false);
  let prefix = '';
  let parts = split(next,'/'); pop(parts);
  for (let part in parts) {
   prefix += (length(prefix) ? '/' : '') + part;
   if (m.files[prefix]) fail('更新链接经过非目录');
  }
  if (m.files[next]) {
   r = m.files[next][phase];
   if (!r) fail('更新链接目标不存在');
  } else {
   let s = lstat('/' + next);
   if (!s) fail('更新链接目标不存在');
   if (s.type == 'directory' || s.type == 'file') return;
   if (s.type != 'link') fail('更新链接目标类型非法');
   r = info('/' + next);
  }
  if (r.kind != 'link') return;
  record(next,r,true);
  path = next;
 }
 fail('更新链接链过长');
}
function put(path, record, source) {
 parents(path,true);
 let tmp = path + '.cm2012-update';
 if (lstat(tmp)) fail('更新临时文件冲突');
 if (record.kind == 'link') {
  if (!symlink(record.target,tmp)) fail('无法写入链接');
 } else write(tmp,readfile(source),record.mode);
 if (!rename(tmp,path)) { unlink(tmp); fail('原子替换失败'); }
}
function manifest(directory) {
 let m;
 try { m = json(readfile(directory + '/update.json')); } catch(e) { fail('更新清单不可读'); }
 if (!exact(m,['format','files']) || type(m.format) != 'int' || m.format != 1 || type(m.files) != 'object' ||
     !length(keys(m.files)) || length(keys(m.files)) > policy.limits.files) fail('更新清单无效');
 for (let path, row in m.files) {
  if (!allowed(path)) fail('更新路径越界');
  if (!exact(row,['before','after'])) fail('更新记录非法');
  if (under(path,policy.preserve_existing_roots) && row.before != null) fail('增量更新必须保留现有配置');
  if (row.before != null) record(path,row.before,true);
  record(path,row.after,false);
 }
 return m;
}
function idle() {
 if (lstat('/etc/cm2012-transaction') || lstat('/etc/cm2012-proxy-transaction') ||
     lstat('/tmp/cm2012-wifi/pending')) fail('网络事务未结束，拒绝安装');
}
function verify(m,directory,rollback) {
 for (let path,row in m.files) {
  parents('/' + path,false);
  if (lstat('/' + path + '.cm2012-update')) fail('更新临时文件冲突，请先检查中断原因：' + path);
  let current = info('/' + path);
  // Check the complete future view before any backup, service stop or file write.
  let future = rollback ? row.before : row.after;
  if (future?.kind == 'link') chain(path,future,m,rollback ? 'before' : 'after');
  if (rollback) {
   if (!equal(current,row.before) && !equal(current,row.after)) fail('文件已有后续修改，撤销前请手动处理：' + path);
   if (row.before?.kind == 'file' && sha256(readfile(saved + '/backup/' + path) || '') != row.before.sha256)
    fail('备份文件损坏，拒绝撤销：' + path);
  } else {
   if (!equal(current,row.before)) fail('目标文件与增量基线不同：' + path);
   if (!equal(info(directory + '/payload/' + path),row.after)) fail('增量负载损坏：' + path);
  }
 }
}

if (trim(readfile('/etc/cm2012-internal-root') || '') != 'CM2012_INTERNAL_OPENWRT25') fail('目标不是已安装的 CM201-2');
if (!base || !match(base,/^\/tmp\/cm2012-build-[a-z0-9]+$/)) fail('仅允许本次 RAM 作业目录');
if (!(action in ['check','install','rollback'])) fail('只支持 check/install/rollback');
try { policy = json(readfile(base + '/update-policy.json')); } catch(e) { fail('更新政策不可读'); }
if (policy?.version != 1) fail('更新政策版本非法');
idle();
const writer_lock='/tmp/cm2012-wifi/apply.lock';
let locked=false;
if (action != 'check') {
 mkdir('/tmp/cm2012-wifi',0700);
 if (!mkdir(writer_lock,0700)) fail('网络配置操作忙，拒绝安装');
 locked=true;
}
try {
idle();
if (action == 'rollback') {
 let m = manifest(saved);
 if (!lstat(saved + '/prepared')) fail('备份尚未完成，不能自动撤销');
 verify(m,saved,true);
 // Stop only the newly installed services, before changing their executables.
 for (let service in ['cm2012-proxy-guard','cm2012-mihomo','cm2012-tailscale'])
  if (lstat('/etc/init.d/' + service) && system('CM2012_NETWORK_UPDATE_LOCK=1 /etc/init.d/' + service + ' stop >/dev/null 2>&1') != 0)
   fail('无法停止新增服务，保留文件和备份');
 for (let path,row in m.files) {
  if (equal(info('/' + path),row.before)) continue;
  if (!row.before) { if (!unlink('/' + path)) fail('移除更新文件失败'); }
  else put('/' + path,row.before,saved + '/backup/' + path);
 }
 write(saved + '/rolled-back','1\n',0600);
 system('sync');
 print('网络增量已撤销；备份保留在 ' + saved + '\n');
} else {
 let m = manifest(base);
 verify(m,base,false);
 if (action == 'check') { print('CM2012_NETWORK_UPDATE_CHECK_OK\n'); exit(0); }
 if (lstat(saved)) fail('已有增量备份，请先处理上一轮更新');
 if (!mkdir(saved,0700)) fail('无法创建持久备份');
 write(saved + '/update.json',sprintf('%J',m),0600);
 for (let path,row in m.files) {
  if (row.before?.kind == 'file') {
   parents(saved + '/backup/' + path,true);
   write(saved + '/backup/' + path,readfile('/' + path),0600);
  }
 }
 system('sync');
 write(saved + '/prepared','1\n',0600); system('sync');
 for (let path,row in m.files) put('/' + path,row.after,base + '/payload/' + path);
 write(saved + '/installed','1\n',0600); system('sync');
 print('CM2012_NETWORK_UPDATE_INSTALLED_DISABLED\n');
}
} catch(e) {
 if (locked) rmdir(writer_lock);
 die(e);
}
if (locked && !rmdir(writer_lock)) fail('无法释放安装锁');
if (action == 'install' && lstat('/etc/init.d/cm2012-proxy-guard')) {
 if (system('/etc/init.d/cm2012-proxy-guard start >/dev/null 2>&1') != 0)
  fail('文件已安装，守卫未能启动；请保持代理停用并修复');
}
if (action != 'check' && lstat('/etc/init.d/rpcd') && system('/etc/init.d/rpcd restart >/dev/null 2>&1') != 0)
 fail('文件操作已完成，rpcd 重启失败；请保持扩展停用并检查服务');
