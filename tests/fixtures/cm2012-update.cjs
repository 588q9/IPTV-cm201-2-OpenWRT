// Run the production ucode installer against a real, isolated filesystem.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const policyCases = JSON.parse(fs.readFileSync(path.join(__dirname,'update-policy-cases.json'),'utf8'));
let source = fs.readFileSync(path.join(__dirname,'../../tools/cm2012/device/network-update.uc'),'utf8')
 .replace(/^import .*;$/gm,'')
 .replace(/exit\(0\)/g,'return')
 .replace(/\b0([0-7]{3,})\b/g,'0o$1')
 .replace(/for \(let (\w+),\s*(\w+) in ([^)]+)\)/g,'for (let [$1,$2] of Object.entries($3))')
 .replace(/for \(let (\w+) in /g,'for (let $1 of ')
 .replace(/(r\.kind|action|path) in \[([^\]]+)\]/g,'[$2].includes($1)');
const execute = new Function('ARGV','readfile','open','lstat','readlink','mkdir','rmdir','chmod','rename','unlink','symlink',
 'sha256','type','length','keys','match','index','split','pop','trim','json','sprintf','die','system','print','exit','substr','push','join',source);
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
function fixture() {
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'cm2012-update-')),stopped=[],modes=new Map(),links=new Map();
 const target=p=>path.join(root,p.replace(/^\//,''));
 const write=(p,data,mode=0o600)=>{fs.mkdirSync(path.dirname(target(p)),{recursive:true});fs.writeFileSync(target(p),data,{mode});modes.set(p,mode);};
 write('/etc/cm2012-internal-root','CM2012_INTERNAL_OPENWRT25\n');
 write('/tmp/cm2012-build-test/update-policy.json',fs.readFileSync(path.join(__dirname,'../../tools/cm2012/device/update-policy.json'),'utf8'));
 const file=data=>({kind:'file',mode:0o600,sha256:digest(data)});
 function run(action,files) {
  if(files) write('/tmp/cm2012-build-test/update.json',JSON.stringify({format:1,files}));
  try {execute([action,'/tmp/cm2012-build-test'],
   p=>{try{return fs.readFileSync(target(p),'utf8')}catch{return null}},
   (p,m,mode)=>{try{const fd=fs.openSync(target(p),'w',mode);modes.set(p,mode);return {write:v=>fs.writeSync(fd,v),close:()=>{fs.closeSync(fd);return true}}}catch{return null}},
   p=>{if(links.has(p))return {type:'link',mode:0o777};try{let s=fs.lstatSync(target(p));return {type:s.isSymbolicLink()?'link':s.isDirectory()?'directory':'file',mode:modes.get(p)??(s.mode&0o7777)}}catch{return null}},
   p=>links.get(p)??fs.readlinkSync(target(p)),
   (p,mode)=>{try{fs.mkdirSync(target(p),{mode});return true}catch{return false}},
   p=>{try{fs.rmdirSync(target(p));return true}catch{return false}},
   (p,mode)=>{try{fs.chmodSync(target(p),mode);modes.set(p,mode);return true}catch{return false}},
   (a,b)=>{try{fs.renameSync(target(a),target(b));modes.set(b,modes.get(a));modes.delete(a);return true}catch{return false}},
   p=>{try{fs.unlinkSync(target(p));return true}catch{return false}},
   (a,b)=>{try{fs.symlinkSync(a,target(b));return true}catch{return false}},
   digest,v=>v===null?'null':Array.isArray(v)?'array':Number.isInteger(v)?'int':typeof v,
   v=>typeof v==='string'||Array.isArray(v)?v.length:Object.keys(v||{}).length,Object.keys,(v,r)=>String(v).match(r),(v,n)=>v.indexOf(n),
   (v,s)=>v.split(s),a=>a.pop(),v=>v.trim(),JSON.parse,(s,v)=>JSON.stringify(v),
   m=>{throw new Error(m)},cmd=>{stopped.push(cmd);return 0},()=>{},code=>{throw {exit:code}},
   (s,a,n)=>s.substr(a,n),(a,v)=>a.push(v),(s,a)=>a.join(s));
  } catch(e) {if(e.exit===0)return;throw e;}
 }
 return {root,target,write,file,run,stopped,link(p,t){links.set(p,t)},close(){fs.rmSync(root,{recursive:true,force:true})}};
}
{
 const f=fixture();try {
  f.write('/usr/bin/original','old');f.write('/tmp/cm2012-build-test/payload/usr/bin/original','new');
  const records={'usr/bin/original':{before:f.file('old'),after:f.file('new')}};
  f.run('check',records);f.run('install');
  assert.equal(fs.readFileSync(f.target('/usr/bin/original'),'utf8'),'new');
  f.run('rollback');assert.equal(fs.readFileSync(f.target('/usr/bin/original'),'utf8'),'old');
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/usr/bin/original','old');f.write('/tmp/cm2012-build-test/payload/usr/bin/original','new');
  f.run('install',{'usr/bin/original':{before:f.file('old'),after:f.file('new')}});
  f.write('/usr/bin/original','user-edit');
  assert.throws(()=>f.run('rollback'),/后续修改/);
  assert.equal(fs.readFileSync(f.target('/usr/bin/original'),'utf8'),'user-edit');
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/outside/placeholder','existing');fs.mkdirSync(f.target('/usr'),{recursive:true});
  fs.symlinkSync(f.target('/outside'),f.target('/usr/bin'),'junction');
  f.write('/tmp/cm2012-build-test/payload/usr/bin/added','new');
  assert.throws(()=>f.run('check',{'usr/bin/added':{before:null,after:f.file('new')}}),/链接目录/);
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/usr/bin/original','old');f.write('/tmp/cm2012-build-test/payload/usr/bin/original','new');
  f.write('/tmp/cm2012-wifi/apply.lock/owner','busy');
  assert.throws(()=>f.run('install',{'usr/bin/original':{before:f.file('old'),after:f.file('new')}}),/操作忙/);
  assert.equal(fs.readFileSync(f.target('/usr/bin/original'),'utf8'),'old');
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/usr/bin/original','old');f.write('/tmp/cm2012-build-test/payload/usr/bin/original','new');
  f.write('/etc/init.d/cm2012-mihomo','service',0o755);f.write('/etc/init.d/cm2012-proxy-guard','guard',0o755);
  f.run('install',{'usr/bin/original':{before:f.file('old'),after:f.file('new')}});
  assert.ok(f.stopped.some(c=>c.includes('cm2012-proxy-guard start')));
  f.write('/etc/cm2012-network-update/backup/usr/bin/original','corrupt');
  assert.throws(()=>f.run('rollback'),/备份.*损坏/);
  assert.equal(fs.readFileSync(f.target('/usr/bin/original'),'utf8'),'new');
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/usr/bin/original','old');f.write('/tmp/cm2012-build-test/payload/usr/bin/original','new');
  f.write('/usr/bin/original.cm2012-update','unfinished');
  assert.throws(()=>f.run('check',{'usr/bin/original':{before:f.file('old'),after:f.file('new')}}),/临时文件冲突/);
  assert.equal(fs.readFileSync(f.target('/usr/bin/original'),'utf8'),'old');
 } finally {f.close()}
}
// Windows requires elevated privileges for file symlinks; Linux CI exercises
// their real install/rollback lifecycle, while manifest rejection runs below.
if (process.platform !== 'win32') {
 const f=fixture();try {
  const name='etc/cm2012-proxy/Country.mmdb',target='/usr/share/cm2012/geodata/Country.mmdb';
  f.write(target,'public-geodata');
  f.write('/tmp/cm2012-build-test/payload/etc/cm2012-proxy/placeholder','');
  fs.symlinkSync(target,f.target('/tmp/cm2012-build-test/payload/'+name));
  f.run('check',{[name]:{before:null,after:{kind:'link',mode:0o777,target}}});
  f.run('install');assert.equal(fs.readlinkSync(f.target('/'+name)),target);
  f.run('rollback');assert.throws(()=>fs.lstatSync(f.target('/'+name)),/ENOENT/);
 } finally {f.close()}
}
if (process.platform !== 'win32') {
 const f=fixture();try {
  const name='etc/cm2012-proxy/Country.mmdb',target='/usr/share/cm2012/geodata/Country.mmdb';
  f.write(target,'public-geodata');
  f.write('/'+name,'old-public-database');
  f.write('/tmp/cm2012-build-test/payload/etc/cm2012-proxy/placeholder','');
  fs.symlinkSync(target,f.target('/tmp/cm2012-build-test/payload/'+name));
  f.run('install',{[name]:{before:f.file('old-public-database'),after:{kind:'link',mode:0o777,target}}});
  assert.equal(fs.readlinkSync(f.target('/'+name)),target);
  f.run('rollback');assert.equal(fs.readFileSync(f.target('/'+name),'utf8'),'old-public-database');
 } finally {f.close()}
}
for(const [name,after] of [
 ['etc/cm2012-proxy/Country.mmdb',{kind:'file',mode:0o644,sha256:digest('invalid')}],
 ['etc/cm2012-proxy/Country.mmdb',{kind:'link',mode:0o777,target:'/etc/shadow'}],
 ['etc/cm2012-proxy/Country.mmdb',{kind:'link',mode:0o700,target:'/usr/share/cm2012/geodata/Country.mmdb'}],
 ...['Country.mmdb.other','secret','key.pem','cert.pem'].map(name=>['etc/cm2012-proxy/'+name,{kind:'link',mode:0o777,target:'/usr/share/cm2012/geodata/Country.mmdb'}])
]) {
 const f=fixture();try {
  assert.throws(()=>f.run('check',{[name]:{before:null,after}}),/更新路径越界|地理数据库链接非法|更新链接非法/);
 } finally {f.close()}
}
for(const [name,target] of [
 ['www/leak','/etc/shadow'], ['usr/bin/leak','/etc/config/cm2012_proxy'],
 ['usr/bin/leak','../../../etc/shadow'], ['usr/bin/leak','/usr/bin/missing'],
 ['usr/bin/leak','/usr/bin/indirect'], ['usr/bin/leak','/usr/bin/cycle'],
 ['usr/bin/leak','/usr/lib/private/file'], ['usr/bin/leak','/usr/lib/private/../public']
]) {
 const f=fixture();try {
  f.link('/usr/bin/indirect','/etc/shadow');f.link('/usr/bin/cycle','/usr/bin/leak');
  f.link('/usr/lib/private','/etc');
  f.write('/usr/lib/public','public');
  f.link('/tmp/cm2012-build-test/payload/'+name,target);
  assert.throws(()=>f.run('check',{[name]:{before:null,after:{kind:'link',mode:0o777,target}}}),/链接|不存在/);
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/usr/bin/tool','new');f.write('/etc/cm2012-network-update/prepared','1');
  f.write('/etc/cm2012-network-update/update.json',JSON.stringify({format:1,files:{'usr/bin/tool':{
   before:{kind:'link',mode:0o777,target:'/etc/shadow'},after:f.file('new')
  }}}));
  assert.throws(()=>f.run('rollback'),/链接/);
  assert.equal(fs.readFileSync(f.target('/usr/bin/tool'),'utf8'),'new');
 } finally {f.close()}
}
console.log('INCREMENTAL_INSTALL_ROLLBACK_OK');
for(const c of policyCases) {
 const f=fixture();try {
  const target=path.posix.resolve('/'+path.posix.dirname(c.name),c.target);
  if(c.allowed) f.write(target,'public-endpoint');
  f.link('/tmp/cm2012-build-test/payload/'+c.name,c.target);
  const run=()=>f.run('check',{[c.name]:{before:null,after:{kind:'link',mode:0o777,target:c.target}}});
  if(c.allowed) assert.doesNotThrow(run,JSON.stringify(c));
  else assert.throws(run,/链接|路径/,JSON.stringify(c));
 } finally {f.close()}
}
console.log('SHARED_UPDATE_POLICY_CONTRACT_OK');
for (const action of ['check','install']) {
 const f=fixture();try {
  f.write('/etc/config/network','live-config');
  f.write('/tmp/cm2012-build-test/payload/etc/config/network','replacement');
  assert.throws(()=>f.run(action,{'etc/config/network':{
   before:f.file('live-config'),after:f.file('replacement')
  }}),/现有配置/);
  assert.equal(fs.readFileSync(f.target('/etc/config/network'),'utf8'),'live-config');
  assert.equal(fs.existsSync(f.target('/etc/cm2012-network-update')),false);
  assert.equal(f.stopped.length,0);
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/tmp/cm2012-build-test/payload/etc/config/new_defaults','disabled');
  f.run('install',{'etc/config/new_defaults':{before:null,after:f.file('disabled')}});
  assert.equal(fs.readFileSync(f.target('/etc/config/new_defaults'),'utf8'),'disabled');
  f.run('rollback');
  assert.equal(fs.existsSync(f.target('/etc/config/new_defaults')),false);
 } finally {f.close()}
}
for (const action of ['check','install','rollback']) {
 const f=fixture();try {
  f.write('/usr/bin/endpoint','public');
  const link={kind:'link',mode:0o777,target:'missing/../endpoint'};
  if(action==='rollback') {
   f.write('/usr/bin/tool','current');f.write('/etc/cm2012-network-update/prepared','1');
   f.write('/etc/cm2012-network-update/update.json',JSON.stringify({format:1,files:{
    'usr/bin/tool':{before:link,after:f.file('current')}
   }}));
  } else f.link('/tmp/cm2012-build-test/payload/usr/bin/tool',link.target);
  const run=()=>action==='rollback'?f.run(action):f.run(action,{'usr/bin/tool':{before:null,after:link}});
  assert.throws(run,/链接.*目录.*不存在/);
  if(action==='rollback') {
   assert.equal(fs.readFileSync(f.target('/usr/bin/tool'),'utf8'),'current');
   assert.equal(fs.existsSync(f.target('/etc/cm2012-network-update/prepared')),true);
  } else assert.equal(fs.existsSync(f.target('/usr/bin/tool')),false);
  if(action==='install') assert.equal(fs.existsSync(f.target('/etc/cm2012-network-update')),false);
  assert.equal(f.stopped.length,0);
 } finally {f.close()}
}
for (const prospective of [false,true]) {
 const f=fixture();try {
  f.write('/usr/bin/endpoint','public');
  const link={kind:'link',mode:0o777,target:'directory/../endpoint'};
  f.link('/tmp/cm2012-build-test/payload/usr/bin/tool',link.target);
  const rows={'usr/bin/tool':{before:null,after:link}};
  if(prospective) {
   f.write('/tmp/cm2012-build-test/payload/usr/bin/directory/new','new');
   rows['usr/bin/directory/new']={before:null,after:f.file('new')};
  } else f.write('/usr/bin/directory/existing','existing');
  assert.doesNotThrow(()=>f.run('check',rows));
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.link('/usr/bin/alias','/usr/lib/libexample.so');
  f.link('/usr/lib/libexample.so','libexample.so.1');
  f.write('/usr/lib/libexample.so.1','public-library');
  f.link('/tmp/cm2012-build-test/payload/usr/bin/tool','alias');
  assert.doesNotThrow(()=>f.run('check',{'usr/bin/tool':{
   before:null,after:{kind:'link',mode:0o777,target:'alias'}
  }}));
 } finally {f.close()}
}
{
 const f=fixture();try {
  f.write('/usr/bin/tool','new');f.write('/etc/cm2012-network-update/prepared','1');
  f.link('/usr/bin/previous','/etc/shadow');
  f.write('/etc/cm2012-network-update/update.json',JSON.stringify({format:1,files:{'usr/bin/tool':{
   before:{kind:'link',mode:0o777,target:'previous'},after:f.file('new')
  }}}));
  assert.throws(()=>f.run('rollback'),/链接/);
  assert.equal(fs.readFileSync(f.target('/usr/bin/tool'),'utf8'),'new');
  assert.equal(f.stopped.length,0);
 } finally {f.close()}
}
