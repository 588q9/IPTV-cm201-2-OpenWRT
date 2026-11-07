const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const source=fs.readFileSync(path.join(__dirname,'../../configs/remote-proxy/cm2012-proxy-native.uc'),'utf8');
const match=source.match(/function geoip_ready\(\) \{([\s\S]*?)\n\}/);
assert.ok(match,'native adapter must verify local locked country MMDB');
const data='synthetic mmdb',hash=crypto.createHash('sha256').update(data).digest('hex');
const asset='/usr/share/cm2012/geodata/Country.mmdb',link='/etc/cm2012-proxy/Country.mmdb',manifest='/usr/share/cm2012/remote-assets.json';
function ready(edit={}) {
 const files={[asset]:data,[manifest]:JSON.stringify({'geoip-country-dbip':{uncompressed_size:data.length,uncompressed_sha256:hash}}),...edit.files};
 const stats={[asset]:{type:'file',size:data.length},[link]:{type:'link'},...edit.stats};
 return new Function('root','readfile','lstat','readlink','sha256','json','type','length','match','return function(){'+match[1]+'}')('/etc/cm2012-proxy',p=>files[p]??null,p=>stats[p]??null,p=>edit.target??asset,s=>crypto.createHash('sha256').update(s).digest('hex'),JSON.parse,v=>Array.isArray(v)?'array':v===null?'null':typeof v==='number'?'int':typeof v,v=>v?.length??0,(s,r)=>s.match(r))();
}
assert.equal(ready(),true);
for(const edit of [
 {target:'/tmp/other.mmdb'},{stats:{[link]:{type:'file'}}},{stats:{[asset]:{type:'link',size:data.length}}},
 {files:{[asset]:data+'corrupt'}},{files:{[asset]:null}},{files:{[manifest]:'invalid'}},
 {files:{[manifest]:'{}'}},{stats:{[asset]:{type:'file',size:data.length+1}}},
 {files:{[manifest]:JSON.stringify({'geoip-country-dbip':{uncompressed_size:1,uncompressed_sha256:hash}})}},
 {files:{[manifest]:JSON.stringify({'geoip-country-dbip':{uncompressed_size:data.length,uncompressed_sha256:'b'.repeat(64)}})}}
])assert.equal(ready(edit),false,JSON.stringify(edit));
console.log('GEOIP_LOCKED_NATIVE_ASSET_OK');
