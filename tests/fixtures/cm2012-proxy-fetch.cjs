// Execute the native fetch adapter with only OS boundaries supplied by this test.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.join(__dirname, '../../configs/remote-proxy/cm2012-proxy-native.uc'), 'utf8');
const body = source.slice(source.indexOf('function fetch('), source.indexOf('function firewall('));
const root = '/etc/cm2012-proxy', state = '/tmp/cm2012-proxy';
const privateUrl = 'https://private.example/config?token=never-log';
for (const code of [35, 60, 124, 28, 0]) {
    const files = new Map();
    let command;
    const fetch = new Function('root','state','lib','write','system','command','unlink','stat','die','readfile','length','json',
        body + ';return fetch;')(
        root, state, {https: u => u.startsWith('https://')},
        (p,v) => files.set(p,v), cmd => { command=cmd; return code; },
        a => a.join(' '), p => files.delete(p), () => null,
        m => {throw new Error(m);}, () => 'null', v => v.length, JSON.parse);
    assert.throws(() => fetch(privateUrl, root), new RegExp(code===35?'Subscription TLS failed':
        code===60?'Subscription certificate failed':code===0?'Subscription YAML invalid':'Subscription timed out'));
    assert.equal(command.includes(privateUrl), false, 'private URL must not enter process arguments');
    assert.equal(files.size, 0, 'URL file and partial download must be cleaned on failure');
}
console.log('PROXY_FETCH_ERRORS_PRIVATE_AND_VISIBLE_OK');
const probeStart=source.indexOf('function external_health(');
assert.ok(probeStart>0,'native external DNS probe must exist');
const probeBody=source.slice(probeStart,source.indexOf('mkdir(root,0700)',probeStart));
function externalProbe(apiOk,answer,active={dns:{listen:'192.168.50.1:1053'}}) {
 const calls=[];
 const functions=new Function('root','readfile','json','split','match','run','capture',probeBody+';return {external_health,flush_dns};')(
  root,()=>JSON.stringify(active),JSON.parse,(a,b)=>a.split(b),(a,b)=>a.match(b),
  a=>{calls.push(a);return apiOk;},a=>{calls.push(a);return answer;});
 return {functions,calls};
}
const goodAnswer=';; rcode: NOERROR\n;; ANSWER SECTION:\nexample.com.\t60\tIN\tA\t93.184.216.34\n';
const probe=externalProbe(true,goodAnswer);assert.equal(probe.functions.external_health(),true);
assert.deepEqual(probe.calls[0],['timeout','5','/usr/libexec/cm2012-proxy-fetch','dns-probe']);
assert.deepEqual(probe.calls[1],['timeout','2','drill','-p','1053','@192.168.50.1','example.com','A']);
assert.equal(probe.functions.flush_dns(),true);
assert.deepEqual(probe.calls.at(-1),['timeout','3','/usr/libexec/cm2012-proxy-fetch','dns-flush']);
for(const answer of [';; rcode: SERVFAIL\n'+goodAnswer.split('\n').slice(1).join('\n'),';; rcode: NOERROR\n', ';; rcode: NOERROR\ncm2012-proxy-health.invalid. 60 IN A 198.18.0.1\n'])
 assert.equal(externalProbe(true,answer).functions.external_health(),false,'real public DNS answer required');
const unreachable=externalProbe(false,goodAnswer);assert.equal(unreachable.functions.external_health(),false);assert.equal(unreachable.calls.length,1);
for(const listen of ['127.0.0.1;reboot:1053','192.168.50.1:53','localhost:1053','999.1.1.1:1053'])
 assert.equal(externalProbe(true,goodAnswer,{dns:{listen}}).functions.external_health(),false,'invalid local listener must fail closed');
console.log('PROXY_NATIVE_EXTERNAL_DNS_OK');
