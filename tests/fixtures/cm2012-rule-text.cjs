// Exercise production text parsing and fetch dispatch at the filesystem/process boundary.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const production = name => fs.readFileSync(path.join(__dirname, '../../configs/remote-proxy', name), 'utf8');
const length = value => typeof value === 'string' ? Buffer.byteLength(value) : value?.length ?? Object.keys(value || {}).length;
const lib = new Function('type','length','match','split','index','int','push','join','json','sprintf','keys','die','lc','slice','trim','replace',
    production('cm2012-proxy-lib.uc').replaceAll('[[:cntrl:]]','[\\x00-\\x1f\\x7f]').replace(/for\(let (\w+) in /g,'for(let $1 of '))(
    value => Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value === 'number' ? 'int' : typeof value,
    length, (value, pattern) => String(value).match(pattern), (value, separator) => value.split(separator),
    (value, item) => value.indexOf(item), value => Number.parseInt(value, 10), (items, item) => items.push(item),
    (separator, items) => items.join(separator), JSON.parse,
    (format, value) => format === '%J' ? JSON.stringify(value) : format === '%c' ? String.fromCharCode(value) : format.replace('%d', String(value)),
    Object.keys, message => {throw new Error(message);}, value => value.toLowerCase(), (value, start) => value.slice(start),
    // Keep the BOM out of this whitespace adapter so the production BOM removal is exercised.
    value => value.replace(/^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g, ''),
    (value, pattern, replacement) => value.replace(pattern, replacement));

assert.equal(typeof lib.rule_text, 'function', 'text rule providers require the production parser');
assert.deepEqual(lib.rule_text('\ufeff# provider header\r\n\r\n  DOMAIN-SUFFIX,example.org  \r\n   # another comment\r\n IP-CIDR,203.0.113.0/24,no-resolve\nDOMAIN-KEYWORD,foo#bar\n'),
    {payload: ['DOMAIN-SUFFIX,example.org', 'IP-CIDR,203.0.113.0/24,no-resolve', 'DOMAIN-KEYWORD,foo#bar']});
assert.deepEqual(lib.rule_text('DOMAIN,one.example\nDOMAIN,two.example'),
    {payload: ['DOMAIN,one.example', 'DOMAIN,two.example']}, 'a final newline is optional');
for (const source of [null, {}, 42, '', ' \r\n # comments only\n', 'DOMAIN,bad\0.example', 'DOMAIN,bad\t.example',
    'DOMAIN,bad\r.example', 'DOMAIN,bad\x7f.example', 'x'.repeat(4096), 'x'.repeat(4194305),
    Array(65537).fill('DOMAIN,example.org').join('\n')]) {
    assert.throws(() => lib.rule_text(source), /^Error: Subscription rule text invalid$/, 'invalid source must be rejected');
}
assert.equal(lib.rule_text('x'.repeat(4095)).payload[0].length, 4095, 'a rule below the per-rule limit is accepted');
assert.equal(lib.rule_text(Array(65536).fill('DOMAIN,example.org').join('\n')).payload.length, 65536);
assert.deepEqual(lib.rule_text('#' + 'x'.repeat(4194283) + '\nDOMAIN,example.org\n'),
    {payload: ['DOMAIN,example.org']}, 'the source byte limit includes comments');
assert.throws(() => lib.rule_text('#' + '界'.repeat(1398102) + '\nDOMAIN,example.org'),
    /Subscription rule text invalid/, 'the source limit counts UTF-8 bytes');

const native = production('cm2012-proxy-native.uc');
const fetchBody = native.slice(native.indexOf('function fetch('), native.indexOf('function firewall('));
const root = '/etc/cm2012-proxy', state = '/tmp/cm2012-proxy', privateUrl = 'https://private.example/rules?token=never-log';
function download(source, options = {}) {
    const files = new Map(), commands = [];
    const fetch = new Function('root','state','lib','write','system','command','unlink','stat','die','readfile','length','json','index',
        fetchBody + ';return fetch;')(
        root, state, lib, (file, value) => files.set(file, value), command => {
            commands.push(command);
            if (command.includes('/usr/libexec/cm2012-proxy-fetch')) {
                files.set(root + '/download.yaml', source);
                return options.code || 0;
            }
            if (command.includes('/usr/bin/yq')) {
                files.set(root + '/download.json', '{"payload":["DOMAIN,yaml.example"]}');
                return 0;
            }
            throw new Error('unexpected command');
        }, args => args.join(' '), file => files.delete(file),
        file => files.has(file) ? {size: options.size ?? length(files.get(file))} : null,
        message => {throw new Error(message);}, file => files.get(file) ?? null, length, JSON.parse,
        (value, item) => value.indexOf(item));
    return {fetch, files, commands};
}
const text = download('\ufeff# text\r\n DOMAIN-SUFFIX,text.example \r\n');
assert.deepEqual(text.fetch(privateUrl, root, 'text'), {payload: ['DOMAIN-SUFFIX,text.example']});
assert.equal(text.commands.length, 1, 'text providers must bypass yq');
assert.equal(text.commands.some(command => command.includes(privateUrl)), false, 'private URLs stay out of process arguments');
assert.equal(text.files.size, 0, 'successful text parsing cleans the download and URL files');
for (const format of [undefined, 'yaml']) {
    const yaml = download('payload:\n  - DOMAIN,yaml.example\n');
    assert.deepEqual(yaml.fetch(privateUrl, root, format), {payload: ['DOMAIN,yaml.example']});
    assert.equal(yaml.commands.length, 2, 'default and explicit YAML providers still use yq');
    assert.equal(yaml.files.size, 0);
}
for (const [source, options, error] of [['# no rules\n', {}, /Subscription rule text invalid/],
    ['', {}, /Subscription rule text invalid/], ['DOMAIN,ok.example', {size: 4194305}, /Subscription download failed/],
    ['partial', {code: 35}, /Subscription TLS failed/]]) {
    const invalid = download(source, options);
    assert.throws(() => invalid.fetch(privateUrl, root, 'text'), error);
    assert.equal(invalid.files.size, 0, 'text failure must clean all download files');
    assert.equal(invalid.commands.length, 1, 'invalid text must not reach yq');
}
for (const format of ['mrs', '', 'TEXT', 1]) {
    const invalid = download('DOMAIN,ok.example');
    assert.throws(() => invalid.fetch(privateUrl, root, format), /Rule provider format unsupported/);
    assert.equal(invalid.commands.length, 0, 'unsupported formats fail before downloading');
    assert.equal(invalid.files.size, 0);
}
console.log('RULE_TEXT_PARSING_AND_NATIVE_FORMATS_OK');
