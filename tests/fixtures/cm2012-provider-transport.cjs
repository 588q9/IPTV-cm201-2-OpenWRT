// Exercise the production GitHub mapping and native rule transport/cache at OS boundaries.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const production = name => fs.readFileSync(path.join(__dirname, '../../configs/remote-proxy', name), 'utf8');
const length = value => typeof value === 'string' ? Buffer.byteLength(value) : value?.length ?? Object.keys(value || {}).length;
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');
const globals = {
    type: value => Array.isArray(value) ? 'array' : value === null ? 'null' : Number.isInteger(value) ? 'int' : typeof value,
    length, match: (value, pattern) => String(value).match(pattern), split: (value, separator) => value.split(separator),
    index: (value, item) => value.indexOf(item), int: value => Number.parseInt(value, 10), push: (items, item) => items.push(item),
    join: (separator, items) => items.join(separator), json: JSON.parse,
    sprintf: (format, value) => format === '%J' ? JSON.stringify(value) : format === '%c' ? String.fromCharCode(value) : format.replace('%d', String(value)),
    keys: Object.keys, die: message => {throw new Error(message);}, lc: value => value.toLowerCase(),
    slice: (value, start, end) => value.slice(start, end),
    trim: value => value.replace(/^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g, ''),
    replace: (value, pattern, replacement) => value.replace(pattern, replacement), sha256,
};
const translate = source => source.replaceAll('[[:cntrl:]]', '[\\x00-\\x1f\\x7f]')
    .replace(/for\(let (\w+) in /g, 'for(let $1 of ').replace(/\b0([0-7]{3})\b/g, '0o$1');
const lib = new Function(...Object.keys(globals), translate(production('cm2012-proxy-lib.uc')))(...Object.values(globals));
assert.equal(typeof lib.github_rule_api, 'function', 'GitHub rule fallback requires the production URL mapper');
const raw = 'https://raw.githubusercontent.com/Example-Org/Repo.Name/Main_1/rules/Classical.list';
const api = 'https://api.github.com/repos/Example-Org/Repo.Name/contents/rules/Classical.list?ref=Main_1';
assert.equal(lib.github_rule_api(raw), api);
for (const encoded of ['%43lassical', '%E8%A7%84%E5%88%99', 'Classical%20Rules', 'Classical%2elist']) {
    const url = raw.replace('Classical', encoded);
    assert.equal(lib.github_rule_api(url), api.replace('Classical', encoded), 'encoded filenames must preserve original URL bytes');
    const explicit = url.replace('/Main_1/', '/refs/heads/Main_1/');
    assert.equal(lib.github_rule_api(explicit), api.replace('Classical', encoded).replace('?ref=Main_1', '?ref=refs%2Fheads%2FMain_1'));
}
for (const [ref, namespace] of [['Main_1', 'heads'], ['V1.0-Tag', 'tags']]) {
    assert.equal(lib.github_rule_api(raw.replace('/Main_1/', '/refs/' + namespace + '/' + ref + '/')),
        'https://api.github.com/repos/Example-Org/Repo.Name/contents/rules/Classical.list?ref=refs%2F' + namespace + '%2F' + ref,
        'explicit Git refs must preserve their namespace and extract only the file path');
}
for (const url of [null, 42, raw + '?token=private', raw + '#fragment', raw.replace('https:', 'http:'),
    raw.replace('raw.githubusercontent.com', 'raw.githubusercontent.com.evil.test'), raw.replace('raw.githubusercontent.com', 'user@raw.githubusercontent.com'),
    raw.replace('.com/', '.com:443/'), raw.replace('Classical', '规则'),
    raw.replace('/Main_1/', '/./'), raw.replace('/Main_1/', '/../'), raw.replace('/Repo.Name/', '/../'),
    raw.replace('/Example-Org/', '/../'), raw.replace('/rules/', '/rules//'), raw.replace('/rules/', '/rules/../'),
    raw.replace('/rules/', '/rules/./'), raw + '/', 'https://raw.githubusercontent.com/owner/repo/ref',
    'https://raw.githubusercontent.com/' + 'x'.repeat(129) + '/repo/ref/file']) {
    assert.equal(lib.github_rule_api(url), null, String(url));
}
for (const suffix of ['refs', 'refs/heads', 'refs/heads/Main', 'refs/tags/Tag', 'refs/notheads/Main/file',
    'refs/HEADS/Main/file', 'refs/pull/12/file', 'refs/heads/./file', 'refs/tags/../file',
    'refs/heads/Main/../file', 'refs/tags/Tag//file', 'refs/heads/Main/file?token=private',
    'refs/tags/Tag/file#fragment', 'refs/heads/分支/file', 'refs/heads/' + 'x'.repeat(129) + '/file']) {
    assert.equal(lib.github_rule_api('https://raw.githubusercontent.com/Example-Org/Repo.Name/' + suffix), null, suffix);
}
for (const encoded of ['%', '%2', '%gg', '%00', '%09', '%1f', '%7f', '%2F', '%2f', '%5C', '%3f', '%23', '%25',
    '%252e', '%2e', '%2e%2e', '.%2E', '%2E.']) {
    assert.equal(lib.github_rule_api(raw.replace('rules/', encoded + '/')), null, 'reject encoded structure: ' + encoded);
}
for (const part of ['Example-Org', 'Repo.Name', 'Main_1']) {
    assert.equal(lib.github_rule_api(raw.replace(part, '%41' + part)), null, 'encoded owner/repository/ref must remain forbidden');
}
for (const filename of ['%41'.repeat(256), 'file%00name', 'file%7fname', 'file%2fname', 'file%5cname', 'file%3fname', 'file%23name', 'file%25name']) {
    assert.equal(lib.github_rule_api(raw.replace('Classical.list', filename)), null, 'reject unsafe encoded filename');
}

const nativeSource = production('cm2012-proxy-native.uc');
const configBody = nativeSource.slice(nativeSource.indexOf('function config('), nativeSource.indexOf('function save('));
for (const [setting, expected] of [[undefined, false], ['0', false], ['1', true], ['true', false], ['', false]]) {
    const config = new Function('cursor', 'die', configBody + ';return config;')(
        () => ({load: () => true, get: (name, section, option) => option === 'github_rule_api' ? setting : undefined}), globals.die);
    assert.equal(config().github_rule_api, expected, 'API metadata egress requires an explicit UCI opt-in');
}
assert.ok(nativeSource.includes('function provider_cache_now('), 'the native bounded cache helpers are required');
const nativeBody = nativeSource.slice(nativeSource.indexOf('function write('), nativeSource.indexOf('function remove_tree(')) +
    nativeSource.slice(nativeSource.indexOf('function provider_cache_now('), nativeSource.indexOf('function firewall('));
const root = '/etc/cm2012-proxy', state = '/tmp/cm2012-proxy', directory = state + '/provider-cache';
const body = 'DOMAIN-SUFFIX,example.org\n';
function harness(responses = []) {
    const files = new Map(), commands = [], requests = [], chmods = [], removed = [];
    let clock = 100, parses = 0, cacheWritable = true, peakCacheBytes = 0, apiEnabled = true;
    const cacheBytes = () => [...files].filter(([file]) => file.startsWith(directory + '/')).reduce((sum, [, entry]) => sum + length(entry.data || ''), 0);
    const put = (file, data, type = 'file', mode = 0o600) => files.set(file, {data, type, mode});
    const readfile = file => file === '/proc/uptime' ? clock + '.25 1.0' : files.get(file)?.data ?? null;
    const lstat = file => {const entry = files.get(file); return entry ? {type: entry.type, mode: entry.mode, size: length(entry.data || '')} : null;};
    const runtime = {...globals, root, state, lib, readfile, lstat, stat: lstat,
        config: () => ({github_rule_api: apiEnabled}),
        open: (file, mode, permission) => {
            if (!cacheWritable && file.startsWith(directory + '/')) return null;
            if (files.has(file) && files.get(file).type !== 'file') return null;
            return {write: data => {put(file, data, 'file', permission); peakCacheBytes = Math.max(peakCacheBytes, cacheBytes()); return length(data);}, close: () => true};
        }, mkdir: (file, mode) => {if (files.has(file)) return false; put(file, '', 'directory', mode); return true;},
        chmod: (file, mode) => {chmods.push({file, mode}); if (!files.has(file)) return false; files.get(file).mode = mode; return true;},
        rename: (from, to) => {if (!files.has(from)) return false; files.set(to, files.get(from)); files.delete(from); return true;},
        rmdir: file => {if (files.get(file)?.type !== 'directory' || [...files.keys()].some(item => item.startsWith(file + '/'))) return false; files.delete(file); return true;},
        unlink: file => {removed.push(file); if (files.get(file)?.type === 'directory') return false; files.delete(file); return true;},
        lsdir: file => [...files.keys()].filter(item => item.startsWith(file + '/') && !item.slice(file.length + 1).includes('/')).map(item => item.slice(file.length + 1)),
        command: args => JSON.stringify(args),
        system: command => {
            commands.push(command);
            if (command.includes('/usr/libexec/cm2012-proxy-fetch')) {
                const args = JSON.parse(command.slice(0, command.indexOf(']') + 1));
                requests.push({url: readfile(args[3]), args});
                const response = responses.length ? responses.shift() : {code: 0, body};
                put(args[4], response.body ?? 'partial');
                return response.code;
            }
            if (command.includes('/usr/bin/yq')) {
                parses++;
                try {put(root + '/download.json', JSON.stringify(JSON.parse(readfile(root + '/download.yaml')))); return 0;}
                catch (_) {return 1;}
            }
            throw Error('unexpected command');
        },
    };
    const fetch = new Function(...Object.keys(runtime), translate(nativeBody) + ';return fetch;')(...Object.values(runtime));
    const cacheEntries = () => [...files.keys()].filter(file => file.startsWith(directory + '/') && file.endsWith('.body'));
    const cleanWork = () => assert.ok(![...files.keys()].some(file => /^\/etc\/cm2012-proxy\/(subscription\.url|download\.(yaml|json))(\.new)?$/.test(file)), 'work files must be cleaned');
    return {files, commands, requests, chmods, removed, put, fetch, cacheEntries, cleanWork,
        get clock() {return clock;}, set clock(value) {clock = value;},
        get parses() {return parses;}, get peakCacheBytes() {return peakCacheBytes;}, set cacheWritable(value) {cacheWritable = value;},
        set apiEnabled(value) {apiEnabled = value;}};
}
for (const code of [35, 28, 124]) for (const enabled of [false, undefined, null, '1', 1]) {
    const disabled = harness([{code}, {code: 0, body}]); disabled.apiEnabled = enabled;
    const mapper = lib.github_rule_api; lib.github_rule_api = () => {throw Error('disabled mapper must not run');};
    try {assert.throws(() => disabled.fetch(raw, root, 'text', 'rule'), code === 35 ? /Subscription TLS failed/ : /Subscription timed out/);}
    finally {lib.github_rule_api = mapper;}
    assert.equal(disabled.requests.length, 1, 'disabled API mode permits only the original rule request');
    assert.equal(disabled.cacheEntries().length, 0);
    assert.ok(!disabled.files.has(directory) && !disabled.files.has(state + '/provider-cache.lock'), 'disabled API mode must bypass all cache access');
    disabled.cleanWork();
}
for (const code of [28, 124]) {
    const timed = harness([{code}, {code: 0, body}]);
    assert.deepEqual(timed.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']});
    assert.deepEqual(timed.requests.map(request => request.url), [raw, api], 'mapped GitHub rule timeouts may retry the identical official file');
    assert.equal(timed.requests[1].args.at(-1), 'github-rule'); timed.cleanWork();
    const failed = harness([{code: 35}, {code}]);
    assert.throws(() => failed.fetch(raw, root, 'text', 'rule'), /Subscription timed out/);
    assert.equal(failed.requests.length, 2, 'an API timeout must not trigger more retries'); failed.cleanWork();
}
const fallback = harness([{code: 35}, {code: 0, body}]);
assert.deepEqual(fallback.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']});
assert.deepEqual(fallback.requests.map(request => request.url), [raw, api]);
assert.equal(fallback.requests[0].args.length, 6, 'the normal helper invocation remains unchanged');
assert.equal(fallback.requests[1].args.at(-1), 'github-rule', 'only the API retry requests the fixed GitHub header mode');
fallback.cleanWork();
assert.equal(fallback.cacheEntries().length, 1);
assert.deepEqual(fallback.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']});
assert.equal(fallback.requests.length, 2, 'a valid cached rule body avoids another download');
assert.equal(fallback.files.get(directory).mode, 0o700);
assert.ok([...fallback.files].filter(([file]) => file.startsWith(directory + '/')).every(([file, entry]) =>
    /^[a-f0-9]{64}\.(body|meta)$/.test(file.slice(directory.length + 1)) && entry.mode === 0o600));
assert.ok(fallback.commands.every(command => !command.includes(raw) && !command.includes(api)), 'URLs must stay out of process arguments');
assert.ok([...fallback.files].every(([file, entry]) => !file.includes('Example-Org') && !String(entry.data).includes('raw.githubusercontent.com') && !String(entry.data).includes(api)), 'cache names and metadata must not retain URLs');
fallback.apiEnabled = false;
fallback.fetch(raw, root, 'text', 'rule');
assert.equal(fallback.requests.length, 3, 'turning the opt-in off also bypasses existing cached bodies');
assert.equal(fallback.requests.at(-1).args.length, 6);

for (const [code, error] of [[60, /Subscription certificate failed/], [22, /Subscription HTTP failed/], [6, /Subscription DNS failed/], [23, /Subscription download failed/]]) {
    const failed = harness([{code}]);
    assert.throws(() => failed.fetch(raw, root, 'text', 'rule'), error);
    assert.equal(failed.requests.length, 1, 'certificate, HTTP, DNS and unrelated errors must not use the API fallback');
    assert.equal(failed.cacheEntries().length, 0); failed.cleanWork();
}
for (const code of [35, 28, 124]) for (const [url, purpose] of [[raw, undefined], [raw, 'proxy'], [raw + '?token=private', 'rule'], [raw.replace('raw.githubusercontent.com', 'example.org'), 'rule']]) {
    const failed = harness([{code}]);
    assert.throws(() => failed.fetch(url, root, 'text', purpose), code === 35 ? /Subscription TLS failed/ : /Subscription timed out/);
    assert.equal(failed.requests.length, 1); assert.equal(failed.cacheEntries().length, 0); failed.cleanWork();
}
const limited = harness([{code: 35}, {code: 69}]);
assert.throws(() => limited.fetch(raw, root, 'text', 'rule'), /GitHub rule API rate limited/);
assert.equal(limited.requests.length, 2); limited.cleanWork();

const expired = harness(); expired.fetch(raw, root, 'text', 'rule'); expired.clock += 3600;
expired.fetch(raw, root, 'text', 'rule');
assert.equal(expired.requests.length, 2, 'cache TTL expires at one hour');
expired.clock += 3600;
// A stale cache must never hide a fresh transport error.
const expiredKey = sha256('text\n' + raw);
expired.put(directory + '/' + expiredKey + '.body', 'not a rule');
expired.fetch(raw, root, 'text', 'rule');
assert.equal(expired.requests.length, 3);
const noStale = harness([{code: 0, body}, {code: 35}, {code: 69}]);
noStale.fetch(raw, root, 'text', 'rule'); noStale.clock += 3600;
assert.throws(() => noStale.fetch(raw, root, 'text', 'rule'), /GitHub rule API rate limited/);
assert.equal(noStale.cacheEntries().length, 0); noStale.cleanWork();

for (const corrupt of ['hash', 'metadata', 'hash-type', 'future', 'link', 'partial', 'parser']) {
    const cache = harness(); cache.fetch(raw, root, 'text', 'rule');
    const prefix = directory + '/' + sha256('text\n' + raw), metadata = JSON.parse(cache.files.get(prefix + '.meta').data);
    if (corrupt === 'hash') cache.put(prefix + '.body', 'modified');
    if (corrupt === 'metadata') cache.put(prefix + '.meta', '{invalid');
    if (corrupt === 'hash-type') {metadata.hash = [metadata.hash]; cache.put(prefix + '.meta', JSON.stringify(metadata));}
    if (corrupt === 'future') {metadata.created = cache.clock + 1; cache.put(prefix + '.meta', JSON.stringify(metadata));}
    if (corrupt === 'link') cache.put(prefix + '.body', '/outside/private', 'link');
    if (corrupt === 'partial') cache.put(prefix + '.body.new', 'partial');
    if (corrupt === 'parser') {cache.put(prefix + '.body', '# empty'); metadata.size = 7; metadata.hash = sha256('# empty'); cache.put(prefix + '.meta', JSON.stringify(metadata));}
    assert.deepEqual(cache.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']}, corrupt);
    assert.equal(cache.requests.length, 2, corrupt + ' cache must refetch');
    assert.ok(cache.removed.every(file => file.startsWith(root + '/') || new RegExp('^' + directory + '/[a-f0-9]{64}\\.(body|meta)(\\.new)?$').test(file)), 'cache cleanup stays within owned strict names');
    cache.cleanWork();
}

const yamlBody = '{"payload":["DOMAIN,yaml.example"]}';
const yaml = harness([{code: 0, body: yamlBody}]);
assert.deepEqual(yaml.fetch(raw, root, 'yaml', 'rule'), {payload: ['DOMAIN,yaml.example']});
assert.deepEqual(yaml.fetch(raw, root, 'yaml', 'rule'), {payload: ['DOMAIN,yaml.example']});
assert.equal(yaml.requests.length, 1); assert.equal(yaml.parses, 2, 'cached YAML is parsed again');
yaml.fetch(raw, root, 'text', 'rule');
assert.equal(yaml.requests.length, 2, 'format participates in the cache identity');

const entries = harness();
for (let index = 0; index < 65; index++) {entries.clock++; entries.fetch(raw + index, root, 'text', 'rule');}
assert.equal(entries.cacheEntries().length, 64, 'cache entry count stays bounded');
assert.ok(!entries.files.has(directory + '/' + sha256('text\n' + raw + '0') + '.body'), 'oldest entries are evicted first');
const largeBody = '#' + 'x'.repeat(3 * 1024 * 1024 - 1 - body.length) + '\n' + body;
const capacity = harness(Array.from({length: 6}, () => ({code: 0, body: largeBody})));
for (let index = 0; index < 6; index++) {capacity.clock++; capacity.fetch(raw + index, root, 'text', 'rule');}
const cacheBytes = [...capacity.files].filter(([file]) => file.startsWith(directory + '/')).reduce((sum, [, entry]) => sum + length(entry.data), 0);
assert.ok(cacheBytes <= 16 * 1024 * 1024, 'the cache size cap includes raw bodies and metadata');
assert.equal(capacity.cacheEntries().length, 5);
assert.ok(capacity.peakCacheBytes <= 16 * 1024 * 1024, 'atomic temporary files stay inside the total byte cap');

const unavailable = harness(); unavailable.cacheWritable = false;
assert.deepEqual(unavailable.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']}, 'cache write failure cannot fail a valid download');
assert.equal(unavailable.cacheEntries().length, 0); unavailable.cleanWork();
assert.ok(![...unavailable.files.keys()].some(file => file.endsWith('.new')), 'partial atomic cache writes are removed');
const foreign = harness(); foreign.put(directory, '', 'directory', 0o700); foreign.put(directory + '/foreign-file', 'leave intact');
assert.deepEqual(foreign.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']});
assert.equal(foreign.files.get(directory + '/foreign-file').data, 'leave intact');
assert.equal(foreign.cacheEntries().length, 0, 'unknown entries make caching unsafe without deleting foreign paths');
const newlineName = harness(); newlineName.put(directory, '', 'directory', 0o700);
newlineName.put(directory + '/' + 'a'.repeat(64) + '.body\n', 'leave intact');
newlineName.fetch(raw, root, 'text', 'rule');
assert.equal(newlineName.cacheEntries().length, 0, 'filenames must match the complete strict name');
const linkedDirectory = harness(); linkedDirectory.put(directory, '/outside/cache', 'link');
assert.deepEqual(linkedDirectory.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']});
assert.equal(linkedDirectory.files.get(directory).type, 'link'); assert.equal(linkedDirectory.cacheEntries().length, 0);
const busy = harness(); busy.put(state + '/provider-cache.lock', '', 'directory', 0o700);
assert.deepEqual(busy.fetch(raw, root, 'text', 'rule'), {payload: ['DOMAIN-SUFFIX,example.org']});
assert.equal(busy.cacheEntries().length, 0, 'a concurrent cache owner makes caching unavailable');
assert.equal(busy.files.get(state + '/provider-cache.lock').type, 'directory', 'only the cache lock owner may release it');
assert.ok(!fallback.files.has(state + '/provider-cache.lock'), 'cache operations release their own lock');
console.log('PROVIDER_GITHUB_TRANSPORT_AND_BOUNDED_CACHE_OK');
