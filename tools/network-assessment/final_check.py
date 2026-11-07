import difflib
import json
from probe import BASE, OPTS, JOB, ssh, run
from run_probe import SNAPSHOT

ip = '192.168.50.1'
normalized = SNAPSHOT.replace("sed '/^#/d'", "sed -e '/^#/d' -e 's/\\[[0-9]*:[0-9]*\\]/[0:0]/g'")
results = []
def record(label, result):
    results.append({'label':label, 'exit':result[0], 'output':result[1]})
    (BASE / 'cm2012-final-check.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(label, result[0], flush=True)
    if result[0]:
        print(result[1], flush=True)
        raise RuntimeError(label)
    return result
before = record('normalized-before', ssh(ip, normalized))
record('upload-script', run(['scp', '-O'] + OPTS + [str(BASE / 'cm-inside.sh'), 'root@' + ip + ':' + JOB + '/cm-inside.sh']))
record('isolated-daemon-repeat', ssh(ip, JOB + '/netns-exec /bin/sh ' + JOB + '/cm-inside.sh', 60))
after = record('normalized-after', ssh(ip, normalized))
print('HOST_NORMALIZED_MATCH=' + str(before == after), flush=True)
if before != after:
    print(''.join(difflib.unified_diff(before[1].splitlines(True), after[1].splitlines(True))), flush=True)
