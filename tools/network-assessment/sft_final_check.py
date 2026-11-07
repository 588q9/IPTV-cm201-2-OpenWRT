import json
from probe import BASE, JOB, ssh
from run_probe import SNAPSHOT

ip = '192.168.250.1'
normalized = SNAPSHOT.replace("sed '/^#/d'", "sed -e '/^#/d' -e 's/\\[[0-9]*:[0-9]*\\]/[0:0]/g'")
results=[]
for label, command in [('normalized-before', normalized), ('tun-probe-repeat', JOB + '/tun-probe'), ('normalized-after', normalized)]:
    code, out = ssh(ip, command)
    results.append({'label':label,'exit':code,'output':out})
    print(label, code, out if label=='tun-probe-repeat' else '(saved)', flush=True)
    (BASE/'sft1200-final-check.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
print('HOST_NORMALIZED_MATCH=' + str(results[0]['output']==results[-1]['output']),flush=True)
