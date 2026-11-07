"""生成不涉及分区的逐文件增量包；旧配置和设备秘密不进入负载。"""
import hashlib
import json
import stat
import uuid

from .archives import Entry, tar_bytes, read_tar_bytes
from .device_jobs import create_private_job
from .update_policy import (GEOIP_LINK, GEOIP_TARGET, allowed_path, allowed_record,
                            fingerprint, canonical_bundle, POLICY)


def make_update(root, before, after):
    files, records = {}, {}
    for name, entry in sorted(after.items()):
        # Incremental files have their own version manifest. Never replace the
        # live global APK database with a build seed's package inventory.
        if name.startswith('lib/apk/'):
            continue
        if stat.S_ISDIR(entry.mode) or before.get(name) == entry:
            continue
        if not allowed_path(name) or not allowed_record(name, fingerprint(entry)):
            raise ValueError('增量更新禁止改动引导、硬件或设备私有文件：' + name)
        # 现有所有 UCI 配置均保留；新包默认值仅在目标不存在时安装。
        if name.startswith('etc/config/') and name in before:
            continue
        records[name] = {'before': fingerprint(before.get(name)), 'after': fingerprint(entry)}
        files['payload/' + name] = entry
    if not records:
        raise ValueError('没有需要安装的网络增量文件')
    manifest = json.dumps({'format': 1, 'files': records}, ensure_ascii=False,
                          sort_keys=True, indent=2).encode() + b'\n'
    files['update.json'] = Entry(stat.S_IFREG | 0o600, manifest)
    return canonical_bundle(tar_bytes(files))


def snapshot_update(root, rootfs, host, output):
    """只读快照目标中的候选文件，绑定真实基线；不读取引导或私钥目录。"""
    from .ssh_link import SSHLink
    candidates = {n:e for n,e in read_tar_bytes(rootfs.read_bytes()).items()
                  if allowed_path(n) and not stat.S_ISDIR(e.mode)}
    job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
    with SSHLink(host) as link:
        create_private_job(link, job)
        link.upload('',job + '/paths', ('\n'.join(sorted(candidates)) + '\n').encode())
        link.command('while IFS= read -r p; do if [ -e "/$p" ] || [ -L "/$p" ]; then '
                     'printf "%s\\n" "$p"; fi; done <' + job + '/paths >' + job + '/existing')
        link.command('tar -czf ' + job + '/before.tar.gz -C / -T ' + job + '/existing',300)
        data = link.run('cat ' + job + '/before.tar.gz',timeout=300)
    bundle = make_update(root,read_tar_bytes(data),candidates)
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_bytes(bundle)
    return {'size':len(bundle),'sha256':hashlib.sha256(bundle).hexdigest(),'snapshot_job':job}


def deploy(bundle,host,*,action='check'):
    """部署前总是验证负载；仅显式 install 才改动内部文件。"""
    from .ssh_link import SSHLink
    if action not in ('check','install','rollback'):
        raise ValueError('不支持的增量操作')
    with bundle.open('rb') as stream:
        data = canonical_bundle(stream.read(POLICY['limits']['compressed_bytes'] + 1))
    job = '/tmp/cm2012-build-' + uuid.uuid4().hex[:12]
    with SSHLink(host) as link:
        create_private_job(link, job)
        link.upload('',job + '/update.tar.gz',data)
        link.command('tar -xzf ' + job + '/update.tar.gz -C ' + job,300)
        result=link.command('sh ' + job + '/update ' + action,300)
        # This exact UUID directory was created above and contains only this
        # completed deployment. Failed jobs remain available for diagnosis.
        link.command('rm -rf -- ' + job)
        return result
