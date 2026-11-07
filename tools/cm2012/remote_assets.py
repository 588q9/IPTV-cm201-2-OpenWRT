"""网络扩展的锁定资源；只读取本地缓存，不发起下载。"""
import gzip
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

from .archives import Entry, read_tar_bytes
from .resources import read_lock, verify_resource, source_archive_root


GEOIP_ASSET_ID = 'geoip-country-dbip'
ASSET_IDS = ('tailscale-arm', 'mihomo-armv7', 'yq-arm', 'metacubexd-static', GEOIP_ASSET_ID)
LICENSE_IDS = ('tailscale-license', 'mihomo-license', 'yq-license', 'metacubexd-license')
REMOTE_PROGRAMS = ('usr/sbin/tailscale', 'usr/sbin/tailscaled', 'usr/bin/mihomo',
                   'usr/libexec/cm2012-proxy-fetch',
                   'usr/bin/yq', 'usr/bin/curl', 'usr/bin/openssl', 'sbin/ip',
                   'usr/bin/drill', 'usr/bin/timeout', 'usr/lib/ddns/dynamic_dns_updater.sh')


def asset_files(root):
    """装配程序和面板，保留静态资源完整目录；任何缺失或摘要不符均失败。"""
    locks = read_lock(root)
    for ident in ASSET_IDS + LICENSE_IDS:
        if ident not in locks:
            raise ValueError('网络资源未锁定：' + ident)
    paths = {ident: verify_resource(root, locks[ident]) for ident in ASSET_IDS}
    result = {}
    tailscale = read_tar_bytes(paths['tailscale-arm'].read_bytes())
    for program in ('tailscale', 'tailscaled'):
        matches = [entry for name, entry in tailscale.items()
                   if PurePosixPath(name).name == program and stat.S_ISREG(entry.mode)]
        if len(matches) != 1 or not matches[0].data:
            raise ValueError('Tailscale 包缺少唯一程序：' + program)
        result['usr/sbin/' + program] = Entry(stat.S_IFREG | 0o755, matches[0].data)
    result['usr/bin/mihomo'] = Entry(stat.S_IFREG | 0o755,
                                    gzip.decompress(paths['mihomo-armv7'].read_bytes()))
    result['usr/bin/yq'] = Entry(stat.S_IFREG | 0o755, paths['yq-arm'].read_bytes())
    geoip_lock = locks[GEOIP_ASSET_ID]
    geoip = gzip.decompress(paths[GEOIP_ASSET_ID].read_bytes())
    if (len(geoip) != geoip_lock.get('uncompressed_size') or
            hashlib.sha256(geoip).hexdigest() != geoip_lock.get('uncompressed_sha256')):
        raise ValueError('地理数据库解压内容与资源锁不一致')
    result['usr/share/cm2012/geodata/Country.mmdb'] = Entry(stat.S_IFREG | 0o644, geoip)
    notice = ('DB-IP Country Lite, release ' + geoip_lock['version'] + '.\n'
              'IP Geolocation by DB-IP - https://db-ip.com.\n'
              'Licensed under CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/.\n'
              'Database content unchanged; gzip decompressed and file renamed to Country.mmdb.\n')
    result['usr/share/licenses/cm2012-network/' + GEOIP_ASSET_ID + '.txt'] = Entry(
        stat.S_IFREG | 0o644, notice.encode())
    dashboard = read_tar_bytes(paths['metacubexd-static'].read_bytes())
    roots = {PurePosixPath(name).parts[0] for name in dashboard}
    if len(roots) != 1:
        raise ValueError('MetaCubeXD 静态包必须有唯一根目录')
    for name, entry in dashboard.items():
        if not stat.S_ISREG(entry.mode) and not stat.S_ISDIR(entry.mode):
            raise ValueError('MetaCubeXD 静态包不允许链接或设备文件')
        relative = PurePosixPath(name).parts[1:]
        if not relative:
            continue
        result['www/metacubexd/' + '/'.join(relative)] = Entry(
            (stat.S_IFDIR | 0o755) if stat.S_ISDIR(entry.mode) else (stat.S_IFREG | 0o644), entry.data)
    if not result.get('www/metacubexd/index.html', Entry(0)).data:
        raise ValueError('MetaCubeXD 缺少本地入口')
    if any(not result[name].data for name in ('usr/bin/mihomo', 'usr/bin/yq')):
        raise ValueError('网络程序为空')
    versions = {ident: {field: locks[ident][field] for field in ('version', 'sha256')}
                for ident in ASSET_IDS}
    versions[GEOIP_ASSET_ID].update({field: geoip_lock[field] for field in
                                   ('uncompressed_size', 'uncompressed_sha256')})
    versions['packages'] = {ident: {field: item[field] for field in ('version', 'sha256', 'feed')}
                            for ident, item in locks.items()
                            if item['path'].startswith('local/cache/apk/') and item['path'].endswith('.apk')}
    result['usr/share/cm2012/remote-assets.json'] = Entry(stat.S_IFREG | 0o644,
        (json.dumps(versions, sort_keys=True, indent=2) + '\n').encode())
    for ident in LICENSE_IDS:
        result['usr/share/licenses/cm2012-network/' + ident + '.txt'] = Entry(
            stat.S_IFREG | 0o644, verify_resource(root, locks[ident]).read_bytes())
    import tarfile
    with tarfile.open(verify_resource(root, locks['curl-source'])) as source:
        name = source_archive_root(source) + '/COPYING'
        member = source.getmember(name)
        if not member.isreg():
            raise ValueError('curl 许可不是普通文件')
        license_text = source.extractfile(member).read()
    result['usr/share/licenses/cm2012-network/curl-source.txt'] = Entry(
        stat.S_IFREG | 0o644, license_text)
    return result


def _installed_providers(seed):
    providers = {}
    entry = seed.get('lib/apk/db/installed', Entry(0))
    for block in entry.data.decode().split('\n\n'):
        fields = dict(line.split(':', 1) for line in block.splitlines()
                      if len(line) > 1 and line[1] == ':' and line[0] in 'PVp')
        if 'P' not in fields or 'V' not in fields:
            continue
        providers.setdefault(fields['P'], set()).add(fields['V'])
        for provide in fields.get('p', '').split():
            name, _, version = provide.partition('=')
            providers.setdefault(name, set()).add(version)
    return providers


def apk_payload(root, locks, seed):
    """保留签名索引，用 APK 原生内容标识和专用缓存消除多 feed 的选源歧义。"""
    result, indexes, packages, constraints = {}, {}, [], []
    total = 0
    for ident, item in locks.items():
        raw = item['path']
        if not raw.startswith('local/cache/apk/'):
            continue
        relative = raw.removeprefix('local/cache/')
        parts = PurePosixPath(relative).parts
        feed = item.get('feed', '')
        if (len(parts) != 3 or parts[0] != 'apk' or parts[1] != feed or
                not re.fullmatch(r'[a-z0-9][a-z0-9-]*', feed) or
                relative != '/'.join(parts)):
            raise ValueError('APK 必须保存为独立 feed 路径：' + raw)
        if relative in result:
            raise ValueError('APK 资源路径碰撞：' + relative)
        filename = parts[-1]
        if filename == 'packages.adb':
            if feed in indexes:
                raise ValueError('APK feed 索引重复：' + feed)
            indexes[feed] = relative
        elif filename.endswith('.apk'):
            if 'depends' not in item:
                raise ValueError('APK 缺少锁定依赖元数据：' + ident)
            identity = item.get('apk_identity', '')
            if not isinstance(identity, str) or not re.fullmatch(r'[a-f0-9]{64}', identity):
                raise ValueError('APK 缺少签名索引中的 SHA-256 内容标识：' + ident)
            if (not re.fullmatch(r'[a-z0-9][a-z0-9+_.-]*', ident) or
                    not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.~-]*', item['version'])):
                raise ValueError('APK 名称或版本无效：' + ident)
            packages.append((ident, item))
            # apk 3.0.5 合并相同内容的 feed 后总从第一个 feed 取文件；
            # cache 使用内容摘要命名，可复用原文件而无需复制到每个 feed。
            cached = 'apk-cache/' + ident + '-' + item['version'] + '.' + identity[:8] + '.apk'
            if cached in result:
                raise ValueError('APK 缓存路径碰撞：' + cached)
            result[cached] = Entry(stat.S_IFLNK | 0o777, ('../' + relative).encode())
            # APK 的候选 id 是 SHA-256 的前 160 位；解包仍验证索引的完整摘要。
            constraints.append(ident + '><X1' + identity[:40])
        else:
            raise ValueError('APK feed 包含未知资源：' + raw)
        data = verify_resource(root, item).read_bytes()
        result[relative] = Entry(stat.S_IFREG | 0o600, data)
        total += len(data)
    providers = _installed_providers(seed)
    # 新锁定版本会替换 seed 中同名包，不能借旧版本满足它的精确依赖。
    for ident, item in packages:
        providers[ident] = {item['version']}
    for ident, item in packages:
        if item['feed'] not in indexes:
            raise ValueError('APK 缺少 feed 签名索引：' + ident)
        for provide in item.get('provides', []):
            providers.setdefault(provide['name'], set()).add(provide.get('version', ''))
    for ident, item in packages:
        for dependency in item['depends']:
            name, version = dependency['name'], dependency.get('version', '')
            if dependency.get('match', 0) != 0:
                raise ValueError('尚未支持的 APK 依赖比较方式：' + ident + ' → ' + name)
            if name not in providers or version and version not in providers[name]:
                raise ValueError('APK 依赖闭包缺失：' + ident + ' → ' + name + ('=' + version if version else ''))
    if not indexes or not packages:
        raise ValueError('APK 离线资源集为空')
    result['repositories.list'] = Entry(stat.S_IFREG | 0o600,
        ('\n'.join(indexes[feed] for feed in sorted(indexes)) + '\n').encode())
    result['apk-constraints.list'] = Entry(stat.S_IFREG | 0o600,
        ('\n'.join(constraints) + '\n').encode())
    return result, total
