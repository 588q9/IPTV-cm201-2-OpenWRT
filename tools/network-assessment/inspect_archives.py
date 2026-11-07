import hashlib
import json
import pathlib
import struct
import tarfile

root = pathlib.Path(__file__).resolve().parent
cache = root.parents[1] / 'local' / 'cache'
manifest = {}
for arch in ('arm', 'mipsle'):
    source = cache / ('tailscale_1.104.1_' + arch + '.tgz')
    expected = source.with_name(source.name + '.sha256').read_text().strip().split()[0]
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if digest != expected:
        raise RuntimeError('checksum mismatch: ' + arch)
    destination = root / arch
    destination.mkdir(exist_ok=True)
    binaries = {}
    with tarfile.open(str(source), 'r:gz') as archive:
        for name in ('tailscale', 'tailscaled'):
            member = archive.getmember('tailscale_1.104.1_' + arch + '/' + name)
            data = archive.extractfile(member).read()
            if data[:4] != b'\x7fELF':
                raise RuntimeError('not ELF')
            (destination / name).write_bytes(data)
            endian = '<' if data[5] == 1 else '>'
            binaries[name] = {
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'elf_class': data[4], 'elf_endian': data[5],
                'elf_machine': struct.unpack(endian + 'H', data[18:20])[0],
            }
    manifest[arch] = {'archive_sha256': digest, 'binaries': binaries}
(root / 'archives.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
print(json.dumps(manifest, indent=2))
