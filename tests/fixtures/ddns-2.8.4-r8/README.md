# Public DDNS regression fixtures

The two shell files are unmodified public OpenWrt ddns-scripts / ddns-scripts-cloudflare 2.8.4-r8 files, read only from the existing installed `output/remote-networking-20261021/rootfs.tar.gz` archive. No configuration, subscription or device data is included. Tests need no local output archive or package cache after these public fixtures are present.

Locked upstream packages in `resources.lock.json`:

| Package | Public source | APK SHA256 |
| --- | --- | --- |
| ddns-scripts 2.8.4-r8 | https://downloads.openwrt.org/releases/25.12.5/packages/arm_cortex-a15_neon-vfpv4/packages/ddns-scripts-2.8.4-r8.apk | `17714cb2cdf8b9a9d15698060f82578ecf37e0445d522f6f86b4667e41ab4ed5` |
| ddns-scripts-cloudflare 2.8.4-r8 | https://downloads.openwrt.org/releases/25.12.5/packages/arm_cortex-a15_neon-vfpv4/packages/ddns-scripts-cloudflare-2.8.4-r8.apk | `be80efd6cd6afd6ee721befc5127efca7552c0f1961123bf3d19b6774a9382ed` |

Both cached APKs were independently hashed against the resource lock during implementation. The fixture extraction source is the installed rootfs, not a claim that Python decoded the APK v3 format.

| Installed public script | Size | SHA256 |
| --- | --- | --- |
| update_cloudflare_com_v4.sh | 10096 | `120bd12191d072f8720640316dec931002a3a9f26e743df45cce08960069fe3f` |
| dynamic_dns_functions.sh | 42656 | `a607436c9e8676977e231e8868e8692943d1d28324869297cafadee7f4e8610d` |

The upstream files declare GNU GPL version 2.0. Their original attribution and license notices remain intact, including Eric Paul Bishop, Christian Schoenebeck, Wayne King and the referenced original authors. The repository carries the full license in `LICENSES/GPL-2.0-only.txt`. The credential hardening in `tools/cm2012/credentials.py` preserves those notices in the produced scripts. It changes only these exact versions and accepts only the original fingerprints or the exact expected patched fingerprints.

The curl fixture is a local shell child process. Its recorded synthetic header bytes exist only to assert transport behavior; production streams headers directly through a pipe without creating a credential file. All tokens used by tests are synthetic.
