# CM201-2 内置 OpenWrt

为已验证的 CM201-2 电视盒子提供可复现的 Windows 构建、RAM 验收、内部 UBI/UBIFS 安装及网络扩展源码。正式系统运行在内部 NAND，不依赖 U 盘。

本项目交付源码、模板、测试、固定资源清单和公开签名索引。使用者自行提供匹配设备的原厂资料，在本机生成系统；镜像包含本机配置和原厂参数，不作为公开发布附件。

## 功能与边界

| 功能 | 入口与说明 |
| --- | --- |
| 内置系统构建、校验、RAM 验收与 userdata 重装 | [构建说明](docs/公开文档/构建说明.md)、[功能修复与重装](docs/公开文档/功能修复与重装.md) |
| AP/无线中继、eth0 LAN/WAN 切换、静态路由与事务回滚 | [网口切换与静态路由](docs/公开文档/网口切换与静态路由.md) |
| Cloudflare DDNS、Tailscale 子网访问、Mihomo/MetaCubeXD | [网络扩展实施与启用](docs/公开文档/CM2012网络扩展实施与启用.md)；三项服务默认停用，账户和订阅在设备本地填写 |
| 节点 DNS 缓存恢复与主 DNS 故障切换 | [防复发实现与验证边界](docs/公开文档/节点DNS缓存防复发-20261102.md) |
| 增量安装、来源校验与精确撤销 | `tools/project.py network-bundle` / `network-deploy`；不改分区，保留现有 UCI 配置 |
| 项目结构、功能归属与验证入口 | [架构与功能索引](docs/公开文档/项目架构与功能索引.md) |
| 凭据处理、公开检查和源码发布 | [源码发布与隐私](docs/公开文档/源码发布与隐私.md) |

硬件范围为 Hi3798MV300、1 GiB LPDDR3、原厂 `3.18.24_hi3798mv2x` 内核和 MT7668。引导器、内核、NAND 几何均有校验。动态 NAND 容量适配不代表支持其他芯片、DDR、内核或无线驱动；SFT1200 不在本版支持范围内。

## 开始使用

Windows x64、CPython 3.12、锁定的 Zig 0.13.0；构建工作机需有匹配内核的串口或已信任主机密钥的 SSH。原厂输入和恢复边界请先阅读 [构建说明](docs/公开文档/构建说明.md) 与 [恢复与限制](docs/公开文档/恢复与限制.md)。

```powershell
py -3.12 tools/project.py prepare
py -3.12 tools/project.py configure --stock-dir .\local\stock-original --port COM3
py -3.12 tools/project.py check
py -3.12 tools/project.py build --output .\output\current
py -3.12 tools/project.py verify --output .\output\current
```

示例使用 Python Launcher；没有 Launcher 时替换为实际 Python 3.12 解释器。`prepare` 下载/导入固定资源；后续 build 使用本地缓存，Python 进程和设备 APK 均禁止联网。五份历史签名索引随源码保存，详见 [快照来源](configs/resource-snapshots/README.md)。其他旧资源仍可能需要可信 `--import-dir` 缓存，摘要变化会停止，不能自动替换为新版本。

普通 build、verify 和 RAM 验收不会正式写入 NAND。`install` 继续要求显式 `--erase-internal-root` 和与当前产物匹配的验收凭据；执行前须完成自己的备份和设备核对。

## 验证与版本状态

公共测试不依赖私人原厂备份或设备：

```powershell
py -3.12 -m unittest discover -s tests -p "test_public_*.py" -v
py -3.12 tools/cm2012/publication.py --ref HEAD
```

CI 在 Windows/Ubuntu 使用 Python 3.12 与 Node 24.9.0。已准备锁定缓存后，可运行独立的离线交叉编译集成测试；实际命令和范围见 [源码发布与隐私](docs/公开文档/源码发布与隐私.md)。

本次源码预发布包含更新包信任与链接边界、DDNS 凭据参数/诊断保护、私密作业目录、模块解耦和公开内容检查。HTTPS 管理策略按使用者要求暂缓，本版保持现有行为。代码回归不等同于完整业务验收：规则集合全量准备、DDNS 真实更新、Tailscale 登录/蜂窝访问、重启恢复和长期负载仍按各自实测记录判断。

历史设备验收、运行修复及证据日期保留在 [版本与验收记录](docs/公开文档/版本与验收记录.md)，不将旧产物结果归到本次重构后的源码上。[实施设计](docs/superpowers/specs/2026-11-01-release-readiness-design.md) 与 [实施计划](docs/superpowers/plans/2026-11-01-release-readiness.md) 记录本轮边界。

## 本机数据与许可证

`local/`、`output/`、备份、下载缓存和现场日志被 Git 忽略。root hash、订阅、API 密钥及含有这些信息的归档仍是敏感数据，不能因为目录被忽略或密码已哈希就公开分享。

原创代码采用 [MIT](LICENSE)。第三方代码、补丁、公开索引和固定软件包的来源与许可见 [THIRD_PARTY](THIRD_PARTY.md)。本仓库不分发原厂引导器、内核、模块、固件和设备参数，也不把第三方资源重新许可为 MIT。
