# 第三方来源与许可证

根目录 `LICENSE` 只适用于本项目原创代码和文档，不能用来重新许可第三方源码、兼容补丁、原厂资源或生成系统中的软件包。

资源版本、下载地址和 SHA256 以 [resources.lock.json](resources.lock.json) 为准。第三方源码和工具下载到被忽略的本地目录，原有版权声明及许可证随下载包保留。下表用于说明来源，完整授权条件以锁定版本所附文本和各源文件声明为准。

| 组件 | 本项目用途 | 许可证与处理方式 |
| --- | --- | --- |
| OpenWrt 25.12.5 ARMv7 根系统及官方 APK | Linux 用户空间、LuCI、网络工具和无线程序 | 包内软件分别采用 GPL、LGPL、BSD、ISC、MIT 等许可证。OpenWrt 镜像没有统一的 MIT 授权；再分发系统时按软件包清单保留声明及对应源码义务。 |
| hostapd-basic、hostapd-common、wpa-supplicant-basic | MT7668 无线用户空间程序 | 锁定 APK 元数据声明 BSD-3-Clause；保留各包及上游源码的完整声明。 |
| iw、wifi-scripts | 无线查询与配置辅助工具 | 锁定 APK 元数据声明 GPL-2.0；另行分发产物时按具体文件许可处理对应源码。 |
| ucode-mod-nl80211、ucode-mod-rtnl、ucode-mod-digest | 无线与网络脚本依赖 | 锁定 APK 元数据声明 ISC；保留上游版权与许可。 |
| Tailscale 1.104.1，官方 ARM 静态包 | CM201-2 异地 LAN 访问；分别安装 tailscale、tailscaled | BSD-3-Clause；额外锁定官方版本 LICENSE，装配到 `/usr/share/licenses/cm2012-network/`。其他内嵌依赖按对应声明处理。 |
| Mihomo v1.19.32，官方 Linux ARMv7 程序 | LAN IPv4 透明代理核心 | 上游版本 LICENSE 为 GPLv3；保留完整许可，再分发二进制时同时履行对应源码等义务。官方 release 的 SHA256 与本地文件一致。 |
| [DB-IP Country Lite，2026 年 10 月版](https://db-ip.com/db/download/ip-to-country-lite) | 为 Mihomo 的 GEOIP 国家规则提供本地 MMDB 数据库 | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)；署名为 IP Geolocation by [DB-IP](https://db-ip.com)。压缩包和解压数据库的大小及 SHA256 分别锁定；数据内容不变，仅解压并改名为 `Country.mmdb`。署名、许可链接及处理说明随产物保存至 `/usr/share/licenses/cm2012-network/geoip-country-dbip.txt`。 |
| MetaCubeXD v1.273.1 静态页面 | 随部署包提供本地 Dashboard，不运行 Node 服务 | MIT；静态发布提交 `28a9589f6239bbafc24e87bbf5e5b4997fe42e59`，发布提交信息对应源码 `8bbc8f58fef71148a94fb5c0ff808f79b057337d`。固定完整静态归档摘要及该源码提交的 LICENSE。 |
| mikefarah/yq v4.44.3，官方 Linux ARM 程序 | 使用固定表达式安全解析订阅 YAML | MIT；保留版本 LICENSE，官方 checksums 中的 SHA256 与实际文件一致。YAML 内容作为数据处理，不执行远端表达式。 |
| ddns-scripts、ddns-scripts-services、ddns-scripts-cloudflare 2.8.4-r8；luci-app-ddns | 标准 Cloudflare DDNS 与 LuCI 页面 | DDNS 包元数据声明 GPL-2.0；LuCI 页面为 Apache-2.0。完整版本、feed、依赖、提供能力及实际 APK 摘要均进入资源锁。 |
| curl、libcurl4、openssl-util、libopenssl-conf、libopenssl3、ca-bundle、ca-certificates | HTTPS 下载、设备本地证书转换与 CA 信任 | curl 为 MIT，OpenSSL 为 Apache-2.0，CA 包元数据列 GPL-2.0-or-later 与 MPL-2.0；保留包内和对应源码的具体声明。 |
| ip-full、libbpf1、libelf1、libatomic1、libnghttp2-14、resolveip、drill、libldns | 策略路由、DDNS 解析及本地 DNS 健康检查的依赖闭包 | 分别包含 GPL、LGPL、BSD、MIT 和 GCC runtime exception 等声明；每项许可以锁定 APK 元数据及源码为准。`ip-full` 的 alternatives 链接由构建显式建立，包脚本仍不执行。 |
| ubus，提交 `24864e7840b3a02a9ef76284a373f6b2f00b8a9b` | 构建兼容旧内核的 ubusd | `ubusd_id.c` 声明 GNU LGPL 2.1；本项目针对该文件的补丁标识为 LGPL-2.1-only，保留该许可。其他文件按其原声明处理。 |
| libubox，提交 `7dd127841e82eb1cfb61185da37dde7b9bd9ba6d` | ubus 所需头文件及接口 | 按文件采用 ISC、LGPL 等授权；保留每个文件的版权和许可，不统一改为 MIT。 |
| firewall3，提交 `3a65fde5a3e675fdf2a24cb3f5d12d0a426be36e` | 原厂内核的 UCI 防火墙后端 | 源文件包含 ISC 风格许可，保留完整版权及许可声明。 |
| UCI，提交 `74f6277aabffc943d026f406df57c22595134c42` | firewall3 所需公开头文件 | 头文件声明 LGPL 2.1；使用官方根运行库，保留锁定源码中的声明。 |
| iptables 1.8.8 | 静态 legacy 命令与 libxtables 运行库 | GPLv2 及文件级许可；锁定完整原始源码，再分发生成系统时提供相应源码及许可。Windows 构建重命名大小写冲突路径并改写对应 include，应用下述 firewall3 注册兼容补丁。 |
| mtd-utils 2.1.6 | 编译 NAND、MTD 与 UBI 工具 | 包含 GPLv2 许可文本及文件级声明；保留这些声明，按实际编译文件执行对应授权要求。 |
| hiloot，提交 `56b598ab7fd62a2b7ddce6e7b3770d93c40f4801` | BootROM 串口传输及原厂引导格式解析 | 上游包含 GPLv2 许可文本；使用完整锁定源码，保留上游许可。 |
| Zig 0.13.0 | Windows 上交叉编译 ARM 程序 | Zig 项目及其捆绑编译器、运行库包含不同授权；保留完整工具发行包中的许可证。工具包不提交到本仓库。 |
| pySerial 3.5、pyserial-asyncio 0.6 | Windows 串口通信 | BSD；保留包内版权、许可及声明。 |
| ymodem 1.5.3 | RAM 镜像串口传输 | MIT；保留上游许可。 |
| ordered-set 4.1.0 | ymodem 所需 Python 依赖 | MIT；保留上游许可。 |
| Passlib 1.7.4 | 在本机生成和验证管理密码摘要 | BSD；包内部分算法或辅助实现另有声明，保留包内完整许可文件。 |
| PyCryptodomex 3.24.0 | hiloot 的芯片属性读取模块需要 `Cryptodome` AES 与填充接口 | BSD 和公有领域代码；保留 wheel 内完整许可和声明。Windows x64 使用 `cp37-abi3` 稳定 ABI wheel，可供 CPython 3.12 使用。 |
| 使用者原厂引导器、内核、模块和固件 | 提供匹配的 DDR、硬件初始化及 MT7668 支持 | 来源和授权由原厂资源决定。本仓库不分发这些文件，也不将其重新许可为 MIT。 |

## 补丁和原创代码

订阅专用下载器使用锁定的 curl 8.22.0 官方头文件，运行时调用已有 `libcurl.so.4`；源码归档的 `COPYING` 随根系统保存在 `/usr/share/licenses/cm2012-network/curl-source.txt`。内核取熵适配为本项目原创代码，不修改或重新分发替换版本的 mbedTLS 库。

针对上游文件的补丁沿用该文件的许可证。独立编写的构建、校验、配置、串口辅助程序和中文文档采用根目录 MIT 许可证。MIT 声明不覆盖运行时下载的源码和软件包。

`tools/cm2012/patches/ubusd-3.18.patch` 保留原文件的上游版权署名：2011 年 Felix Fietkau。已核对锁定 ubus 源码中的文件标头，补丁采用 LGPL-2.1-only，并随仓库附带 [GNU LGPL 2.1 完整正文](LICENSES/LGPL-2.1-only.txt)。此判断来自被修改文件自身的声明，与其他下载工具采用 GPL 的情况无关。

正文与 [GNU GCC 官方源码镜像的固定版本 COPYING.LIB](https://raw.githubusercontent.com/gcc-mirror/gcc/d0ca130aa5d50cdaeea8e5c343d65250cdf51955/COPYING.LIB) 逐字节一致，共 26527 字节，SHA256 为 `a9bdde5616ecdd1e980b44f360600ee8783b1f99b8cc83a2beb163a0a390e861`。许可证版本说明见 [GNU 官方 LGPL 2.1 页面](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)；法律正文保持原文，不作中文翻译或改写。

Windows 运行依赖的固定版本和 wheel 摘要另列于 `requirements.lock`，实际文件来源以 `resources.lock.json` 为准。hiloot 的 `Device` 导入会加载芯片属性模块，因此需要 PyCryptodomex；只解析引导头并不能消除这项导入依赖。上游可选的 tqdm 和 colorama 均有缺失回退，本项目未将它们列为必要依赖。

网络扩展的 APK 分别保存在 `local/cache/apk/<feed>/`，每个 feed 保留自己的签名 `packages.adb`。原无线包的 base 索引快照保存为 `base-20261011`；新增依赖使用 2026-10-18 核对的 base、packages、luci、target 索引。OpenWrt 发布目录可能更新，下载内容不符合锁定摘要时必须失败，不能重新使用当前索引替代旧快照。锁定原根内已有的 libc、LuCI 基础和其他依赖由原根的 SHA256 及已安装包数据库固定；构建前检查新增包与原根组成的依赖闭包，设备端继续由 apk 校验签名，保持离线、禁安装脚本。

旧调试目录中的厂商源码摘录不进入公共版本。其中部分文件明示保留全部权利，部分 U-Boot 文件采用 GPL-2.0-or-later；不得因为本项目采用 MIT 就修改其许可或删除版权声明。

## 生成产物的分发

### 本轮公开索引与 DDNS 修改

`configs/resource-snapshots/` 保存五份资源锁原有的官方 OpenWrt 签名索引原始字节，来源、feed、版本日期和完整摘要见该目录 `provenance.json`。两份 base 历史快照用于不同的既有锁定内容身份；没有升级无线包或修改签名字段。该目录不包含设备包数据库、原厂参数或配置。索引取得方式和本轮核对范围见该目录 README；软件包继续遵循各自许可，不能据根目录 MIT 声明重新授权。

`tools/cm2012/credentials.py` 对固定的 ddns-scripts/ddns-scripts-cloudflare 2.8.4-r8 脚本作定点修改：认证头通过 stdin 交给 curl，初始化 URL 编码避免密码进入 awk 参数，诊断先脱敏再输出。原始脚本、作者/许可标头、软件包来源与锁定摘要见 `tests/fixtures/ddns-2.8.4-r8/README.md`；回归 fixture 保存的是公开脚本，不包含设备 Token。原代码沿用 GPL-2.0 及原始声明，完整 GPLv2 见 `LICENSES/GPL-2.0-only.txt`。修改保留原始版权和脚本元数据；未知脚本内容会停止构建，不模糊套用补丁。完整对应修改源码随本仓库提供。

`tools/cm2012/patches/iptables-register-reset.patch` 沿用 GPL-2.0-only，适配自 [OpenWrt v23.05.5 的固定补丁](https://raw.githubusercontent.com/openwrt/openwrt/v23.05.5/package/network/utils/iptables/patches/101-remove-check-already.patch)。源地址和原始摘要记在补丁头中，应用上下文针对锁定的 iptables 1.8.8；允许 firewall3 重置扩展列表后重新注册。附带的 [GPLv2 正文](LICENSES/GPL-2.0-only.txt) 来自锁定 iptables 源码的 COPYING，共 18092 字节，SHA256 为 `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643`。

本仓库首版交付代码、模板和锁定清单，使用者在本机生成产物。生成的镜像包含官方软件包、本机原厂资源以及本地管理配置，不能直接套用本仓库的 MIT 许可证公开分发。若另行分发系统，需要逐项核对软件包许可、保留授权文件并提供许可要求的对应源码，同时先移除密码摘要、设备参数、私钥和其他私人数据。
