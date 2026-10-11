# 第三方来源与许可证

根目录 `LICENSE` 只适用于本项目原创代码和文档，不能用来重新许可第三方源码、兼容补丁、原厂资源或生成系统中的软件包。

资源版本、下载地址和 SHA256 以 [resources.lock.json](resources.lock.json) 为准。第三方源码和工具下载到被忽略的本地目录，原有版权声明及许可证随下载包保留。下表用于说明来源，完整授权条件以锁定版本所附文本和各源文件声明为准。

| 组件 | 本项目用途 | 许可证与处理方式 |
| --- | --- | --- |
| OpenWrt 25.12.5 ARMv7 根系统及官方 APK | Linux 用户空间、LuCI、网络工具和无线程序 | 包内软件分别采用 GPL、LGPL、BSD、ISC、MIT 等许可证。OpenWrt 镜像没有统一的 MIT 授权；再分发系统时按软件包清单保留声明及对应源码义务。 |
| hostapd-basic、hostapd-common、wpa-supplicant-basic | MT7668 无线用户空间程序 | 锁定 APK 元数据声明 BSD-3-Clause；保留各包及上游源码的完整声明。 |
| iw、wifi-scripts | 无线查询与配置辅助工具 | 锁定 APK 元数据声明 GPL-2.0；另行分发产物时按具体文件许可处理对应源码。 |
| ucode-mod-nl80211、ucode-mod-rtnl、ucode-mod-digest | 无线与网络脚本依赖 | 锁定 APK 元数据声明 ISC；保留上游版权与许可。 |
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

针对上游文件的补丁沿用该文件的许可证。独立编写的构建、校验、配置、串口辅助程序和中文文档采用根目录 MIT 许可证。MIT 声明不覆盖运行时下载的源码和软件包。

`tools/cm2012/patches/ubusd-3.18.patch` 保留原文件的上游版权署名：2011 年 Felix Fietkau。已核对锁定 ubus 源码中的文件标头，补丁采用 LGPL-2.1-only，并随仓库附带 [GNU LGPL 2.1 完整正文](LICENSES/LGPL-2.1-only.txt)。此判断来自被修改文件自身的声明，与其他下载工具采用 GPL 的情况无关。

正文与 [GNU GCC 官方源码镜像的固定版本 COPYING.LIB](https://raw.githubusercontent.com/gcc-mirror/gcc/d0ca130aa5d50cdaeea8e5c343d65250cdf51955/COPYING.LIB) 逐字节一致，共 26527 字节，SHA256 为 `a9bdde5616ecdd1e980b44f360600ee8783b1f99b8cc83a2beb163a0a390e861`。许可证版本说明见 [GNU 官方 LGPL 2.1 页面](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)；法律正文保持原文，不作中文翻译或改写。

Windows 运行依赖的固定版本和 wheel 摘要另列于 `requirements.lock`，实际文件来源以 `resources.lock.json` 为准。hiloot 的 `Device` 导入会加载芯片属性模块，因此需要 PyCryptodomex；只解析引导头并不能消除这项导入依赖。上游可选的 tqdm 和 colorama 均有缺失回退，本项目未将它们列为必要依赖。

旧调试目录中的厂商源码摘录不进入公共版本。其中部分文件明示保留全部权利，部分 U-Boot 文件采用 GPL-2.0-or-later；不得因为本项目采用 MIT 就修改其许可或删除版权声明。

## 生成产物的分发

`tools/cm2012/patches/iptables-register-reset.patch` 沿用 GPL-2.0-only，适配自 [OpenWrt v23.05.5 的固定补丁](https://raw.githubusercontent.com/openwrt/openwrt/v23.05.5/package/network/utils/iptables/patches/101-remove-check-already.patch)。源地址和原始摘要记在补丁头中，应用上下文针对锁定的 iptables 1.8.8；允许 firewall3 重置扩展列表后重新注册。附带的 [GPLv2 正文](LICENSES/GPL-2.0-only.txt) 来自锁定 iptables 源码的 COPYING，共 18092 字节，SHA256 为 `8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643`。

本仓库首版交付代码、模板和锁定清单，使用者在本机生成产物。生成的镜像包含官方软件包、本机原厂资源以及本地管理配置，不能直接套用本仓库的 MIT 许可证公开分发。若另行分发系统，需要逐项核对软件包许可、保留授权文件并提供许可要求的对应源码，同时先移除密码摘要、设备参数、私钥和其他私人数据。
