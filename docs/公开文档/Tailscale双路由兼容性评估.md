# CM201-2 与 SFT1200：Tailscale 实机兼容性评估

日期：2026-10-18。范围：SSH 基础检查、官方二进制与有限运行验证；未安装常驻服务，未登录账号，未发布子网路由。

## 1. 结论

**CM201-2 建议进入登录与子网访问验证；SFT1200 具备基础运行条件，但仍是需要适配和资源验证的候选。两台均未通过完整异地组网验收。**

| 项目 | CM201-2 | GL-SFT1200（Opal） |
| --- | --- | --- |
| 实测管理地址 | 192.168.50.1 | 192.168.250.1 |
| 运行系统 | OpenWrt 25.12.5 用户空间 | GL 3.206，OpenWrt 18.06 系列 |
| 实际内核 | 3.18.24_hi3798mv2x | 4.14.90 |
| 实际架构 | ARMv7，32 位小端，四核 | MIPS32r2，小端；opkg 为 mips_siflower |
| 官方程序选择 | arm，1.104.1 | mipsle，1.104.1 |
| 测前可用内存 | 约 902MiB | 约 53MiB，检查间有波动 |
| 测前可用持久存储 | 约 7.25GiB | overlay 约 65MiB |
| 官方 tailscaled --version | 通过 | 通过 |
| TUN 验证 | 正常 daemon 创建并启用 TUN，MTU 1280 | 最小程序创建、关闭非持久 TUN 通过 |
| daemon / 本地 API | 隔离环境初始化通过，TUN=true，NeedsLogin | 正常 daemon 未启动验证 |
| 策略路由 | 隔离环境成功生成 5210/5230/5250/5270 | iproute2 功能具备；mwan3 共存待正式验证 |
| 当前判断 | 初始化兼容已实测，优先部署候选 | 二进制与 TUN 基础通过，完整兼容未确认 |

GL 官方文档仍将 SFT1200 列为 Tailscale **不支持的集成型号**；这与手工运行官方二进制是不同范围。本轮成功运行不能视为取得原厂支持。[GL 型号列表](https://docs.gl-inet.com/router/en/4/interface_guide/tailscale/#supported-models)

## 2. 测试程序与方法

使用 [Tailscale 官方静态程序](https://pkgs.tailscale.com/stable/)，固定版本 1.104.1。下载归档与官方 HTTPS checksum 文件核对 SHA-256；checksum 核对不等同于独立数字签名验证。

| 归档 | SHA-256 |
| --- | --- |
| tailscale_1.104.1_arm.tgz | aea7ae225989d302444b10b44aa42e89fdfa2a691b4d124ed710b4753518a875 |
| tailscale_1.104.1_mipsle.tgz | 6ad1f6c2d26f54f61312303ae9d2bad7a71b505b83ffc08cd77ed7f89875b3ac |

两个架构的版本输出均为 `1.104.1-t7f4efe814-g8da26756c`。SFT1200 上传后的 tailscaled 摘要与本地文件一致：`e1e81233070e9728e21c38c6bb9d9e32f4eb9fc8f3692d966811779089af81bd`。

CM201-2 使用临时网络与挂载命名空间，测试环境只有 loopback 和测试 TUN；宿主 LAN/WAN、策略路由与防火墙不在该网络视图内。私有挂载视图将 /etc 设为只读，并挂载对应测试网络的 sysfs；检查时无 system D-Bus socket 或 Tailscale DNS 残留。

daemon 配置使用 enabled=false、acceptDNS=false、acceptRoutes=false、advertiseRoutes=[]、netfilterMode=off，状态为内存存储，独立 socket、TUN 和临时目录。进程关闭 TCP/UDP GRO，使用旧内核保守测试参数。两次短测均成功初始化；不代表默认 offload 配置已验证。

不能直接在宿主机运行一个“未登录 daemon”来假设完全没有网络动作：该版本启动时仍做 DNS/路由清理，创建 OS Router 时也会添加规则。相关行为已核对[固定版本启动流程](https://github.com/tailscale/tailscale/blob/v1.104.1/cmd/tailscaled/tailscaled.go)与 [Linux router 实现](https://github.com/tailscale/tailscale/blob/v1.104.1/wgengine/router/osrouter/router_linux.go)。

SFT1200 的上述组合 unshare 调用返回 EINVAL，表示本次隔离方式不可用，尚未区分具体缺失哪一种命名空间。**Tailscale 本身不以这套测试隔离方式为运行前提，不能据此判定 Tailscale 不兼容。** 因此仅执行版本命令和独立最小 TUN ioctl 测试，未把正常 daemon 放到宿主网络运行。

## 3. CM201-2 的实测结果与限制

- tailscaled 创建 tscompat0，接口 UP、MTU 1280；用户空间 WireGuard 引擎及 LocalBackend 初始化完成。
- 本地 API 返回 TUN=true、BackendState=NeedsLogin、AuthURL 为空，没有 tailnet 地址；这是预期的未登录状态。
- 隔离网络内生成标准策略规则，正常退出后消失。宿主的 local/main/default 规则保持原状。
- 首次初始化后 VmRSS 为 26144KiB，约 25.5MiB；VmSize 约 578MiB 是虚拟地址空间，不能当作实际物理内存占用。该样本没有账号、peer 和流量，不能用作正式运行的内存上限。
- 日志出现旧内核相关的 setsockopt / netlink 清理警告，但未阻止本次引擎、TUN、规则与 API 初始化；后续仍需覆盖登录和真实转发路径。

当前实测证明旧 3.18 内核能够运行该 ARM 二进制并完成上述初始化。尚未验证真实外网连接、NAT 穿透、DERP、加密吞吐、子网转发、重启恢复和长期稳定性。不能把较新的 OpenWrt 用户空间版本当成内核已经升级。

## 4. SFT1200 的适配要点

### 程序与内核接口

官方 mipsle tailscaled 可执行并正常输出版本。独立探针成功完成 TUNGETFEATURES、带 IFF_NO_PI / IFF_VNET_HDR 的 TUNSETIFF，以及 CSUM/TSO4/TSO6 的 TUNSETOFFLOAD；关闭文件描述符后测试接口自动消失。两次测试结果一致。该检查没有设置接口地址、启用转发路由或修改防火墙。

这证明架构选择和所测 TUN ioctl 可用；没有测到正常 daemon 的实际常驻内存，也没有验证其完整网络初始化。

### 内存与安装空间

| 原始文件 | ARM | MIPSLE |
| --- | --- | --- |
| tailscaled | 35.8MiB | 39.2MiB |
| tailscale CLI | 30.5MiB | 33.3MiB |

MIPSLE 两个原始文件合计约 72.5MiB，大于测前 overlay 可用空间的未压缩预算，也大于 /tmp 的总容量。不能把归档压缩体积当作安装占用或运行内存。文件系统压缩可能改变实际占用，但不能据此预先保证双文件安装成功。

本轮仅将 tailscaled 临时放入独立 overlay 目录，避免用大文件挤占 tmpfs 与运行内存；测试结束已删除。正式适配宜评估同版本 multicall 单二进制或精简构建，保留子网路由和管理所需功能；精简产物必须重新验收，不能沿用官方二进制的测试结论。

### mwan3 与路由

现有 iproute2 4.16 支持策略路由，IPv4 forwarding 已开启，所查 rp_filter 为 0。mwan3 有 priority 2001 的非零 fwmark 规则。

v1.104.1 源码会在识别为 OpenWrt、存在 /etc/config/mwan3，且发现 priority 2001–2004 的非零 mark 规则时，改用 **1310/1330/1350/1370**。当前观察满足该识别条件，因此已有 mwan3 **不是已证实的冲突**；此结论来自源码与现有规则对应，尚未由 SFT1200 正常 daemon 的实际生成规则验证。[检测代码](https://github.com/tailscale/tailscale/blob/v1.104.1/wgengine/router/osrouter/router_linux.go)

正式测试必须覆盖远程客户端访问 LAN 后的回包、源 NAT、GL 防火墙重载和 WAN 重连。不能仅凭控制台在线或规则优先级正确就判定子网路由通过。

## 5. 现场拓扑与后续验收

本轮观察到 SFT1200 的 WAN 接在 CM201-2 的 LAN 下，二者目前是级联测试拓扑。本轮没有实际跨两个独立地点验证穿透。

后续建议先完成 CM201-2 的最小 IPv4 验证，再单独推进 SFT1200：

1. 在选定 tailnet 登录，保持 accept-dns=false、accept-routes=false，不启用退出节点；仅发布本机 LAN，控制台逐条批准访问权限与子网路由。
2. 手机切换移动数据，检查直连或 DERP 实际路径；分别验证 LAN 目标的 TCP、UDP 与回包，不能用路由器自身可达代替 LAN 转发验收。
3. 实测 fw3 重载、WAN 重连与重启恢复；SFT1200 需记录真实 daemon 内存、CPU、OOM 与连接状态，先短测再做两小时及 24 小时观察。
4. 独立验证 Web 管理的认证、监听范围与权限。此次没有启动节点 Web 或部署新的 LuCI 页面。

## 6. 清理与证据边界

两台短测前后，/etc/config 文件、resolv.conf、包数据库、宿主策略规则、路由和已加载模块均核对一致。防火墙结构比较去除了生成时间与流量计数，保留规则顺序；规范化后的短测前后摘要一致。

已删除两台上传的临时程序、测试配置、状态、日志和目录，以及 CM201-2 首次启动在默认 /var/lib/tailscale 下生成的日志配置。最后检查无 tailscaled 进程或测试 TUN 遗留；未安装包、未设置开机自启、未写入账号凭据。

原始诊断输出与下载清单保留在本机忽略目录 local/tailscale-compat-20261018/，不进入公开仓库。本文只记录与兼容性判断有关的事实，不包含设备密钥或用户认证信息。

本次 9 份实验源码、未登录测试配置与不含设备输出的产物摘要清单，另以原始文件归档于 [历史评估源码](../../tools/network-assessment/README.md)。该目录不含下载程序和现场诊断输出；依赖、执行副作用及复核顺序见归档说明。
