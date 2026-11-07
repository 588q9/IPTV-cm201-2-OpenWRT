# CM201-2 订阅 TLS 握手故障诊断记录

后续：2026-10-24 已落实正式下载器修复，真实订阅下载和解析通过，见 [正式修复与验证](TLS正式修复与验证.md)。

日期：2026-10-22。依据 [取证方案](TLS握手取证方案.md)，通过限定连接抓包、函数计时和三组单变量对照，已定位本次失败的本地原因：**curl/mbedTLS 在握手内阻塞读取 `/dev/random`，使 ClientHello 延迟约 4 秒，碰上对端连接关闭，最终报 EOF。**

此前根据“同目标 OpenSSL 成功、mbedTLS 失败”提出的握手特征兼容或策略假设，没有得到包时序支持，应由本记录中的实测结论取代。仍不能只凭设备端数据包判断连接关闭由真实服务端还是中间设备发起，但这不影响已经复现的本地延迟原因。

## 实机与采集方式

设备保持原厂 Linux `3.18.24_hi3798mv2x`、OpenWrt musl 用户空间，curl 8.22.0 / mbedTLS 3.6.7，独立 OpenSSL 3.5.9。当前订阅只在设备上读取；测试使用同域名源站根路径，不发送订阅路径、查询串、Token、Cookie 或 Authorization，不跟随 HTTP 重定向。

由于设备没有 tcpdump，使用已锁定 Zig 0.13.0 编译 28 KiB 级的临时 ARMv7 采集器，上传独立 RAM 目录运行。采集器不启用混杂模式，在启用接收前附加四元组 BPF 过滤器；只保存指定本地/远端 IPv4 和端口的 TCP 包。每个进程最多运行 20 秒、200 包、约 2 MiB。内核 BPF 自测 11 个案例通过，覆盖双向匹配及地址、端口、协议、分片和短包拒绝。

离线分析器重组 TCP 序号，区分乱序、重传、缺段、冲突数据和跨段 TLS 记录，输出结构和相对时间，不输出 IP、域名、证书、密钥或应用载荷。11 项合成 PCAP 用例通过。首次采集启动失败得到的空包文件已排除，不计入证据。

## 基础对照的实际时序

固定同一目标 IP、443 端口、域名 SNI、直连、IPv4 和证书验证，交替执行三次 curl 与三次 OpenSSL。以下延迟从客户端完成 TCP 三次握手的 ACK 开始计算。

| 轮次 | curl 发出 ClientHello | 收到服务方向 FIN | OpenSSL 发出 ClientHello |
| --- | --- | --- | --- |
| 1 | 3618.831 ms | 3448.828 ms | 4.643 ms |
| 2 | 4000.809 ms | 3079.581 ms | 4.470 ms |
| 3 | 3044.289 ms | 3344.294 ms | 4.554 ms |

curl 三次均收到 0 字节服务方向 TLS 数据，没有明文 TLS Alert；服务方向 ACK 均未确认任何客户端 TLS 载荷。前两次 FIN 到达时 ClientHello 还未发出，故不能解释为对端根据该 ClientHello 的指纹拒绝。第三次虽然 ClientHello 先发，仍未得到 TLS 载荷确认；单点抓包不能证明真实服务端是否已收到。

三次 curl 载荷无重传或缺段；第三次存在一次 SYN 重传，不能笼统称所有 TCP 包都没有重传。OpenSSL 三次均迅速发包并成功收到 TLS 1.3 服务端握手。六次 SNI 一致；curl 的提议中也包含成功使用的 TLS 1.3 ChaCha20 套件和 X25519。

脱敏记录：本机 `local/network-tls-packet-timing-20261022.log`；六份原始 PCAP 及各自分析 JSON 位于 `local/private-tls-packets-20261022/613fb47f1ded/`，均被 Git 忽略。

## 函数计时定位

只在无订阅凭据的独立测试进程使用临时观测库计时，不改参数、返回值、系统库或随机数来源。计时包含墙钟与线程 CPU 时间，并只输出函数名、耗时和退出状态，不输出随机数据。

一轮代表性结果：

| 项目 | 墙钟耗时 | CPU 耗时 | 含义 |
| --- | --- | --- | --- |
| 实际 `/dev/random` 读取，6 次 | 10512.709 ms | 2.356 ms | 大部分时间在等待；包含全局初始化与握手，不能重复累加下列嵌套函数 |
| DRBG 初始化 | 3997.021 ms | 1.464 ms | 进程初始化时取熵等待 |
| 握手内两次 DRBG 随机数调用 | 3912.480 ms | 1.414 ms | 直接解释连接后的首包延迟 |
| CA 文件加载与解析 | 30.352 ms | 30.250 ms | 不是本轮数秒延迟的主要来源 |
| TLS setup | 0.101 ms | 0.101 ms | 无显著阻塞 |

实际导出的熵设备变量为 `/dev/random`，对该文件 `fread()` 的计时也直接确认阻塞。内核随机数接口只读探针显示：当时 `entropy_avail=2`，非阻塞读取 `/dev/random` 返回 EAGAIN；`getrandom(flags=0)` 读取 32 字节连续两次约 0.012 ms。探针不输出或保存任何随机字节，也不修改熵池参数。

脱敏记录：本机 `local/network-tls-profile-random-device-20261022.log`、`local/network-random-latency-20261022.log`。

## 上游行为与设备为何受影响

mbedTLS 3.6.7 的 Linux `getrandom()` 编译分支要求相应 libc 条件，musl 构建通常转入随机设备读取路径。本机已直接确认该路径读取 `/dev/random`。[mbedTLS 3.6.7 源码](https://raw.githubusercontent.com/Mbed-TLS/mbedtls/mbedtls-3.6.7/library/entropy_poll.c)

上游自 3.6.6 起把回退设备改为 `/dev/random`，并明确说明 Linux 5.6 以前即使已有足够随机性，也可能出现阻塞。本机运行 3.6.7；这属于该安全修复后在旧内核上的回退行为，不代表设备仍运行公告涉及的旧漏洞版本。[上游说明](https://mbed-tls.readthedocs.io/en/latest/security-advisories/mbedtls-security-advisory-2026-03-dev-random/)

curl 8.22.0 为其 mbedTLS DRBG 启用 prediction resistance，每次随机数调用前重新取熵，因此握手内会再次触发等待。[curl 8.22.0 源码](https://raw.githubusercontent.com/curl/curl/curl-8_22_0/lib/vtls/mbedtls.c)

## 单变量因果验证

只在独立测试进程中，将 `mbedtls_entropy_func` 回调临时接到本机已验证可用的 `getrandom(flags=0)`。此接口在内核随机数系统未就绪时会等待；不使用弱回退、不注入自制熵、不关闭 prediction resistance，证书与主机名验证仍开启。临时回调仅用于诊断，不是生产补丁。

固定同一地址、SNI、TLS 参数与根路径，按 A/B/A/B/A/B 顺序测试；每次保留限定连接 PCAP：

| 轮次 | 原路径结果 / ClientHello 延迟 | getrandom 测试路径结果 / ClientHello 延迟 |
| --- | --- | --- |
| 1 | curl 35 / 3981.269 ms | 成功 / 42.570 ms |
| 2 | curl 35 / 3935.569 ms | 成功 / 42.825 ms |
| 3 | curl 35 / 3990.236 ms | 成功 / 38.833 ms |

三次测试路径均通过证书验证，完整 TLS 建立时间分别约 139、168、136 ms，源站根路径返回 HTTP 307。307 表示已到达 HTTP 阶段，不代表真实订阅下载或代理业务已验收；测试不跟随重定向，也未发送私人订阅凭据。

脱敏记录：本机 `local/network-tls-entropy-ab-20261022.log`；六份单变量对照 PCAP、分析 JSON 和摘要位于 `local/private-tls-entropy-ab-20261022/9d71a0577ab3/`。采集前后的项目、网络、DHCP、防火墙、订阅 UCI、APK 数据库摘要、热点/DNS 进程及策略路由一致。

## 结论、修复边界与现场状态

此次 TLS 故障已有可重复因果证据：**旧内核上 `/dev/random` 读取阻塞，被 curl/mbedTLS 握手内的重复取熵放大，使 ClientHello 首包迟到，碰上对端的连接关闭窗口，报 `MBEDTLS_ERR_SSL_CONN_EOF`。** 单变量替换为保持就绪检查的内核 getrandom 后，延迟消失且三次握手成功。

正式修复应让订阅下载安全使用可用的 getrandom 路径，并在接口不可用或取熵失败时保留安全回退或拒绝请求；也可评估经过同地址验证的独立 TLS 下载器。需要把构建、版本锁、错误处理和早期开机随机数就绪纳入验证，不能把临时 LD_PRELOAD 观测/试验当作已交付的生产修复。不通过关闭证书校验、关闭随机数保护或无就绪检查地强制 `/dev/urandom` 解决。

本轮只完成诊断及临时因果验证。临时设备程序、库和采集目录已清理，生产下载器与 TLS 库没有修改，代理仍停用。连接关闭方的精确内部超时/策略名称仍需服务端或链路设备日志；真实订阅下载、节点、客户端流量、重启及长期运行仍待正式修复后的业务验收。
