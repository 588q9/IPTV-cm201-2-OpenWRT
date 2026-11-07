# CM201-2 TLS 握手取证方案

日期：2026-10-22。目标是定位订阅下载的 TLS 失败，区分失败阶段、握手差异和可证实的原因。本文保留取证设计；执行已完成，实际根因为旧内核随机设备取熵阻塞，详见 [故障诊断记录](TLS握手故障诊断记录.md)。初始仅知 curl/mbedTLS 握手遇到 EOF、同目标 OpenSSL 成功时，不能直接断定 TLS 库缺陷或网络封锁。

## 当前已取得的证据

| 项目 | 实测结果 |
| --- | --- |
| 下载客户端 | curl 8.22.0，mbedTLS 3.6.7 |
| 直接错误 | curl 35，mbedTLS `-0x7280`，握手接收遇到 EOF |
| 同地址对照 | 两个固定 IPv4、同域名 SNI、同 443 端口，curl 失败，OpenSSL 3.5.9 完成 TLS 1.3 并通过证书和主机名验证 |
| 已排除的配置差异 | 代理环境、用户 curlrc、重定向；强制 IPv4、TLS 1.2/1.3、关闭 ALPN、指定 TLS 1.3 ChaCha20 套件仍未改善 |
| 当前设备工具 | 已有 curl、OpenSSL、timeout、netstat；未发现 tcpdump、dumpcap、tshark、strace |
| 重启影响 | 设备已重启，上次 `/tmp` 运行日志不能作为当前运行日志；必须标记启动会话并重新复现 |

本轮已额外采集源站根路径的客户端 trace，不发送订阅路径、查询串或 Token：curl 再次为 `-0x7280`，trace 仅 90 字节，未提供 SSL 报文记录；OpenSSL trace 为 36,785 字节，含 ClientHello、ServerHello、EncryptedExtensions、CertificateVerify 和双向 Finished，验证成功。配置摘要和策略路由在采集前后一致。

本机脱敏摘要为 `local/network-tls-trace-summary-20261022.log`。原始证据位于本机忽略目录 `local/private-tls-evidence-20261022/`，不进入公开仓库。初次 trace 阶段尚无包级证据，不能把“curl trace 没有记录 ClientHello”解释为网络上没有发送 ClientHello；后续已完成限定连接采集。

## 采集范围与固定条件

只对本次主动创建的测试连接取证，保留生产代理停用和现有网络配置。每次记录 UTC 时间、设备启动标识/运行时间、实际程序及 TLS 库版本和摘要、目标代号、固定 IP、端口、SNI、使用接口、源端口、测试参数和退出码。

目标代号用于关联私有原始证据，不在报告中公开真实域名。采集开始和结束均核对已保存订阅及网络配置摘要；若用户在采集中修改目标，标记本轮无效，重新建立对照，不能混用前后目标。

握手测试只访问从订阅提取的 `https://域名:端口/`，或仅完成 TLS 握手。HTTP 路径和方法在握手完成后发送，根路径可用于复现握手前错误；不使用真实订阅路径、查询参数、Authorization 或 Cookie。curl trace 会包含请求、响应及认证等内容，原始文件仍按私有证据处理。[curl 官方 trace 说明](https://curl.se/docs/manpage.html#--trace)

## 第一层：客户端状态与握手日志

以下是执行模板，变量由设备私有配置生成，不要求用户在聊天中粘贴域名或订阅。`tls_job` 为本次专用 RAM 目录，权限 0700，日志文件 0600；完成后复制到本机私有目录并校验摘要，防止重启丢失。

curl 使用私有配置文件，固定源站根路径、解析 IP、IPv4、直连、源端口 46080、CA 验证和最多 15 秒；不跟随重定向、不读取用户 curlrc：

```sh
curl -q --config "$tls_job/origin-curl.conf" \
  --trace-time --trace "$tls_job/curl.trace"
```

OpenSSL 使用相同 IP、端口、SNI 和信任根，源端口 46081，只握手，不发 HTTP：

```sh
timeout 20 openssl s_client \
  -connect "$tls_ip:$tls_port" -servername "$tls_host" \
  -bind 0.0.0.0:46081 \
  -verify_hostname "$tls_host" -verify_return_error \
  -CAfile /etc/ssl/cert.pem -state -msg -trace \
  </dev/null >"$tls_job/openssl.trace" 2>&1
```

必须显式保留 `-verify_return_error`，因为 s_client 默认可能继续处理验证错误；成功按握手状态与验证结果判断，不能只看进程退出码。[OpenSSL 官方说明](https://docs.openssl.org/3.5/man1/openssl-s_client/)

每组至少三次，交替执行 curl/OpenSSL，并固定同一地址。每次使用可区分的源端口；端口被占用或处于 TIME_WAIT 而不能绑定时，分配新的端口并同步更改抓包过滤器，不能把绑定失败算作 TLS 错误。

## 第二层：限定连接抓包

设备没有系统抓包工具。本轮在主机编译了兼容 ARMv7 与旧内核的临时限定连接采集器，在独立 RAM 目录运行并清理；未向活动根系统安装包或替换库。以下 tcpdump 命令是等价过滤范围的执行模板，实机使用的是自编译的一次性采集器。

抓包点为盒子的实际上联接口，不能在 Windows 普通网口上假定能看到盒子与服务端的全部单播流量。过滤器只接受本次测试的源/目标 IP 和端口；每次最多 20 秒、200 包，并设置总文件大小上限。执行模板为：

```sh
timeout 20 "$tls_job/tcpdump" -p -i "$tls_uplink" -nn -s 0 \
  -c 200 -w "$tls_job/handshake.pcap" \
  "tcp and host $tls_local_ip and host $tls_ip and port $tls_port and port $tls_source_port"
```

需要从包中建立以下相对时间线：TCP 建连 → ClientHello → ServerHello/Alert/数据 → FIN/RST/重传 → 本地库报错。确认连接关闭前已接收多少字节、是否存在 TLS 告警，以及双方关闭顺序。发送侧抓包可能受校验和卸载影响，不能只凭本机显示的坏校验和判断线路损坏。

ClientHello 对照提取版本、套件、扩展及顺序、ALPN、supported_groups、signature_algorithms、key_share 类型/长度、SNI 是否一致。比较时归一化随机数、session ID 和临时公钥内容；原始包保留在私有目录，公开报告仅输出结构摘要。

## 第三层：针对差异做单变量实验

先用包判断失败点，再选择参数，不继续盲目组合参数。对于疑似触发差异，只改一个参数，按 A/B/A/B 交替重复；至少三组可重复地从失败变成功，才将该参数列为有证据支持的触发因素。

若普通 trace 和 pcap 仍不足，再考虑与现有版本、构建选项一致的临时 mbedTLS debug 客户端，仅在 RAM 中测试源站根路径。不能假定当前发行版 curl 有一个通用环境变量可启用完整 mbedTLS 内部日志，也不能替换生产库后拿新行为解释旧故障。

TLS 1.3 的 ServerHello 后握手消息及相应状态下的 Alert 通常已加密。仅凭 pcap 未必能读出告警，需要端点日志；确有必要时，只为这次无订阅凭据的临时测试会话保存 keylog，保持私有，不提交或公开。[TLS 1.3 规范](https://www.rfc-editor.org/rfc/rfc8446)

## 根据证据如何判断

| 日志/包中的事实 | 可以支持的判断 | 仍不能直接确定的事项 |
| --- | --- | --- |
| 收到 `protocol_version` 告警 | 对端拒绝所提出的协议版本 | 是服务配置还是具体策略规则 |
| 收到 `unrecognized_name` 告警 | SNI/虚拟主机处理失败 | 原因在客户端输入还是服务端域名配置，需核对实际 SNI |
| 收到 `handshake_failure` 告警 | 对端明确拒绝握手 | 不能仅凭通用告警断定“没有共同套件” |
| ClientHello 后直接 FIN/RST，无 Alert | 连接在握手阶段被提前关闭 | 服务端还是中间设备发起；单点看到源 IP 不能排除伪造或中间设备代发 |
| 收到 ServerHello 后客户端退出，并有本地错误 | 可定位到客户端处理的具体握手阶段 | 需要内部日志判断扩展、密钥交换、解析或验证的哪一项失败 |
| 重传、部分段持续未确认 | 可能存在传输/路径问题 | 不能未验证就修改 MTU 或归责 TLS 库 |
| 同目标 OpenSSL 成功，mbedTLS 失败 | 失败跟随客户端握手路径 | 单纯存在 ClientHello 差异不能证明差异就是原因 |
| 改单一参数后结果反复翻转 | 该参数是可重复的触发因素，可能形成兼容修复 | 仍未必说明服务端关闭连接的内部策略名称 |

若最终只有静默断开，完整归因须由 TLS 终结点按时间、源公网 IP、SNI 查询握手/访问策略日志，并与设备包时间线对齐。上游设备的同步抓包可辅助区分链路中的关闭或丢弃行为。没有服务端或中间设备证据时，报告保留“不确定”，不把推测写成确定根因。

## 交付结果与停止条件

每轮交付一份脱敏摘要，分开列明观测事实、推断、已排除项、剩余不确定性和可验证的修复方向；私有附件保留参数、客户端日志、pcap、版本及 SHA-256。

本次已完成环境核对、第一层 trace、十二份有效限定连接 PCAP、函数耗时记录及三组取熵路径单变量对照。实验已稳定消除握手失败，按本方案停止扩大采集；结果与剩余边界见 [故障诊断记录](TLS握手故障诊断记录.md)。
