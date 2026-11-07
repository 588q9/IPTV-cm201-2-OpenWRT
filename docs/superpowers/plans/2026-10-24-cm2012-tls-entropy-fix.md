# CM2012 订阅 TLS 取熵修复实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** 正式修复已通过三组对照确认的订阅下载取熵阻塞，并在 CM2012 上验证真实订阅下载。

**Architecture:** 新增专用 `cm2012-proxy-fetch`，通过锁定版本的官方 curl 头文件调用设备既有 `libcurl.so.4`，让 libcurl 继续负责 HTTPS、重定向及证书验证。程序仅导出 mbedTLS 的外部取熵回调 `mbedtls_entropy_func`，接到内核 `getrandom(flags=0)`；该下载器直接依赖内核 CSPRNG，保留 curl DRBG 与 prediction resistance。调用计数确认平台源确实被使用，否则失败。由现有订阅服务调用此程序，不设置 LD_PRELOAD，不替换系统 TLS 库。

**Tech Stack:** C99、Zig 0.13.0、curl 8.22.0 / mbedTLS 3.6.7、ucode、Python unittest。

**Spec:** [已验证故障与修复边界](../../公开文档/TLS握手故障诊断记录.md)。用户本轮“落实修改”授权实施与 SSH 验证，延续现有工作目录，保留此前未提交工作。

## Global Constraints

- 仅 CM2012；固定原厂 Linux 3.18、musl 和 ARMv7。
- 不关闭证书或主机名验证；仅允许 HTTPS 与 HTTPS 重定向，最多三跳。
- getrandom 等待 CRNG 就绪；EINTR 重试、处理短读，其他异常拒绝请求，无弱回退。
- 私有订阅 URL 只经权限 0600 文件传递，不写进参数或日志。
- 下载大小最多 4194304 字节，连接超时 10 秒、传输超时 35 秒；原有事务总超时仍负责终止早期开机取熵等待。
- 保持订阅、网络配置与直连状态；验证真实下载但不自动开启 LAN 分流。
- 安装前生成校验和与可回退补丁，保留已有备份链；不写原始分区、不重启。

## Review Focus

- 系统熵源不可用、短读或中途失败时不使用半成品随机数据。
- 未来 curl/mbedTLS 版本或符号绑定变化时拒绝请求，不静默退回阻塞路径。
- 证书不可信、错误主机名与降级 HTTP 重定向必须失败。
- 无 Content-Length 的超限内容也必须被写入回调限制并删除残留。
- 下载失败的日志、参数和补丁不包含订阅地址或响应正文。

## Task 1: 专用下载器与构建接入

- [x] 为平台熵源写 C 行为测试，观察缺少实现时失败；实现 EINTR、短读、失败清理与调用计数并通过测试。
- [x] 为下载器写可在 Linux 实际运行的 TLS 测试，覆盖证书拒绝、HTTPS 重定向、超限响应与私有 URL 传递；观察实现缺失失败。
- [x] 新建 `tools/cm2012/proxy_fetch.c`，只接受 URL 文件和输出文件两个参数，使用官方头文件与 dlopen API；验证锁定 TLS 后端及实际熵源调用。
- [x] 在 `resources.lock.json` 锁定官方 curl 8.22.0 源码头文件，在 `compiler.py` 编译并检查动态依赖，在 `build.py` 装配、校验 libcurl 间接依赖。
- [x] 修改 `cm2012-proxy-native.uc` 的 fetch 调用，补齐外层超时返回码 124，保留解析和清理；执行项目公共测试与离线编译。

## Task 2: 实机安装和业务验证

- [x] SSH 只读核对现场状态、版本与未完成事务，在 RAM 运行新下载器确认实际平台取熵绑定。
- [x] 生成仅下载器和调用端的补丁、安装前校验及备份；安装后逐文件比对。
- [x] 通过实际服务 fetch 下载保存的真实订阅，脱敏报告结果；不输出节点、URL、Token 或正文。
- [x] 核对订阅、网络配置、策略路由、热点和 DNS 状态，清理 RAM 测试目录。
- [x] 独立审查本次差异，更新公开实施说明及诊断记录，报告已验证边界。

## 执行记录

- 已观察未安装下载器时 8 项实机 TLS 回归全部失败（127）；新增边界测试通过。
- 实机发现 libmbedcrypto 将内部平台源本地绑定，导出 `mbedtls_platform_entropy_poll` 无法替换它；回归仍失败，进程等待点为 `_random_read`，启动后回调计数为零，下载器按设计拒绝继续。
- 调整：改为专用进程导出已通过此前三组单变量验证的 `mbedtls_entropy_func`；直接使用已就绪内核 CSPRNG，不再声称保留 mbedTLS 熵累积器。独立安全审查确认此回调满足 CTR_DRBG 输入契约。成本是该下载器仅依赖内核强随机源；接口故障时拒绝下载。
- 代码与构建接入的首轮独立审查未发现部署阻断问题；补充 124 超时映射，已观察测试从通用错误失败转为正确超时通过。

- 最终发现并修正订阅服务的 User-Agent 分支；同址对照由 0 字节变为有效配置。空响应检查、外层超时及实际客户端标识均已观察失败后通过。
- 公共回归 127 项（2 跳过）、离线编译、9 项最终实机 TLS 回归与正式下载器真实订阅解析通过。独立审查无阻断发现。未验收的导出符号专门断言及间接依赖缺失专门 fixture 作为覆盖边界记录，不影响已实测的绑定及依赖闭包。
