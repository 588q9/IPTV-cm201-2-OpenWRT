# CM201-2 网络扩展实施计划

**目标：** 按已有《DDNS、异地访问与 LAN 自动分流方案》实现 CM201-2 的三项独立服务、Web 配置、保护和离线交付；SFT1200 留待后续研究。

**设计依据：** [现有方案](../../公开文档/DDNS与异地访问及代理方案.md)。用户本轮直接要求按该方案实施，因此沿用已有设计，不另行增加设计审批。

**结构：** 保留原厂 3.18 内核、fw3/iptables legacy、现有无线和网络事务。扩展使用独立 UCI 包、所有权标记和受限 RPC；镜像默认停用，凭据在设备本地填写。代码与离线测试可完成的部分先实现；账号授权、真实流量、两小时及 24 小时运行须记录实际证据。

## 任务与接口

- [x] 固定官方 ARM 程序、静态 UI 和 APK 完整依赖，保留各 feed 路径；`remote_assets.asset_files(root)` 供构建合并，下载和离线构建分开。
- [x] Tailscale 默认停用服务、实际 LAN 发布、来源限定 fw3 转发和 SNAT、受限配置入口；`tailscale.configuration()` / `runtime_files(root)` 供运行时合并。
- [x] Mihomo 安全订阅生成、TUN/DNS/策略路由、90 秒事务、故障 guard、LuCI/MetaCubeXD；`proxy.configuration()` / `runtime_files(root)` 供运行时合并。
- [x] 根侧接入标准 DDNS 默认值、网络写入互斥、LAN/防火墙生命周期协调，以及不改分区的增量包和撤销入口。
- [x] 回归测试、独立审查、中文说明和清晰的实机未验收边界。

## 共享约定

- 写配置时短暂独占 `/tmp/cm2012-wifi/apply.lock`；持锁检查已有网络、代理事务并建立本次持久记录后释放。未确认事务拒绝其他应用。
- 原网络 journal 为 `/etc/cm2012-transaction`；代理 journal 为 `/etc/cm2012-proxy-transaction`。
- 生命周期使用 `/usr/libexec/cm2012-proxy suspend|reconcile` 和 `/usr/libexec/cm2012-tailscale suspend|reconcile`；事务中撤销接管，LAN 稳定且确认后重建。
- 代理规则 table 2022 / priority 11000–11031，不覆盖用户占用；DNS 显式 DNAT 到实际 LAN IPv4:1053；不改本机 OUTPUT、系统 dnsmasq 上游。
- 订阅、设备密钥、Token、运行状态不进入公开资源或镜像。

## 验证重点

关键行为先失败后实现：无效/恶意订阅、策略冲突、并发事务、未确认重启、健康失败、依赖路径碰撞、安装来源漂移和精确撤销。公开回归使用 Python 3.12 与 Node fixtures；旧内核、UDP、蜂窝访问及长期运行必须实机验证。

## 执行记录

- 当前工作区已在网络扩展分支 `codex/remote-networking`，直接在此分支实施；不新建或切换工作区。
- 初次默认 Python 3.7 运行不符合项目要求，改用桌面运行时 Python 3.12.14 后基线 102 项通过，跳过 2 项 Linux 专属测试；两份已有 Node fixture 通过。
- 2026-10-21 完成上述代码与文档交付。完整 Python 回归运行 130 项，结果 OK，2 项 Linux 专属测试在 Windows 跳过；全部 Node fixtures 通过，独立审查发现的问题已补回归并修正。
- 在 CM201-2 原厂 3.18 内核上完成签名 APK 离线构建、原生 UCI/ucode 测试、隔离 fw3 规则生成及 Mihomo TUN/API/DNS 探测。隔离测试未接管现场客户端流量。
- 通过 SSH 安装增量包、实际撤销并重装最终版；未改分区、未重启。原网络配置、APK 数据库和热点/DNS 进程保持不变，DDNS、Tailscale 与代理均默认停用。启用与撤销说明见 [实施与启用](../../公开文档/CM2012网络扩展实施与启用.md)。

## 后续业务验收

2026-10-22 已补订阅独立保存、应用阶段反馈、脱敏错误与准备/确认两段超时，完成 131 项回归（2 项跳过）及五文件实机更新。现场实际应用复现订阅 TLS 握手失败，错误可见，地址保留、直连不变；真实客户端分流仍未验收。

以下项目不属于已通过的实机业务验收，需要设备本地凭据及真实客户端：

- [ ] Cloudflare 独立 DNS 记录与受限 Token 的实际更新。
- [ ] Tailscale 登录、控制台路由批准、来源权限拒绝与手机蜂窝访问 LAN。
- [ ] 真实订阅、下游客户端 TCP/UDP/DNS 分流及故障恢复。
- [ ] 启用后的实际重启恢复、两小时负载与 24 小时观察。
- [ ] SFT1200 的独立适配研究。
