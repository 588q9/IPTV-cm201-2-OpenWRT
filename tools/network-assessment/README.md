# Tailscale 历史评估源码（2026-10-18）

本目录归档 CM201-2 与 GL-SFT1200 的 Tailscale 1.104.1 现场评估代码，属于 `codex/remote-networking` 分支。完整结论见 [双路由兼容性评估](../../docs/公开文档/Tailscale双路由兼容性评估.md)，后续功能设计见 [网络扩展方案](../../docs/公开文档/DDNS与异地访问及代理方案.md)。

这是历史实验归档，不是安装入口或已经封装好的通用诊断工具。9 份源码和两份 JSON 均从本机 `local/tailscale-compat-20261018/` 原样复制；没有修改程序逻辑，也没有通过重新执行实验来验证归档。`archives.json` 保留原始 CRLF 字节，其他文件保留原始 LF。

## 文件与依赖

| 文件 | 当次用途 |
| --- | --- |
| inspect_archives.py | 核对官方归档 checksum，提取指定二进制，记录 SHA-256、大小与 ELF 架构 |
| probe.py | 两台设备地址、SSH/SCP 公共函数与命名空间预检 |
| run_probe.py | 测前/测后快照、程序版本与分设备的有限运行测试 |
| final_check.py | CM201-2 的规范化防火墙快照与第二次隔离初始化 |
| sft_final_check.py | SFT1200 的规范化快照与第二次最小 TUN 测试 |
| cleanup.py | 删除当次实验已确认创建的精确路径，检查进程和接口遗留 |
| cm-inside.sh | 在已建立的私有命名空间内运行并停止 CM201-2 测试 daemon |
| netns_exec.c | 建立私有网络、挂载命名空间与只读 /etc 视图 |
| tun_probe.c | 创建和关闭非持久 TUN，检查所用 ioctl |
| disabled.json | alpha0 未登录、禁用路由广告与 DNS 接管的测试配置 |
| archives.json | 官方 ARM/MIPSLE 归档及解包程序的摘要、大小和 ELF 信息 |

当次控制端使用 Windows PowerShell、Python 3.7.4 标准库、OpenSSH 的 ssh/scp 和 Zig 0.13.0。源码未做更新版本兼容性认证。SCP 使用旧协议 `-O`；SSH 使用已有 known_hosts、免密 root 密钥和显式 ssh-rsa 兼容参数。仓库不包含该私钥或账号凭据。

设备需要 root、/dev/net/tun、BusyBox/基础命令、ip、iptables-save 和 SHA-256 工具；具体能力和资源见评估报告。CM201-2 成功执行私有命名空间；SFT1200 的组合 unshare 返回 EINVAL，该失败不是完整 Tailscale 不兼容结论。

官方归档位于本机忽略目录 `local/cache/`：`tailscale_1.104.1_arm.tgz`、`tailscale_1.104.1_mipsle.tgz` 及其 `.sha256` 文件。下载来源为 [官方 stable 静态程序](https://pkgs.tailscale.com/stable/)。本目录不包含下载器、归档、编译器或已编译程序。

`inspect_archives.py` 从所在目录上两层定位仓库，再读取 `local/cache/`，因此本目录保持与原本地目录相同的层级深度。提取程序与编译辅助程序需在本目录的 `arm/`、`mipsle/` 子目录下；二者由忽略规则排除。其他脚本通过同目录导入相互依赖，不能只复制一个 Python 文件运行。生成的诊断 JSON 同样保持忽略。

## 当次编译参数

下面记录 Zig 的交叉编译参数，不会访问设备。若用于源码复核，所有输出写到独立、已忽略的本地构建目录，不覆盖原始证据；需要按环境替换 Zig 路径和输出位置。

| 辅助程序 | target | CPU | 其他参数 |
| --- | --- | --- | --- |
| ARM netns-exec | arm-linux-musleabihf | cortex_a15 | -Os -static -s |
| MIPSLE netns-exec | mipsel-linux-musl | mips32r2 | -Os -static -s |
| MIPSLE tun-probe | mipsel-linux-musl | mips32r2 | -Os -static -s |

调用形式为 `zig cc -target <target> -mcpu=<CPU> -Os -static -s <源文件> -o <输出文件>`。当次设置 `ZIG_GLOBAL_CACHE_DIR` 和 `ZIG_LOCAL_CACHE_DIR` 指向仓库 local 下的专用缓存。官方 tailscale/tailscaled 使用下载的静态程序，并未由这些命令编译。

## 历史执行顺序与边界

以下是当次执行记录的顺序，不能作为直接重放操作单。设备地址、日期、远端目录、现存服务和资源都必须重新确认，当前归档不负责自动适配这些差异。

1. 核对两台系统、内核、架构、TUN、路由/防火墙、资源、DNS 残留和 system D-Bus socket；确认无运行中的 Tailscale。下载和核对固定版本归档后，使用 inspect_archives.py 提取程序并生成清单。
2. 交叉编译 netns-exec；probe.py 为每台设备建立固定实验目录、上传辅助程序并做命名空间预检。SFT1200 在 EINVAL 后停止该项流程，仅保留版本及最小 TUN 测试路径。
3. CM201-2 由 run_probe.py 上传官方 CLI、daemon、配置与 cm-inside.sh，必须通过 netns-exec 启动脚本。SFT1200 先准备 tun-probe，再由 run_probe.py 将 daemon 临时放入 overlay，仅运行版本命令和独立 TUN 探针，不启动正常 daemon。
4. 初次防火墙摘要包含会增长的链计数，不能直接作为配置变化结论；final_check.py 和 sft_final_check.py 去掉生成时间与计数、保留顺序后重新比较，同时复核配置、路由和模块。CM201-2 的第二次测试还把日志目录明确放入实验目录。
5. 已确认当次进程退出后，cleanup.py 按已核验路径清理并检查接口/进程。原始证据只保存在本机忽略目录，报告保留相应结论。

代码包含以下实际执行副作用：

- probe.py 固定 CM201-2 为 192.168.50.1、SFT1200 为 192.168.250.1；远端目录固定为 `/tmp/tscompat-20261018-1405` 和 SFT1200 的 `/root/tscompat-20261018-1405`。日期和地址只反映当次现场。
- 导入 cleanup.py 就会 SSH 到两台设备并删除固定文件，其中包括 CM201-2 的 `/var/lib/tailscale/tailscaled.log.conf`。未来安装正式服务后直接重放可能删除其日志配置。归档时只做静态语法解析，不导入该模块。
- 导入 final_check.py 或 sft_final_check.py 会进行 SSH、快照或测试操作；导入 inspect_archives.py 会写目录、提取二进制和覆盖清单。probe.py、run_probe.py 有 main 入口保护，但执行仍会访问固定设备。
- cm-inside.sh 本身不检查命名空间。直接在宿主执行会启动 daemon 并产生网络动作；enabled=false、netfilterMode=off 不能单独隔离启动清理行为。
- tun_probe.c 会在调用者当前网络命名空间创建 TUN；关闭描述符后自动删除，没有配置地址和转发规则。可选 offload 失败只打印错误，不等同于探针整体失败。
- 部分快照匹配结果只打印 True/False，并不保证 False 时退出非零；这些脚本不能直接用作自动验收门禁。

此次实验没有登录、发布子网或启用常驻服务。CM201-2 的成功范围是隔离环境内的引擎、TUN、策略规则与本地 API 初始化；SFT1200 仅完成官方程序版本与独立 TUN ioctl。真实子网转发、穿透、吞吐、Web 管理及长期稳定性仍未验收。

## 本分支的归档验证

整理时仅核对原文件与归档文件的 SHA-256、UTF-8、Python AST/JSON 语法、文档链接、Git 白名单与暂存清单，不导入或执行实验脚本、不连接路由器。该目录不接入固件构建、现有命令入口、CI 或自动测试发现。

本地原始源码、7 份现场诊断输出、二进制和缓存继续保留在 `local/`，未删除、上传或提交。白名单仅允许本目录 README、上述 9 份源码及两份 JSON；新生成文件默认忽略。
