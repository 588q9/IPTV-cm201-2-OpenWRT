# CM201-2 Release Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复公开凭据和增量更新风险，整理现有模块，验证后合并 main 并发布源码预发布。

**Architecture:** 保留现有功能与接口；将 ELF/补丁、根系统、产物、安装包和验收从编排层下沉。增量更新在 SSH 前验证并使用本地受信 updater；公开提交与附件使用独立隐私检查。

**Tech Stack:** Python 3.12、Zig 0.13.0、Node 24.9.0、ucode、BusyBox、原厂 3.18、fw3/iptables legacy。

**Spec:** `docs/superpowers/specs/2026-11-01-release-readiness-design.md`（用户 2026-11-01 已批准实施，含后续凭据范围澄清）。

## Global Constraints

- HTTPS 暂缓，不修改现有 HTTP/HTTPS 管理策略，不作为本轮门槛。
- 不接触现场设备，不刷机、不重启、不启用业务；保留刷机入口和 MTD 保护。
- 系统归档保留 mode、UID/GID、执行位和目录遍历权限；私密限制只施加于外层作业和敏感文件，umask 使用局部作用域。
- 不输出实际订阅、口令、hash 或 API 密钥；本机原厂资料、输出和日志不进入提交/附件。
- 保持 CLI、设备路径、UCI/RPC 接口和默认停用策略；不升级锁定无线包。
- 用户授权已包含实施、合并和发布；无需重复请求流程确认。遵守远端实际保护规则。
- 本机原有修改是待发布功能的一部分，逐一审查后纳入提交，不覆盖或删除。

## Review Focus

- 旧包与恶意归档：可信安装脚本、严格完整成员集、规范路径与大小上限；Task 1 在 SSH mock 尚未调用时断言拒绝。
- 多跳链接和回滚：不能从公开路径访问 shadow/私密状态；Task 1 覆盖固定 GeoIP、合法 rc.d 链接、链/循环、危险 before。
- 权限与根系统：串口交互 shell 的 umask 不漂移，维护工具仍可执行；Task 2/3 对比归档元数据与私密容器创建命令。
- 凭据进入第三方参数/日志：Task 2 用合成 Token 和模拟 curl 断言 argv/verbose 不含秘密并正确清理临时文件。
- 完全离线或缺缓存：Task 4 覆盖签名快照导入、许可缺失、curl 缓存输入变化；Task 3 验证 restore 不依赖无关缓存。

## Task 1: Incremental update trust and link policy

**Files:** `tools/cm2012/update_policy.py`（新）、`tools/cm2012/remote_update.py`、`tools/cm2012/device/network-update.uc`、`tests/test_public_remote_update.py`、`tests/fixtures/cm2012-update.cjs`，必要的声明式 policy 文件和 fixture。

**Interfaces:** 保留 `allowed_path(name)`、`allowed_record(name,record)`、`fingerprint(entry)`、`make_update(root,before,after)`、`snapshot_update(root,rootfs,host,output)`、`deploy(bundle,host,*,action='check')`。`update_policy` 提供 schema/path/link 验证和规范 bundle 函数；本地 updater 来源以模块定位仓库为准。

- [ ] 新增回归，证明未知成员、恶意 updater、非规范路径/类型、坏 manifest、超限、私密 Web 链接在 SSH 前失败；先记录失败。
- [ ] 实现受限归档读取、记录与完整成员校验；兼容旧 updater 文件名但从本地可信源码替换其内容，上传规范重打包字节。
- [ ] 主机和设备共享声明式政策，设备复查实际链接链、父目录和撤销目标；保留固定 GeoIP 和合法程序/库/rc.d 链接。
- [ ] 运行 Python 更新回归、Node update fixture；保留并发修改与精确撤销测试。
- [ ] 形成任务差异和独立审查，修复后提交本任务。

## Task 2: Credential handling and private job helpers

**Files:** `tools/cm2012/credentials.py`（新）、`tools/cm2012/device_jobs.py`（新）、`tests/test_public_credentials.py`（新）、`tests/test_public_device_jobs.py`（新），必要的公开补丁/辅助模板。集成调用由 Task 3 执行。

**Interfaces:** `credentials.protect_root(entries: dict[str, Entry]) -> dict[str, Entry]` 对已锁定 Cloudflare 脚本作有前置条件的补丁；保持原 Entry 元数据，缺失（无 DDNS 的合成输入）可原样返回，存在但不匹配需明确失败。`device_jobs.create_private_job(link, path)` 检查 root 并用局部 umask/显式模式创建不复用的私密目录；不改变串口后续 shell 环境。

- [ ] 合成 token/curl fixture 证明原脚本的 argv/verbose 泄露，再实现私密 header/config/stdin 传递，清理临时文件，诊断输出先脱敏。
- [ ] 保持固定 APK 来源，记录脚本修改适用版本/来源和许可；不是任意脚本的模糊替换。
- [ ] 私密作业 helper 校验路径、身份和0700，文件0600、工具0700；测试串口命令不留下全局 umask。
- [ ] 运行本任务测试和 shell 语法验证；提供 Task 3 集成位置说明。
- [ ] 独立审查后提交本任务。

## Task 3: Module boundaries, CLI dependencies, build privacy integration

**Files:** 新 `elf.py`、`patching.py`、`rootfs.py`、`artifacts.py`、`install_bundle.py`、`acceptance.py`；调整 `build.py`、`compiler.py`、`legacy_firewall.py`、`installer.py`、`ram.py`、`images.py`、`profile.py`、`tools/project.py`、`device/build-job`；相应公共测试。

**Interfaces:** 新模块保留搬移函数原有签名：ELF/patch 算法；rootfs 的 `strip_runtime/resolve_file/validate_program/validate_root/make_seed/make_overlay`；artifacts 的 `assemble_outputs/verify_output`；install_bundle 的 `root_digest/make_install_env/install_archive`；acceptance 的 `RAM_CHECKS/record_ram_acceptance`。原公开导入允许单向再导出，不复制实现。CMDLINE 归 `images.py`。

- [ ] 利用现有合成根/归档/安装测试锁定内容、权限、UID/GID和摘要关系；增加 CLI restore/verify 在无关缓存缺失时仍可调度的行为回归。
- [ ] 按底层到上层移动实现并修正依赖，使 rootfs/artifacts/acceptance/install_bundle 不反向导入编排层。
- [ ] 使用 Task 2 的 protect_root 和 private-job helper；build-job 对结果/诊断创建采用局部私密权限，根系统内新文件显式保持应有模式。
- [ ] 删除无消费者的 packages.list/locked_packages，保留 APK 内容标识约束。只替换相应旧测试，不删有行为价值的覆盖。
- [ ] 配置读取拆分设置与原厂输入；按命令激活所需依赖，不削弱 build/install 检查。
- [ ] 全公共回归、导入烟测和 compiler integration；独立审查后提交。

## Task 4: Resource acquisition, metadata and feature composition

**Files:** `resources.lock.json`、`resources.py`、`compiler.py`、`remote_assets.py`、`runtime.py`、`remote.py`、`tailscale.py`、`proxy.py`、新小型模板读取 helper、`configs/resource-snapshots/`、资源/运行时测试、THIRD_PARTY。

**Interfaces:** `prepare` 支持可选的已验证 bundled source；保留缓存路径与锁定身份。统一模板 loader 输出 `dict[str,Entry]`，功能组合拒绝冲突；`configuration()` 独占 UCI 默认值。

- [ ] 对有来源记录的5份已签名索引按 SHA256 核验，保存公开快照和来源清单；有 bundled 输入时准备流程先验证再导入。
- [ ] 测试缺失/篡改快照不会联网绕过或放宽锁。保留旧无线索引，禁止替换 r5 身份。
- [ ] curl 归档根和许可来源集中且受校验；头文件缓存绑定输入摘要或安全重建；必需许可缺失立即失败。
- [ ] 统一模板读取与功能无冲突合并，消除 Tailscale 配置重复合并，保持最终归档内容/权限。
- [ ] 资源/运行时回归和编译集成；独立审查后提交。

## Task 5: Publication privacy gate and documentation

**Files:** 新 `tools/cm2012/publication.py`、`tests/test_public_publication.py`、CI、`.gitignore`、README、变更记录、架构功能索引、发布说明、THIRD_PARTY。

**Interfaces:** publication 检查明确的 Git 树/索引（可选工作候选），只返回规则/路径/行号；可选本机 known-secret 比对不写入值或值的摘要。源码包只从提交树生成。

- [ ] 用合成私钥/token/crypt hash/订阅和受限样例测试秘密检测、日志脱敏、二进制 allowlist；不能整目录豁免 tests/docs。
- [ ] CI Windows/Ubuntu 使用只读内容权限运行公共测试和公开树扫描，确保必要 Node fixture 覆盖。
- [ ] README/变更记录/架构索引说明功能、入口、测试、可信缓存前提、敏感产物和未验收范围；修正代理 secret 存储文案。
- [ ] 按白名单审查所有原有未提交源码、模板、测试和文档，不加入私有现场资料。
- [ ] 在干净的仅公开文件目录运行公共测试，形成全分支独立审查并修复。

## Task 6: Merge and source prerelease

**Files:** Git 提交、远端分支/PR、发布源包/清单/SHA256；仅使用批准代码树。

- [ ] 验证完整公共回归、锁定离线交叉编译、最终树隐私扫描、git diff --check 和独立审查均通过。
- [ ] 取得 canonical 远端 main/保护/已有tag的最新状态；推送功能分支并按保护规则建立PR，等待必需 CI 成功。
- [ ] 核对 head SHA 后合并 main，更新本机 main，保留功能分支；核对合并后的远端 SHA。
- [ ] 使用首个未占用的 `v0.2.0-rc.N`，创建源码预发布；包中只含提交树，附文件清单与 SHA256。
- [ ] 读取 Release 页面、tag/commit与附件状态确认发布；报告验证范围和未验收项，不把源码预发布称为完整设备验收。

## Execution record

实施由当前会话自主推进；安全/资源等不重叠任务可并行，Git 提交与集成串行。每项进度与裁定记入本计划专属的本机忽略 ledger，所有真实秘密只在本机内存比较。

## Task 7: DNS recurrence prevention (user scope extension 2026-11-02)

- [ ] Add bounded fixed private loopback probe/flush transport and real native protocol tests.
- [ ] DNS-only fallback group; two failed samples trigger cache flush/retest with cooldown; skip disabled/busy/local failure.
- [ ] Report local readiness and fresh external DNS/proxy state separately, no new secrets in status/logs.
- [ ] Record runtime-only incident accurately; document new code, probe destination and limits.
- [ ] TDD regressions, ARM build, fresh clean public suite and independent review before Task6 merge/release.
