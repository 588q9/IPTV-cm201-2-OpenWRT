# CM201-2 公开仓库与完整离线构建实施计划

> 执行方式：用户已批准在当前会话直接实施。使用执行计划技能逐项完成，最后进行一次独立整体审查。

目标：形成可公开分享的源码仓库，能够从官方资源和用户原厂输入离线生成并在 RAM 验证完整系统。

架构：Windows 负责输入校验、交叉编译和镜像规范化，盒子提供隔离的 Linux APK 安装环境；资源、配置、备份和输出均留在忽略目录。

技术：Python 3.12、Zig 0.13.0、ARMv7 musl、apk 3、串口分块传输、newc/Android boot、UBI/UBIFS。

设计依据：[公开构建设计](../specs/2026-10-07-public-build-design.md)。

## 全局约束

- 所有 Markdown 中文；当前目录原地整理，原始资料保留。
- 前部核心八分区固定共 48MiB，剩余物理 NAND 全部归入 userdata；64 位大小和擦除块对齐。
- 原厂内核、驱动、引导器的兼容性校验不能随容量动态化放宽。
- build 离线且不依赖旧私人根归档；密码及私钥不入仓库。
- 串口单连接；RAM 测试 NAND 只读；本轮不刷写、不推送。

## 审查重点

容量超过 4GiB 的溢出、伪造几何、归档路径或链接越界、签名资源缺失、串口中断，以及失败后错误清理正在运行的根系统。各项在所属任务补充真实行为测试。

## 任务 1：公开边界与动态安装资料

文件：.gitignore、.gitattributes、tools/cm2012/layout.py、tools/cm2012/images.py、tests/test_public_layout.py。

接口：layout_for(total_bytes, erase_bytes) 生成九分区；make_bundle(boot, stock, profile) 消费已核对原厂输入，返回镜像文件和本次清单。

- [x] 写合成输入测试，核对 4/8/16GiB 最后分区与核心布局，拒绝非对齐、重叠、外来内核和错误摘要。
- [x] 运行测试观察失败；实现动态布局及来源校验；运行测试通过。
- [x] 白名单、许可、资源审计完成后初始化 main；本轮最终才提交和打标签。

## 任务 2：资源锁与独立 Windows 编译

文件：resources.lock.json、tools/project.py、tools/cm2012/resources.py、compiler.py、patches/、tests/test_public_resources.py。

接口：configure 写 local/config.json；prepare 下载已锁定资源；check 验证全部本地输入；compiler 输出确定性 ARM 程序。

- [x] 写缺失、篡改、离线路径和归档越界测试，观察失败。
- [x] 实现锁定资源校验、原厂档案清单、密码配置和安全提取。
- [x] 固定源码与兼容补丁，编译 ubusd、切根、mtd-utils 和串口程序；检验架构及动态依赖。

## 任务 3：隔离盒子作业与完整产物

文件：tools/cm2012/serial_link.py、build.py、device/、configs/templates/、tests/test_public_build.py。

接口：Link.upload/download 提供块 CRC 和整文件 SHA；build 与 device/build-job 只写专属 /tmp；read_tar_bytes/tar_bytes 保留权限与链接并规范化元数据。

- [x] 写传输中断、空间不足、错误依赖与归档规范化测试，观察失败。
- [x] 在 Windows 准备官方根与锁定本地 APK；在盒子隔离安装，禁网络、禁脚本和提交钩子。
- [x] 显式应用账户、网络和 AP 服务模板；检验关键文件后最后写内部根标识。
- [x] 导出根归档并生成 boot、RAM 镜像和动态安装清单；失败保留诊断，只清理本次目录。
- [x] 原厂 Android 环境提供独立 RAM 构建环境启动入口，不能循环依赖完整产物。

## 任务 4：可复现构建与 RAM 验收

文件：tests/test_public_*.py、tools/cm2012/ram.py、docs/公开文档/验收记录.md。

- [x] 纯测试无需备份；本机集成检查缺输入明确报错。
- [x] 核对盒子运行状态前后不变，主机禁网络钩子与 APK --no-network 下构建两次，逐一比较字节与摘要；电脑物理网络未断开。
- [x] 从新产物 RAM 启动，全部 MTD 只读，验证 ubus、热点、手机 DHCP、LuCI。
- [x] 恢复内部系统并核对启动状态。

## 任务 5：公开交付

文件：README.md、LICENSE、THIRD_PARTY.md、docs/公开文档/、.github/workflows/tests.yml。

- [x] 编写从零复现、资源提取、容量说明、恢复限制与验收说明；CI 只做纯测试。
- [x] 一次独立整体审查，修复重要问题并运行完整测试。
- [x] 审计暂存白名单、秘密、个人路径、授权和大文件。
- [x] main 初次提交与干净 Git 克隆测试完成；交付时创建本地 v0.1.0 标签，由用户自行上传 GitHub。
