"""CM201-2 公开项目入口；资源下载与离线构建明确分开。"""
import argparse
import getpass
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError('本流程要求 Python 3.12，请使用已安装的 3.12 解释器')
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prepare = commands.add_parser('prepare', help='联网准备全部固定资源')
    prepare.add_argument('--import-dir', type=Path, help='优先导入已有且摘要一致的缓存')
    configure = commands.add_parser('configure', help='保存被 Git 忽略的原厂档案和热点配置')
    configure.add_argument('--stock-dir', type=Path, required=True)
    configure.add_argument('--port', default='COM3')
    check = commands.add_parser('check', help='离线核对依赖与原厂输入')
    check.add_argument('--device', action='store_true', help='同时经串口只读核对硬件')
    build = commands.add_parser('build', help='Windows 编译并在盒子 RAM 目录隔离安装')
    build.add_argument('--output', type=Path, default=ROOT / 'output/current')
    build.add_argument('--ssh-host', help='通过已信任主机密钥的 SSH 在盒子 RAM 中隔离构建')
    network_bundle = commands.add_parser('network-bundle', help='只读快照现有系统，生成网络增量安装/撤销包')
    network_bundle.add_argument('--rootfs',type=Path,required=True,help='新构建的完整 rootfs.tar.gz')
    network_bundle.add_argument('--ssh-host',required=True)
    network_bundle.add_argument('--output',type=Path,default=ROOT / 'output/network-update.tar.gz')
    network_deploy = commands.add_parser('network-deploy', help='校验、安装或撤销网络增量；不操作分区')
    network_deploy.add_argument('--bundle',type=Path,required=True)
    network_deploy.add_argument('--ssh-host',required=True)
    network_deploy.add_argument('--action',choices=('check','install','rollback'),default='check')
    verify = commands.add_parser('verify', help='校验本次生成清单和完整产物')
    verify.add_argument('--output', type=Path, default=ROOT / 'output/current')
    ram = commands.add_parser('ram-test', help='通过串口启动新 RAM 镜像，NAND 只读')
    ram.add_argument('--output', type=Path, default=ROOT / 'output/current')
    ram.add_argument('--bootstrap', action='store_true', help='仅启动独立 RAM 构建环境')
    install = commands.add_parser('install', help='只重建 userdata 根系统，清除内部配置与密钥')
    install.add_argument('--output', type=Path, default=ROOT / 'output/current')
    install.add_argument('--erase-internal-root', action='store_true', required=True)
    commands.add_parser('restore', help='RAM 验收后同步并重启回原内部系统')
    args = parser.parse_args()
    if args.command == 'network-bundle':
        from cm2012.remote_update import snapshot_update
        destination = args.output.resolve()
        if not destination.is_relative_to(ROOT):
            raise ValueError('输出必须位于本工作区内')
        print(snapshot_update(ROOT,args.rootfs.resolve(),args.ssh_host,destination))
        return
    if args.command == 'network-deploy':
        from cm2012.remote_update import deploy
        print(deploy(args.bundle.resolve(),args.ssh_host,action=args.action))
        return
    from cm2012.resources import prepare as prepare_resources, read_lock, verify_resource
    if args.command == 'prepare':
        prepare_resources(ROOT, args.import_dir)
        from cm2012.profile import activate_dependencies
        activate_dependencies(ROOT)
        print('准备完成；后续 build 不访问网络')
        return
    if args.command == 'configure':
        from cm2012.profile import configure as configure_project
        configure_project(ROOT, args.stock_dir.resolve(), input('热点名称：'),
                          getpass.getpass('热点密码：'), getpass.getpass('root 管理密码：'), args.port)
        print('本地配置已保存；不包含可公开提交的秘密配置')
        return
    from cm2012.profile import load_config, load_settings, activate_dependencies
    if args.command == 'restore':
        config = load_settings(ROOT)
        activate_dependencies(ROOT, names=('pyserial',))
        from cm2012.ram import restore_internal
        restore_internal(config)
        return
    if args.command != 'verify':
        for item in read_lock(ROOT).values():
            verify_resource(ROOT, item)
    config, stock = load_config(ROOT)
    if args.command == 'check':
        if args.device:
            activate_dependencies(ROOT, names=('pyserial',))
            from cm2012.build import check_device
            from cm2012.serial_link import Link
            with Link(config['port']) as link:
                check_device(link, config)
        print('锁定资源和原厂输入检查通过')
        return
    output = args.output.resolve()
    if not output.is_relative_to(ROOT):
        raise ValueError('输出必须位于本工作区内')
    if args.command == 'build':
        if not args.ssh_host:
            activate_dependencies(ROOT, names=('pyserial',))
        from cm2012.build import build
        build(ROOT, config, stock, output, ssh_host=args.ssh_host)
    elif args.command == 'verify':
        from cm2012.artifacts import verify_output
        verify_output(output, config, stock)
    elif args.command == 'ram-test':
        activate_dependencies(ROOT, names=('pyserial', 'pyserial-asyncio', 'ymodem', 'ordered-set', 'pycryptodomex'))
        from cm2012.ram import ram_test
        ram_test(ROOT, config, stock, output, bootstrap=args.bootstrap)
    elif args.command == 'install':
        activate_dependencies(ROOT, names=('pyserial', 'pyserial-asyncio', 'ymodem', 'ordered-set', 'pycryptodomex'))
        from cm2012.installer import install
        install(ROOT, config, stock, output, erase_internal_root=args.erase_internal_root)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, FileNotFoundError, TimeoutError) as error:
        print('停止：' + str(error), file=sys.stderr)
        sys.exit(1)
