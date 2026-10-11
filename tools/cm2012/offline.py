"""build 的主机网络保护；子进程只调用本地锁定编译器。"""
import sys


def forbid_network():
    def audit(event, args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.gethostbyname'):
            raise RuntimeError('离线构建禁止网络访问，请先运行 prepare')
    sys.addaudithook(audit)
