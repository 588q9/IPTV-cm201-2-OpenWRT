"""使用已信任主机密钥的 SSH；文件传输限制在本次 RAM 作业目录。"""
import hashlib
import re
import subprocess

from .serial_link import check_device_path


class SSHLink:
    def __init__(self, host):
        if not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', host):
            raise ValueError('SSH 主机必须为 IPv4 地址或主机名')
        self.args = ['ssh', '-oBatchMode=yes', '-oConnectTimeout=8',
                     '-oStrictHostKeyChecking=yes', '-oHostKeyAlgorithms=+ssh-rsa',
                     '-oPubkeyAcceptedAlgorithms=+ssh-rsa', 'root@' + host]

    def __enter__(self):
        self.command('true')
        return self

    def __exit__(self, *args):
        return False

    def run(self, command, *, data=None, timeout=60):
        result = subprocess.run(self.args + [command], input=data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
        if result.returncode:
            # 远端工具可能把订阅/Token 写在 stderr；错误不回显命令或原始日志。
            raise RuntimeError('SSH 命令失败，退出码 ' + str(result.returncode))
        return result.stdout

    def command(self, command, timeout=60):
        return self.run(command, timeout=timeout).decode('utf-8', 'replace')

    def upload(self, helper, target, data):
        target = check_device_path(target)
        temporary = target + '.upload'
        digest = hashlib.sha256(data).hexdigest()
        self.run('umask 077; cat >' + temporary + ' && chmod 600 ' + temporary +
                 ' && test "$(sha256sum ' + temporary + ' | cut -d\" \" -f1)" = ' + digest +
                 ' && mv ' + temporary + ' ' + target, data=data, timeout=300)

    def put_small(self, target, data, mode=0o600):
        if mode not in (0o600, 0o700):
            raise ValueError('SSH 上传权限只能是 0600 或 0700')
        self.upload('', target, data)
        self.command('chmod ' + oct(mode)[2:] + ' ' + target)

    def download(self, helper, source, length, digest):
        source = check_device_path(source)
        if not 0 < length <= 512 * 1048576 or not re.fullmatch(r'[a-f0-9]{64}', digest):
            raise ValueError('SSH 下载清单无效')
        result = self.run('cat ' + source, timeout=300)
        if len(result) != length or hashlib.sha256(result).hexdigest() != digest:
            raise ValueError('SSH 下载的大小或摘要不一致')
        return result
