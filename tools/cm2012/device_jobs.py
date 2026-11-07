"""Create private outer device jobs without changing a serial shell's umask."""
import re


def create_private_job(link, path):
    """Root-only, non-reusable 0700 directory under the existing RAM job prefix.

    The shell subscope contains the umask. Uploaded files/tools must additionally
    use put_small(..., mode=0o600/0o700); root image metadata is never restricted.
    """
    if not isinstance(path, str) or not re.fullmatch(r'/tmp/cm2012-build-[a-z0-9]{1,64}', path):
        raise ValueError('Private job must use a single /tmp/cm2012-build-* directory')
    link.command('( test "$(id -u)" = 0 && umask 077 && mkdir -m 700 ' + path +
                 ' && test "$(stat -c %a ' + path + ')" = 700 )')
