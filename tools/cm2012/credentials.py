"""Narrow offline hardening for locked OpenWrt ddns-scripts 2.8.4-r8 (GPL-2.0).

Upstream fingerprints/provenance: tests/fixtures/ddns-2.8.4-r8/README.md.
Only file contents change; archive ownership, modes and device metadata survive.
"""
from dataclasses import replace
import hashlib
import stat

from .archives import Entry


_CF = 'usr/lib/ddns/update_cloudflare_com_v4.sh'
_FUNCTIONS = 'usr/lib/ddns/dynamic_dns_functions.sh'
_ORIGINAL = {
    _CF: '120bd12191d072f8720640316dec931002a3a9f26e743df45cce08960069fe3f',
    _FUNCTIONS: 'a607436c9e8676977e231e8868e8692943d1d28324869297cafadee7f4e8610d',
}
_PATCHED = {
    _CF: 'be00ecb4bc1f746b43f9fe4ae4b83eaf6f78a90cdb0f7fd5f730384e6b506161',
    _FUNCTIONS: '2e9eddc0d35f1e0fb88ee114389ed9d92a43fe26f2296694fbc78889e8e8bb89',
}

_HEADERS = '''# CM2012: auth headers travel over a pipe, never argv or a temporary file.
# Reject header injection without logging credential values.
case "$password$username" in
  *[![:print:]]*) write_log 3 "Invalid Cloudflare authentication header"; return 127 ;;
esac
cm2012_cloudflare_headers() {
  if [ "$username" = "Bearer" ]; then
    printf 'Authorization: Bearer %s\\n' "$password"
  else
    printf 'X-Auth-Email: %s\\nX-Auth-Key: %s\\n' "$username" "$password"
  fi
  printf 'Content-Type: application/json\\n'
}
__PRGBASE="$__PRGBASE --header @- "
'''

_REDACT = '''	# CM2012: redact literal secrets before console, syslog construction or files.
	# Shell builtins keep even quote/metacharacter-containing secrets out of argv.
	local __SECRET __TAIL __CLEAN
	for __SECRET in "$password" "$URL_PASS"; do
		[ -n "$__SECRET" ] || continue
		__TAIL=$__MSG
		__CLEAN=
		while :; do
			case "$__TAIL" in
				*"$__SECRET"*)
					__CLEAN="$__CLEAN${__TAIL%%"$__SECRET"*}***PW***"
					__TAIL=${__TAIL#*"$__SECRET"} ;;
				*) break ;;
			esac
		done
		__MSG="$__CLEAN$__TAIL"
	done
'''

_URL_GUARD = '''	# CM2012: generic URL transports cannot safely carry configured secrets.
	# Fail before curl/wget selection; the Cloudflare script uses private stdin.
	local __SECRET
	for __SECRET in "$password" "$URL_PASS"; do
		[ -n "$__SECRET" ] || continue
		case "$__URL" in
			*"$__SECRET"*) write_log 3 "Credential URL transport unsupported"; return 127 ;;
		esac
	done
	case "$__URL" in
		*://*@*) write_log 3 "Credential URL transport unsupported"; return 127 ;;
	esac
'''

_URLENCODE = '''urlencode() {
	# $1 output variable, $2 literal input; never place input in awk argv.
	local __ENC
	[ $# -ne 2 ] && write_log 12 "Error calling 'urlencode()' - wrong number of parameters"
	# An extra record separator preserves trailing newlines. Existing DDNS
	# control-byte encoding is %00; printable bytes retain lowercase percent hex.
	__ENC="$(printf '%s\\n' "$2" | awk 'BEGIN{ORS="";for(i=32;i<=127;i++)lookup[sprintf("%c",i)]=i}
		{if(NR>1)printf "%%00";str=$0
		for(k=1;k<=length(str);++k){enc=substr(str,k,1);if(enc!~"[-_.~a-zA-Z0-9]")enc=sprintf("%%%02x", lookup[enc]);print enc}}')"
	eval "$1=\\"$__ENC\\""
	return 0
}'''


def _patch(name: str, data: bytes) -> bytes:
    text = data.decode('utf-8')
    if name == _CF:
        start = text.index('# set headers\n')
        end = text.index('\n# read zone id', start)
        text = text[:start] + _HEADERS + text[end:]
        text = text.replace('\t\teval "$__RUNPROG"\n',
                            '\t\tcm2012_cloudflare_headers | eval "$__RUNPROG"\n', 1)
        # -q must be curl's first option, preventing user curlrc verbose/trace leaks.
        text = text.replace('__PRGBASE="$CURL -RsS', '__PRGBASE="$CURL -q -RsS', 1)
    else:
        start = text.index('urlencode() {')
        end = text.index('\n}', start) + 2
        text = text[:start] + _URLENCODE + text[end:]
        point = '\tcase $__LEVEL in\t\t# create log message and command depending on loglevel\n'
        text = text.replace(point, _REDACT + point, 1)
        start = text.index('\t\tif [ -n "$password" ]; then', text.index('write_log() {'))
        end = text.index('\t\tprintf "%s\\n" "$__MSG" >> $LOGFILE', start)
        text = text[:start] + text[end:]
        start = text.index('\n\t# Use ip_network as default', text.index('\ndo_transfer() {'))
        text = text[:start] + '\n' + _URL_GUARD + text[start:]
    return text.encode('utf-8')


def protect_root(entries: dict[str, Entry]) -> dict[str, Entry]:
    """Harden only the exact locked scripts, or accept exact prior patched bytes.

    Roots with neither DDNS file are unchanged. Partial, unknown, linked or
    altered scripts fail closed so a package change requires an explicit review.
    """
    present = set(_ORIGINAL).intersection(entries)
    if not present:
        return entries
    if present != set(_ORIGINAL):
        raise ValueError('DDNS credential patch requires both locked scripts')
    result = entries.copy()
    for name in _ORIGINAL:
        entry = entries[name]
        digest = hashlib.sha256(entry.data).hexdigest()
        if not stat.S_ISREG(entry.mode):
            raise ValueError('DDNS credential script must be a regular file: ' + name)
        if digest == _PATCHED[name]:
            continue
        if digest != _ORIGINAL[name]:
            raise ValueError('DDNS credential script differs from locked 2.8.4-r8: ' + name)
        result[name] = replace(entry, data=_patch(name, entry.data))
    return result
