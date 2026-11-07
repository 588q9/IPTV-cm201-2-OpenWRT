"""Strict source patch application without compiler dependencies."""
import re


def apply_patch(text, patch):
    lines, result, cursor = text.splitlines(keepends=True), [], 0
    chunks = patch.splitlines(keepends=True)
    i = 0
    while i < len(chunks):
        match = re.match(r'@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@', chunks[i])
        if not match:
            i += 1
            continue
        start = int(match.group(1)) - 1
        if start < cursor:
            raise ValueError('源码补丁块重叠')
        result.extend(lines[cursor:start])
        cursor, i = start, i + 1
        while i < len(chunks) and not chunks[i].startswith('@@ '):
            line = chunks[i]
            if line.startswith((' ', '-')):
                if cursor >= len(lines) or lines[cursor] != line[1:]:
                    raise ValueError('源码补丁上下文不匹配')
                if line.startswith(' '):
                    result.append(line[1:])
                cursor += 1
            elif line.startswith('+'):
                result.append(line[1:])
            else:
                break
            i += 1
    result.extend(lines[cursor:])
    return ''.join(result)
