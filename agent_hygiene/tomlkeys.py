"""Read and set one `key = value` in a TOML file without a TOML library (none ships before
Python 3.11). Only plain `[table]` sections and top-level dotted keys are handled; anything
fancier (an inline `table = { ... }`) is refused rather than guessed at. On Python 3.11+
the input and the result are double-checked with `tomllib`.
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

try:
    import tomllib as _tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - exercised on 3.9/3.10
    _tomllib = None

_HEADER = re.compile(r"^\s*\[\s*([^\[\]]+?)\s*\]\s*(#.*)?$")
_ARRAY_HEADER = re.compile(r"^\s*\[\[")


def _key_re(key: str) -> "re.Pattern[str]":
    k = re.escape(key)
    return re.compile(rf"^(\s*)(?:{k}|\"{k}\"|'{k}')\s*=\s*(.*?)\s*$")


def _strip_comment(value: str) -> str:
    if value.startswith(("\"", "'")):
        return value
    return value.split("#", 1)[0].strip()


def _parse_value(raw: str) -> Any:
    v = _strip_comment(raw)
    if v == "true":
        return True
    if v == "false":
        return False
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    try:
        return int(v)
    except ValueError:
        return v


def _format_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _scan(lines: List[str], table: Optional[str], key: str) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """(index of the key line, index of the table header, index of the first header)."""
    key_re = _key_re(key)
    dotted_re = _key_re(f"{table}.{key}") if table else None
    inline_re = re.compile(rf"^\s*{re.escape(table)}\s*=\s*\{{") if table else None
    current: Optional[str] = None
    header_idx = first_header = None
    in_multiline: Optional[str] = None
    for i, line in enumerate(lines):
        if in_multiline:
            if line.count(in_multiline) % 2 == 1:
                in_multiline = None
            continue
        for q in ('"""', "'''"):
            if line.count(q) % 2 == 1:
                in_multiline = q
        m = _HEADER.match(line)
        if m or _ARRAY_HEADER.match(line):
            current = m.group(1).strip().strip("\"'") if m else "[[array]]"
            if first_header is None:
                first_header = i
            if table and current == table and header_idx is None:
                header_idx = i
            continue
        if current is None and inline_re is not None and inline_re.match(line):
            raise ValueError(f"[{table}] is written as an inline table; edit it by hand")
        if current is None and dotted_re is not None and dotted_re.match(line):
            return i, header_idx, first_header
        if current == table and key_re.match(line):
            return i, header_idx, first_header
    return None, header_idx, first_header


def get(text: str, table: Optional[str], key: str) -> Any:
    lines = text.splitlines()
    idx, _, _ = _scan(lines, table, key)
    if idx is None:
        return None
    return _parse_value(lines[idx].split("=", 1)[1].strip())


def set_value(text: str, table: Optional[str], key: str, value: Any) -> str:
    if _tomllib is not None and text.strip():
        try:
            _tomllib.loads(text)
        except _tomllib.TOMLDecodeError as exc:
            raise ValueError(f"not valid TOML: {exc}")
    lines = text.splitlines()
    idx, header_idx, first_header = _scan(lines, table, key)
    formatted = _format_value(value)
    if idx is not None:
        indent = re.match(r"^(\s*)", lines[idx]).group(1)
        name = lines[idx].split("=", 1)[0].strip()
        lines[idx] = f"{indent}{name} = {formatted}"
    elif table is None:
        lines.insert(first_header if first_header is not None else len(lines), f"{key} = {formatted}")
    elif header_idx is not None:
        lines.insert(header_idx + 1, f"{key} = {formatted}")
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines += [f"[{table}]", f"{key} = {formatted}"]
    out = "\n".join(lines) + "\n"
    if _tomllib is not None:
        parsed: Any = _tomllib.loads(out)
        for part in ([table] if table else []) + [key]:
            parsed = parsed.get(part) if isinstance(parsed, dict) else None
        if parsed != value:
            raise ValueError("could not set the value safely; edit the file by hand")
    return out
