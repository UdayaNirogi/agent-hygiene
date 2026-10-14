"""Plain-text tables and JSON output. No colour, no dependencies, pipe-friendly."""
from __future__ import annotations

import json
import os
import sys
from typing import Any, List, Sequence

from .model import AgentFootprint, Inventory
from .platform import home, human_bytes, human_duration


def shorten_home(path: str) -> str:
    h = str(home())
    if path == h:
        return "~"
    if path.startswith(h + os.sep):
        return "~" + path[len(h):]
    return path


def truncate(text: str, width: int) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= width else text[: width - 1] + "…"


def table(headers: Sequence[str], rows: Sequence[Sequence[Any]], max_col: int = 70) -> str:
    cells = [[truncate(str(c), max_col) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))
    fmt = "  ".join("{:<%d}" % w for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*row).rstrip() for row in cells]
    return "\n".join(lines)


def section(title: str) -> str:
    return f"\n{title}\n{'=' * len(title)}"


def dump_json(obj: Any, out=None) -> None:
    print(json.dumps(obj, indent=2, sort_keys=False, default=str), file=out or sys.stdout)


def _switch(a: AgentFootprint, kind: str) -> str:
    relevant = [s for s in a.settings if s.kind == kind and s.applicable]
    if not relevant:
        return "n/a"
    return "on" if a.settings_on(kind) else "off"


def render_inventory(inv: Inventory, verbose: bool = False) -> str:
    out: List[str] = [f"agent-hygiene scan  host={inv.host}  os={inv.os}  at={inv.generated_at}"]

    rows = []
    for a in inv.agents:
        if not a.installed and not verbose:
            continue
        rows.append([
            a.name, "yes" if a.installed else "no", human_bytes(a.total_bytes),
            len(a.versions), len(a.stale_versions), _switch(a, "self-update"), _switch(a, "auto-start"),
            ", ".join(f"{n.package}@{n.version} ({n.manager})" for n in a.npm) or
            ", ".join(shorten_home(b) for b in a.binaries) or "-",
        ])
    out.append(section("Agents"))
    out.append(table(["agent", "present", "disk", "versions", "stale", "self-update", "auto-start", "install"], rows)
               if rows else "no known agents found")

    rows = []
    for a in inv.agents:
        for e in a.paths:
            rows.append([a.name, e.kind, shorten_home(e.path), human_bytes(e.bytes)])
        for n in a.npm:
            rows.append([a.name, n.manager, shorten_home(n.path), human_bytes(n.bytes)])
    if rows:
        out.append(section("Disk use"))
        out.append(table(["agent", "kind", "path", "size"], rows))

    rows = []
    for a in inv.agents:
        for vs in a.versions_by_root().values():
            for i, v in enumerate(vs):
                status = "current" if v.is_current else ("newest" if i == 0 else "stale")
                if v.in_use:
                    status += ", in use"
                rows.append([a.name, v.version, status, "dir" if v.is_dir else "file",
                             human_bytes(v.bytes), shorten_home(v.path)])
    if rows:
        out.append(section("Version folders"))
        out.append(table(["agent", "version", "status", "type", "size", "path"], rows))

    out.append(section("Auto-start"))
    if inv.autostarts:
        rows = [[e.agent or "-", e.kind, e.id, "yes" if e.enabled else "no",
                 "" if e.user_writable else "needs sudo", e.detail, e.program] for e in inv.autostarts]
        out.append(table(["agent", "kind", "id", "enabled", "", "detail", "program"], rows))
    else:
        out.append("no agent auto-start entries (LaunchAgents / systemd user units / crontab)")

    out.append(section("Processes"))
    if inv.processes:
        rows = [[p.agent or "-", p.pid, p.ppid, p.tty, human_duration(p.etime_s),
                 human_bytes(p.rss_kb * 1024), " ".join(x for x in ("LEFTOVER" if p.orphaned else "", p.role) if x),
                 p.command, p.parent_command] for p in inv.processes]
        out.append(table(["agent", "pid", "ppid", "tty", "uptime", "rss", "", "command", "parent"], rows))
    else:
        out.append("no agent processes running")

    if inv.ports:
        out.append(section("Network"))
        rows = [[p.agent or "-", p.pid, p.proto, p.local, p.remote, p.state] for p in inv.ports]
        out.append(table(["agent", "pid", "proto", "local", "remote", "state"], rows))

    total = sum(a.total_bytes for a in inv.agents)
    stale = sum(v.bytes for a in inv.agents for v in a.stale_versions)
    leftovers = sum(1 for p in inv.processes if p.orphaned)
    out.append("")
    out.append(f"total agent disk use: {human_bytes(total)}   stale versions: {human_bytes(stale)}   "
               f"auto-start entries: {len(inv.autostarts)}   leftover processes: {leftovers}")
    for w in inv.warnings:
        out.append(f"warning: {w}")
    return "\n".join(out)


def confirm(prompt: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print("stdin is not a terminal; re-run with --yes to apply without a prompt.", file=sys.stderr)
        return False
    try:
        answer = input(f"{prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")
