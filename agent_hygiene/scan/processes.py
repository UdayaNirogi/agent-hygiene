"""Running processes attributed to agents, their parents, and the sockets they hold."""
from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Set

from .. import agents
from ..model import PortInfo, ProcessInfo
from ..platform import have, run

PS_ARGS = ["ps", "-eo", "pid=,ppid=,pgid=,uid=,tty=,etime=,rss=,args="]

# Command lines can carry credentials (e.g. `--api-key crsr_...`). Never print or log them.
_SECRET_FLAG = re.compile(
    r"(?i)(--?(?:[a-z0-9]+[-_])*(?:api[-_]?key|key|token|secret|password|passwd|pass|pwd|auth(?:orization)?"
    r"|credentials?|cookie)(?:[=\s]+))(\S+)")
_SECRET_ENV = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?|COOKIE|AUTH)[A-Z0-9_]*=)(\S+)")
_SECRET_BEARER = re.compile(r"(?i)\b((?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})")
_SECRET_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_SECRET_TOKEN = re.compile(
    r"\b(sk-[A-Za-z0-9_-]{8,}|crsr_[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    r"|glpat-[A-Za-z0-9_-]{8,}|xox[abprs]-[A-Za-z0-9-]{8,}|AIza[A-Za-z0-9_-]{20,}|(?:AKIA|ASIA)[A-Z0-9]{12,}"
    r"|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,})")


def redact(text: str) -> str:
    text = _SECRET_URL.sub(lambda m: m.group(1) + "***:***@", text)
    text = _SECRET_BEARER.sub(lambda m: m.group(1) + "***", text)
    text = _SECRET_FLAG.sub(lambda m: m.group(1) + "***", text)
    text = _SECRET_ENV.sub(lambda m: m.group(1) + "***", text)
    return _SECRET_TOKEN.sub("***", text)


def parse_etime(text: str) -> int:
    """ps etime: [[dd-]hh:]mm:ss -> seconds."""
    days = 0
    if "-" in text:
        d, text = text.split("-", 1)
        days = int(d)
    parts = [int(p) for p in text.split(":")]
    while len(parts) < 3:
        parts.insert(0, 0)
    h, m, s = parts[-3:]
    return days * 86400 + h * 3600 + m * 60 + s


def parse_ps(output: str) -> List[ProcessInfo]:
    procs: List[ProcessInfo] = []
    for line in output.splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8:
            continue
        try:
            procs.append(ProcessInfo(
                pid=int(parts[0]), ppid=int(parts[1]), pgid=int(parts[2]), uid=int(parts[3]), tty=parts[4],
                etime_s=parse_etime(parts[5]), rss_kb=int(parts[6]), command=redact(parts[7].strip()),
            ))
        except ValueError:
            continue
    return procs


def list_processes(warnings: Optional[List[str]] = None) -> List[ProcessInfo]:
    """The current user's processes only; other accounts' processes are never read or reported."""
    res = run(PS_ARGS, timeout=15)
    if res.returncode != 0:
        if warnings is not None:
            warnings.append(f"ps failed: {res.stderr.strip() or res.returncode}")
        return []
    me = os.getuid()
    return [p for p in parse_ps(res.stdout) if p.uid == me]


def _no_tty(tty: str) -> bool:
    return tty in ("?", "??", "-", "")


def annotate(all_procs: List[ProcessInfo], self_pid: Optional[int] = None) -> List[ProcessInfo]:
    """Attribute processes to agents and flag ones whose session has ended."""
    self_pid = os.getpid() if self_pid is None else self_pid
    by_pid: Dict[int, ProcessInfo] = {p.pid: p for p in all_procs}
    ours: Set[int] = set()
    # exclude ourselves and our ancestors
    cur = by_pid.get(self_pid)
    while cur is not None and cur.pid not in ours:
        ours.add(cur.pid)
        cur = by_pid.get(cur.ppid)

    matched: List[ProcessInfo] = []
    for p in all_procs:
        if p.pid in ours:
            continue
        agent = agents.match_process(p.command)
        if not agent:
            continue
        p.agent = agent
        parent = by_pid.get(p.ppid)
        p.parent_command = parent.command if parent else "(exited)"
        # A session that ended leaves its children re-parented to pid 1 and detached from a tty.
        p.orphaned = (p.ppid <= 1 or parent is None) and _no_tty(p.tty)
        matched.append(p)

    # Children of an orphaned agent process are leftovers too.
    orphan_roots = {p.pid for p in matched if p.orphaned}
    changed = True
    while changed:
        changed = False
        for p in matched:
            if not p.orphaned and p.ppid in orphan_roots:
                p.orphaned = True
                orphan_roots.add(p.pid)
                changed = True
    return matched


def scan_processes(warnings: List[str]) -> List[ProcessInfo]:
    return annotate(list_processes(warnings))


def descendants(all_procs: Iterable[ProcessInfo], root_pid: int) -> List[ProcessInfo]:
    children: Dict[int, List[ProcessInfo]] = {}
    for p in all_procs:
        children.setdefault(p.ppid, []).append(p)
    out: List[ProcessInfo] = []
    stack = [root_pid]
    seen = {root_pid}
    while stack:
        pid = stack.pop()
        for c in children.get(pid, []):
            if c.pid not in seen:
                seen.add(c.pid)
                out.append(c)
                stack.append(c.pid)
    return out


# --- ports ------------------------------------------------------------------------

_LSOF_NAME = re.compile(r"^(?P<local>\S+?)(?:->(?P<remote>\S+))?(?:\s+\((?P<state>[A-Z_]+)\))?$")


def parse_lsof(output: str, agent_of: Dict[int, Optional[str]]) -> List[PortInfo]:
    ports: List[PortInfo] = []
    for line in output.splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        proto = parts[7]  # NODE column: TCP / UDP
        m = _LSOF_NAME.match(parts[8].strip())
        if not m:
            continue
        ports.append(PortInfo(
            pid=pid, agent=agent_of.get(pid), proto=proto, local=m.group("local"),
            remote=m.group("remote") or "", state=m.group("state") or ("UDP" if proto == "UDP" else ""),
        ))
    return ports


def parse_ss(output: str, agent_of: Dict[int, Optional[str]]) -> List[PortInfo]:
    ports: List[PortInfo] = []
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        proto, state, local, remote = parts[0], parts[1], parts[4], parts[5]
        for pid_s in re.findall(r"pid=(\d+)", line):
            pid = int(pid_s)
            if pid in agent_of:
                ports.append(PortInfo(pid=pid, agent=agent_of[pid], proto=proto.upper(),
                                      local=local, remote=remote if remote != "*:*" else "", state=state))
    return ports


def scan_ports(procs: List[ProcessInfo], warnings: List[str]) -> List[PortInfo]:
    agent_of = {p.pid: p.agent for p in procs}
    if not agent_of:
        return []
    if have("lsof"):
        pids = ",".join(str(p) for p in agent_of)
        res = run(["lsof", "-nP", "-i", "-a", "-p", pids], timeout=20)
        if res.returncode in (0, 1):  # 1 = nothing found
            return parse_lsof(res.stdout, agent_of)
        warnings.append(f"lsof failed: {res.stderr.strip()}")
    if have("ss"):
        res = run(["ss", "-tunap"], timeout=10)
        if res.returncode == 0:
            return parse_ss(res.stdout, agent_of)
    if not have("lsof") and not have("ss"):
        warnings.append("neither lsof nor ss found; skipped port scan")
    return []
