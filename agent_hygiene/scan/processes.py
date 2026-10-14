"""Running processes attributed to agents, their parents, and the sockets they hold."""
from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set

from .. import agents
from ..model import PortInfo, ProcessInfo
from ..platform import IS_LINUX, IS_MACOS, have, run

PS_ARGS = ["ps", "-eo", "pid=,ppid=,pgid=,uid=,stat=,tty=,etime=,rss=,args="]

# When a session ends its processes are re-parented to pid 1, or on desktops to a per-user
# subreaper (`systemd --user` on Linux, launchd on macOS) that keeps them running.
SUBREAPER = re.compile(r"(^|/)(systemd\s+--user|launchd|init)(\s|$)")
_INTERPRETER = re.compile(r"(^|/)(node|nodejs|bun|deno|python[0-9.]*|ruby|perl|sh|bash|zsh|dash)$", re.IGNORECASE)

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
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            procs.append(ProcessInfo(
                pid=int(parts[0]), ppid=int(parts[1]), pgid=int(parts[2]), uid=int(parts[3]), state=parts[4],
                tty=parts[5], etime_s=parse_etime(parts[6]), rss_kb=int(parts[7]), command=redact(parts[8].strip()),
            ))
        except ValueError:
            continue
    return procs


def list_processes(warnings: Optional[List[str]] = None) -> List[ProcessInfo]:
    """The current user's running processes. Other accounts' processes are never read or
    reported, and zombies (already exited, waiting to be reaped) are not running."""
    res = run(PS_ARGS, timeout=15)
    if res.returncode != 0:
        if warnings is not None:
            warnings.append(f"ps failed: {res.stderr.strip() or res.returncode}")
        return []
    me = os.getuid()
    return [p for p in parse_ps(res.stdout) if p.uid == me and not p.state.startswith("Z")]


def _no_tty(tty: str) -> bool:
    return tty in ("?", "??", "-", "")


_LIBPROC = None


def exe_path(pid: int) -> Optional[str]:
    """The program file a process is running, from the kernel rather than its argv (which
    a process can set to anything). None if the OS will not say."""
    if IS_LINUX:
        try:
            path = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            return None
        return path[: -len(" (deleted)")] if path.endswith(" (deleted)") else path
    if IS_MACOS:
        global _LIBPROC
        try:
            import ctypes
            if _LIBPROC is None:
                _LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib")
            buf = ctypes.create_string_buffer(4096)
            if _LIBPROC.proc_pidpath(pid, buf, 4096) > 0:
                return buf.value.decode("utf-8", "replace")
        except (OSError, AttributeError):
            return None
    return None


def is_running(pid: int) -> bool:
    """Alive and not a zombie (exited, only waiting to be reaped)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().rsplit(")", 1)[-1].split()[0] != "Z"
    except OSError:
        pass
    return not run(["ps", "-o", "stat=", "-p", str(pid)], timeout=5).stdout.strip().startswith("Z")


def is_interpreter(path: str) -> bool:
    return bool(path) and _INTERPRETER.search(path) is not None


def _under(path: str, folder: str) -> bool:
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


def runs_from(p: ProcessInfo, folders: Sequence[str]) -> bool:
    """True if the process's program (or the script its interpreter runs) lives inside one
    of `folders`. A matching name alone is never enough."""
    if not folders:
        return False
    forms = set()
    for f in folders:
        forms.add(os.path.abspath(f))
        forms.add(os.path.realpath(f))
    exe = p.exe or exe_path(p.pid) or ""
    if exe:
        real = os.path.realpath(exe)
        if any(_under(exe, f) or _under(real, f) for f in forms):
            return True
        if not is_interpreter(exe):
            return False  # the kernel names a program elsewhere; argv cannot override that
    cmd = p.command
    prefixes = [f.rstrip(os.sep) + os.sep for f in forms]
    if any(cmd.startswith(x) for x in prefixes):
        return True
    tokens = list(re.finditer(r"\S+", cmd))
    if tokens and (is_interpreter(tokens[0].group(0)) or is_interpreter(exe)):
        # the script the interpreter runs: its first argument that is not an option
        script = next((t for t in tokens[1:] if not t.group(0).startswith("-")), None)
        if script is not None:
            rest = cmd[script.start():]
            return any(rest.startswith(x) for x in prefixes)
    return False


def resolve_exes(procs: Iterable[ProcessInfo]) -> None:
    for p in procs:
        if not p.exe:
            p.exe = exe_path(p.pid) or ""


def running_from(procs: Iterable[ProcessInfo], folder: str, resolve: bool = True) -> List[ProcessInfo]:
    """Processes whose program, or any argument, points inside `folder`."""
    forms = {os.path.abspath(folder).rstrip(os.sep), os.path.realpath(folder).rstrip(os.sep)}
    out = []
    for p in procs:
        exe = p.exe or (exe_path(p.pid) if resolve else None) or ""
        if exe and any(_under(exe, f) or _under(os.path.realpath(exe), f) for f in forms):
            out.append(p)
            continue
        padded = f" {p.command} "
        if any(f" {f}{os.sep}" in padded or f" {f} " in padded for f in forms):
            out.append(p)
    return out


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
        p.role = agents.daemon_role(agent, p.command)
        p.exe = exe_path(p.pid) or ""
        parent = by_pid.get(p.ppid)
        p.parent_command = parent.command if parent else "(exited)"
        # A session that ended leaves its children detached from a tty and re-parented to
        # pid 1 or to the desktop's per-user subreaper.
        reparented = p.ppid <= 1 or parent is None or SUBREAPER.search(parent.command) is not None
        p.orphaned = reparented and _no_tty(p.tty)
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


def scan_processes(warnings: List[str], all_procs: Optional[List[ProcessInfo]] = None) -> List[ProcessInfo]:
    return annotate(list_processes(warnings) if all_procs is None else all_procs)


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
