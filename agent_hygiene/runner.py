"""`run -- <agent>`: launch an agent in its own process group (and a transient systemd
scope on Linux), shut down everything it started when it exits, and report files it
touched outside its own folders.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import agents
from .model import ProcessInfo
from .output import shorten_home
from .platform import IS_LINUX, atomic_write, expand, have, home, private_state_dir, run, runs_dir, state_dir
from .scan.processes import descendants, list_processes, redact

SKIP_DIR_NAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    ".cache", "Library", ".Trash", ".npm", ".nvm", ".cargo", ".rustup", ".docker", ".pyenv",
    ".gradle", ".m2", "target", "dist", "build", ".next", ".turbo", "Applications", "Movies",
    "Music", "Pictures", "Photos Library.photoslibrary",
}
MAX_SNAPSHOT_ENTRIES = 400_000
# orphans are re-parented to pid 1, or to a per-user subreaper on systemd/launchd systems
_SUBREAPER = re.compile(r"(^|/)(systemd --user|launchd)(\s|$)")


@dataclass
class RunReport:
    agent: Optional[str]
    command: str
    started_at: str
    ended_at: str = ""
    exit_code: Optional[int] = None
    isolation: str = "process-group"
    cgroup_unit: Optional[str] = None
    killed: List[Dict] = field(default_factory=list)
    leftovers: List[Dict] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    snapshot_truncated: bool = False
    log_path: str = ""


# --- file snapshot --------------------------------------------------------------------

def _excluded_prefixes(agent: Optional[str]) -> List[str]:
    prefixes = [str(state_dir())]
    specs = [agents.by_name(agent)] if agent and agents.by_name(agent) else agents.AGENTS
    for spec in specs:
        if spec is None:
            continue
        for pat in spec.home_dirs + spec.data_dirs + spec.versions_roots:
            if any(ch in pat for ch in "*?["):
                continue
            prefixes.append(str(expand(pat)))
    return prefixes


def snapshot(roots: Sequence[Path], excluded: Sequence[str], depths: Sequence[int]) -> Tuple[Dict[str, Tuple[int, int]], bool]:
    seen: Dict[str, Tuple[int, int]] = {}
    truncated = False

    def excluded_path(p: str) -> bool:
        return any(p == e or p.startswith(e + os.sep) for e in excluded)

    def walk(d: str, depth: int) -> None:
        nonlocal truncated
        if truncated or depth < 0 or excluded_path(d):
            return
        try:
            it = os.scandir(d)
        except OSError:
            return
        with it:
            for entry in it:
                if len(seen) >= MAX_SNAPSHOT_ENTRIES:
                    truncated = True
                    return
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name in SKIP_DIR_NAMES:
                            continue
                        walk(entry.path, depth - 1)
                    else:
                        st = entry.stat(follow_symlinks=False)
                        seen[entry.path] = (st.st_mtime_ns, st.st_size)
                except OSError:
                    continue

    for root, depth in zip(roots, depths):
        walk(str(root), depth)
    return seen, truncated


def diff_snapshots(before: Dict[str, Tuple[int, int]], after: Dict[str, Tuple[int, int]]) -> Tuple[List[str], List[str]]:
    created = sorted(p for p in after if p not in before)
    modified = sorted(p for p, v in after.items() if p in before and before[p] != v)
    return created, modified


# --- process control ------------------------------------------------------------------

def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _systemd_user_available() -> bool:
    if not (IS_LINUX and have("systemd-run") and have("systemctl")):
        return False
    res = run(["systemctl", "--user", "is-system-running"], timeout=5)
    return res.stdout.strip() in ("running", "degraded")


def _cgroup_pids(unit: str) -> Set[int]:
    res = run(["systemctl", "--user", "show", unit, "-p", "ControlGroup", "--value"], timeout=5)
    cg = res.stdout.strip()
    if not cg:
        return set()
    try:
        with open(f"/sys/fs/cgroup{cg}/cgroup.procs") as fh:
            return {int(x) for x in fh.read().split()}
    except OSError:
        return set()


class Supervisor:
    def __init__(self, argv: List[str], agent: Optional[str], watch: Sequence[Path],
                 grace: float, use_cgroup: bool, log=print):
        self.argv = argv
        self.agent = agent
        self.watch = list(watch)
        self.grace = grace
        self.use_cgroup = use_cgroup
        self.log = log
        self.tty_fd: Optional[int] = None
        self.proc: Optional[subprocess.Popen] = None
        self.unit: Optional[str] = None
        self.tracked: Dict[int, str] = {}
        self.initial_pids: Set[int] = set()
        self.report = RunReport(agent=agent, command=redact(" ".join(argv)),
                                started_at=dt.datetime.now().isoformat(timespec="seconds"))

    # -- setup -------------------------------------------------------------------------

    def _open_tty(self) -> None:
        if not sys.stdin.isatty():
            return
        try:
            self.tty_fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        except OSError:
            self.tty_fd = None

    def _command(self) -> List[str]:
        if self.use_cgroup and _systemd_user_available():
            self.unit = f"agent-hygiene-{os.getpid()}-{int(time.time())}"
            self.report.isolation = "systemd-scope+process-group"
            self.report.cgroup_unit = f"{self.unit}.scope"
            return ["systemd-run", "--user", "--scope", "--quiet", "--collect",
                    f"--unit={self.unit}", "--"] + self.argv
        return self.argv

    def _child_setup(self) -> None:
        # Runs in the child between fork and exec: own process group, and take the
        # terminal foreground so an interactive agent can read from the tty.
        os.setpgid(0, 0)
        if self.tty_fd is not None:
            try:
                os.tcsetpgrp(self.tty_fd, os.getpgrp())
            except OSError:
                pass
        for sig in (signal.SIGTTOU, signal.SIGTTIN, signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            signal.signal(sig, signal.SIG_DFL)

    def _install_signals(self) -> None:
        def on_term(signum, frame):
            self.log(f"\nagent-hygiene: received {signal.Signals(signum).name}, shutting down the agent")
            self.shutdown()
            self._finish()
            raise SystemExit(128 + signum)

        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        signal.signal(signal.SIGTTIN, signal.SIG_IGN)
        if self.tty_fd is not None:
            # The terminal delivers Ctrl-C to the foreground group (the agent), not to us.
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        else:
            signal.signal(signal.SIGINT, lambda s, f: self._forward(signal.SIGINT))
        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGHUP, on_term)

    def _forward(self, sig: int) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, sig)
            except OSError:
                pass

    # -- main loop ---------------------------------------------------------------------

    def run(self) -> int:
        excluded = _excluded_prefixes(self.agent)
        depths = [12 if w != home() else 3 for w in self.watch]
        before, trunc1 = snapshot(self.watch, excluded, depths)
        self.initial_pids = {p.pid for p in list_processes()}

        self._open_tty()
        self._install_signals()
        cmd = self._command()
        try:
            self.proc = subprocess.Popen(
                cmd,
                preexec_fn=self._child_setup if self.tty_fd is not None else None,
                start_new_session=self.tty_fd is None,
            )
        except FileNotFoundError:
            self.log(f"agent-hygiene: command not found: {cmd[0]}")
            self._release_tty()
            return 127

        try:
            os.setpgid(self.proc.pid, self.proc.pid)  # harmless if the child already did it
        except OSError:
            pass

        try:
            while True:
                rc = self.proc.poll()
                if rc is not None:
                    break
                self._track()
                time.sleep(0.5)
        finally:
            self._release_tty()

        self.report.exit_code = rc
        self.shutdown()
        after, trunc2 = snapshot(self.watch, excluded, depths)
        created, modified = diff_snapshots(before, after)
        self.report.files_created = created
        self.report.files_modified = modified
        self.report.snapshot_truncated = trunc1 or trunc2
        self._finish()
        return rc if rc is not None else 1

    def _release_tty(self) -> None:
        if self.tty_fd is None:
            return
        try:
            os.tcsetpgrp(self.tty_fd, os.getpgrp())
        except OSError:
            pass

    def _track(self) -> None:
        """Remember every descendant we see so double-forked daemons are still found later."""
        if self.proc is None:
            return
        procs = list_processes()
        cg = _cgroup_pids(f"{self.unit}.scope") if self.unit else set()
        desc = {p.pid for p in descendants(procs, self.proc.pid)}
        for p in procs:
            if p.pid in desc or p.pgid == self.proc.pid or p.pid in cg:
                self.tracked[p.pid] = p.command

    # -- teardown ----------------------------------------------------------------------

    def _targets(self) -> List[ProcessInfo]:
        procs = list_processes()
        me = os.getpid()
        root = self.proc.pid if self.proc else -1
        cg = _cgroup_pids(f"{self.unit}.scope") if self.unit else set()
        by_pid = {p.pid: p for p in procs}
        out: List[ProcessInfo] = []
        for p in procs:
            if p.pid == me or p.pid == root:
                continue
            in_group = p.pgid == root
            # same pid *and* same command line, so a reused pid is never mistaken for ours
            tracked = self.tracked.get(p.pid) == p.command
            in_cgroup = p.pid in cg
            parent = by_pid.get(p.ppid)
            reparented = p.ppid <= 1 or (parent is not None and _SUBREAPER.search(parent.command) is not None)
            escaped = (
                p.pid not in self.initial_pids
                and reparented
                and agents.match_process(p.command) is not None
                and (self.agent is None or agents.match_process(p.command) == self.agent)
            )
            if in_group or tracked or in_cgroup or escaped:
                out.append(p)
        # anything an escaped process itself spawned goes with it
        chosen = {p.pid for p in out}
        for p in list(out):
            for d in descendants(procs, p.pid):
                if d.pid not in chosen and d.pid != me:
                    chosen.add(d.pid)
                    out.append(d)
        return out

    def shutdown(self) -> None:
        if self.proc is None:
            return
        targets = self._targets()
        if self.proc.poll() is None:
            targets.append(ProcessInfo(self.proc.pid, os.getpid(), self.proc.pid, "", 0, 0, self.report.command))
        if not targets:
            return
        self._signal_all(targets, signal.SIGTERM)
        deadline = time.time() + self.grace
        while time.time() < deadline and any(_alive(t.pid) for t in targets):
            time.sleep(0.1)
        survivors = [t for t in targets if _alive(t.pid)]
        if survivors:
            self._signal_all(survivors, signal.SIGKILL)
            time.sleep(0.2)
        if self.unit:
            run(["systemctl", "--user", "stop", f"{self.unit}.scope"], timeout=10)
        for t in targets:
            self.report.killed.append({"pid": t.pid, "command": t.command,
                                       "forced": any(s.pid == t.pid for s in survivors)})
        # whatever is still around after all that is a genuine leftover
        self.report.leftovers = [{"pid": t.pid, "command": t.command} for t in self._targets() if _alive(t.pid)]

    def _signal_all(self, targets: List[ProcessInfo], sig: int) -> None:
        if self.unit and have("systemctl"):
            run(["systemctl", "--user", "kill", f"--signal={sig}", f"{self.unit}.scope"], timeout=10)
        if self.proc is not None:
            try:
                os.killpg(self.proc.pid, sig)
            except OSError:
                pass
        for t in targets:
            try:
                os.kill(t.pid, sig)
            except OSError:
                pass

    def _finish(self) -> None:
        self.report.ended_at = dt.datetime.now().isoformat(timespec="seconds")
        private_state_dir()
        runs_dir().mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = runs_dir() / f"{stamp}-{self.agent or Path(self.argv[0]).name}.json"
        self.report.log_path = str(path)
        atomic_write(path, json.dumps(asdict(self.report), indent=2), mode=0o600)
        self._print_summary()

    def _print_summary(self) -> None:
        r = self.report
        self.log("")
        self.log(f"agent-hygiene run summary  agent={r.agent or '?'}  exit={r.exit_code}  isolation={r.isolation}")
        if r.killed:
            self.log(f"  shut down {len(r.killed)} process(es) the agent left running:")
            for k in r.killed:
                self.log(f"    pid {k['pid']}{' (SIGKILL)' if k['forced'] else ''}: {k['command'][:90]}")
        else:
            self.log("  no background processes were left running")
        if r.leftovers:
            self.log(f"  WARNING: {len(r.leftovers)} process(es) could not be stopped:")
            for k in r.leftovers:
                self.log(f"    pid {k['pid']}: {k['command'][:90]}")
        else:
            self.log("  leftover processes: 0")
        outside = [p for p in r.files_created]
        if outside:
            self.log(f"  files created outside the agent's own folders: {len(outside)}")
            for p in outside[:25]:
                self.log(f"    + {shorten_home(p)}")
            if len(outside) > 25:
                self.log(f"    … and {len(outside) - 25} more (see log)")
        if r.files_modified:
            self.log(f"  files modified: {len(r.files_modified)}")
            for p in r.files_modified[:10]:
                self.log(f"    ~ {shorten_home(p)}")
            if len(r.files_modified) > 10:
                self.log(f"    … and {len(r.files_modified) - 10} more (see log)")
        if r.snapshot_truncated:
            self.log("  note: file snapshot hit its size cap; use --watch to narrow the scope")
        self.log(f"  log: {shorten_home(r.log_path)}")


def run_agent(argv: List[str], agent: Optional[str] = None, watch: Optional[Sequence[str]] = None,
              grace: float = 3.0, use_cgroup: bool = True, log=print) -> int:
    if not argv:
        log("usage: agent-hygiene run [--agent NAME] -- <command> [args...]")
        return 2
    agent = agent or agents.guess_from_argv0(argv[0])
    roots = [Path(w).absolute() for w in watch] if watch else [Path.cwd(), home()]
    uniq: List[Path] = []
    for r in roots:
        if r not in uniq:
            uniq.append(r)
    sup = Supervisor(argv, agent, uniq, grace, use_cgroup, log)
    return sup.run()
