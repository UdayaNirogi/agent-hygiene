"""Build a plan of fixes from an inventory, preview it, and apply it with a backup journal.

Each applied action writes a restore record into the journal; `restore.py` reverses them
in reverse order. Killing a process is the only irreversible action and is opt-in.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from . import agents, tomlkeys
from .journal import Journal
from .model import AgentFootprint, AutostartEntry, Inventory, ProcessInfo
from .output import human_bytes, shorten_home, table
from .platform import atomic_write, expand, have, run, uid
from .scan.autostart import read_crontab
from .scan.footprint import beyond_keep, select_prunable
from .scan.processes import is_interpreter, is_running, list_processes, running_from, runs_from

DEFAULT_KEEP = 2


@dataclass
class Action:
    # stop-daemon | disable-launchagent | disable-systemd | disable-cron | disable-setting
    # | prune-version | kill-process
    kind: str
    agent: str
    target: str
    description: str
    reversible: bool = True
    bytes: int = 0
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Plan:
    actions: List[Action] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    @property
    def bytes_to_trash(self) -> int:
        return sum(a.bytes for a in self.actions if a.kind == "prune-version")


# --- planning -----------------------------------------------------------------------

def build_plan(
    inv: Inventory,
    autostart: bool = True,
    self_update: bool = True,
    prune: bool = True,
    kill: bool = False,
    keep: int = DEFAULT_KEEP,
    keep_per_agent: Optional[Dict[str, int]] = None,
) -> Plan:
    plan = Plan()
    keep_per_agent = keep_per_agent or {}
    stopping: Set[int] = set()

    if autostart:
        for a in inv.agents:
            act = _plan_daemon_stop(a, inv.processes, plan)
            if act is not None:
                plan.actions.append(act)
                stopping |= {int(p["pid"]) for p in act.data["procs"]}
        for e in inv.autostarts:
            if not e.enabled:
                continue
            if not e.user_writable:
                plan.skipped.append(f"{e.kind} {e.id} is system-wide ({e.path}); needs sudo, skipped")
                continue
            plan.actions.append(_plan_autostart(e))

    for a in inv.agents:
        if not a.installed:
            continue
        for s in a.settings_on():
            if (s.kind == "auto-start" and not autostart) or (s.kind == "self-update" and not self_update):
                continue
            plan.actions.append(Action(
                kind="disable-setting", agent=a.name, target=s.path or "",
                description=f"turn off {s.kind}: set {s.key} in {shorten_home(s.path or '')} (backup of file kept)",
                data={"path": s.path, "key": (s.key or "").split(".")},
            ))

    if prune:
        for a in inv.agents:
            n = keep_per_agent.get(a.name, keep)
            for v in beyond_keep(a.versions, n):
                busy = set(v.in_use_by) - stopping
                if busy:
                    plan.skipped.append(f"{a.name} {v.version} is still running (pid "
                                        f"{', '.join(map(str, sorted(busy)))}); not pruned")
            for v in select_prunable(a.versions, n, stopping):
                plan.actions.append(Action(
                    kind="prune-version", agent=a.name, target=v.path, bytes=v.bytes,
                    description=f"move {a.name} {v.version} ({human_bytes(v.bytes)}) to trash; keep newest {n}",
                    data={"path": v.path, "version": v.version},
                ))

    if kill:
        for p in inv.processes:
            if p.orphaned and p.pid not in stopping:
                plan.actions.append(Action(
                    kind="kill-process", agent=p.agent or "?", target=str(p.pid), reversible=False,
                    description=f"terminate pid {p.pid} ({p.command[:60]}) — session ended, parent gone",
                    data={"pid": p.pid, "command": p.command},
                ))
    return plan


def program_of(p: ProcessInfo) -> str:
    """The agent program behind a process: its executable, or the script an interpreter runs."""
    parts = p.command.split()
    if p.exe and not is_interpreter(p.exe):
        return p.exe
    if parts and (is_interpreter(parts[0]) or (p.exe and is_interpreter(p.exe))):
        script = next((a for a in parts[1:] if not a.startswith("-")), "")
        return script if script.startswith(os.sep) else ""
    return parts[0] if parts and parts[0].startswith(os.sep) else ""


def inside(path: str, folders: Sequence[str]) -> bool:
    if not path:
        return False
    real = os.path.realpath(path)
    return any(real.startswith(os.path.realpath(f).rstrip(os.sep) + os.sep) for f in folders)


def _plan_daemon_stop(a: AgentFootprint, procs: List[ProcessInfo], plan: Plan) -> Optional[Action]:
    spec = agents.by_name(a.name)
    if spec is None or spec.daemon is None:
        return None
    candidates = [p for p in procs if p.agent == a.name and p.role]
    if not candidates:
        return None
    folders = spec.own_folders()
    ours = [p for p in candidates if runs_from(p, folders)]
    for p in candidates:
        if p not in ours:
            plan.skipped.append(f"{a.name} {p.role} pid {p.pid} does not run from {a.name}'s own folders; left alone")
    if not ours:
        return None
    server = next((p for p in ours if p.role == "daemon"), None)
    binary = next((program_of(p) for p in [server] + ours if p and inside(program_of(p), folders)), "")
    pids = ", ".join(f"{p.role} {p.pid}" for p in ours)
    return Action(
        kind="stop-daemon", agent=a.name, target=pids,
        description=f"stop the {spec.display} background server ({pids}); restore starts it again",
        data={"binary": binary, "server_running": server is not None,
              "procs": [{"pid": p.pid, "command": p.command, "role": p.role} for p in ours]},
    )


def _plan_autostart(e: AutostartEntry) -> Action:
    if e.kind == "launchagent":
        return Action(kind="disable-launchagent", agent=e.agent or "?", target=e.id,
                      description=f"unload LaunchAgent {e.id} and move {shorten_home(e.path)} to backup",
                      data={"label": e.id, "path": e.path})
    if e.kind == "systemd-user":
        return Action(kind="disable-systemd", agent=e.agent or "?", target=e.id,
                      description=f"systemctl --user disable --now {e.id} (unit file left in place)",
                      data={"unit": e.id, "path": e.path})
    return Action(kind="disable-cron", agent=e.agent or "?", target=e.id,
                  description=f"comment out crontab line: {e.detail} {e.program}"[:110],
                  data={"line_id": e.id, "program": e.program, "schedule": e.detail})


def render_plan(plan: Plan) -> str:
    if not plan.actions and not plan.skipped:
        return "nothing to clean"
    rows = [[i + 1, a.kind, a.agent, "yes" if a.reversible else "NO",
             human_bytes(a.bytes) if a.bytes else "", a.description] for i, a in enumerate(plan.actions)]
    out = []
    if rows:
        out.append(table(["#", "action", "agent", "reversible", "size", "detail"], rows, max_col=110))
    if plan.bytes_to_trash:
        out.append(f"\n{human_bytes(plan.bytes_to_trash)} would move to trash; run `agent-hygiene purge` "
                   f"later to free it permanently, or `agent-hygiene restore` to put it back.")
    for s in plan.skipped:
        out.append(f"skipped: {s}")
    return "\n".join(out)


# --- applying -------------------------------------------------------------------------

def apply_plan(plan: Plan, log=print) -> Optional[Journal]:
    if not plan.actions:
        return None
    journal = Journal.create()
    log(f"backup id: {journal.id}  ({shorten_home(str(journal.root))})")
    for action in plan.actions:
        handler = _APPLIERS[action.kind]
        try:
            record = handler(action, journal)
        except Exception as exc:  # keep going; the journal only records what actually happened
            log(f"  FAILED {action.kind} {action.target}: {exc}")
            continue
        record.update({"kind": action.kind, "agent": action.agent, "target": action.target,
                       "reversible": action.reversible, "applied_at": time.time()})
        journal.record(record)
        log(f"  done   {action.kind} {action.target}")
    return journal


def _apply_launchagent(action: Action, journal: Journal) -> Dict[str, Any]:
    plist = Path(action.data["path"])
    label = action.data["label"]
    bootout = None
    if have("launchctl"):
        res = run(["launchctl", "bootout", f"gui/{uid()}/{label}"], timeout=15)
        if res.returncode != 0:
            res = run(["launchctl", "unload", str(plist)], timeout=15)
        bootout = res.returncode
    dest = journal.unique_file("launchagents", plist.name)
    shutil.move(str(plist), str(dest))
    return {"label": label, "original": str(plist), "backup": str(dest), "bootout_rc": bootout}


def _apply_systemd(action: Action, journal: Journal) -> Dict[str, Any]:
    unit = action.data["unit"]
    was_enabled = run(["systemctl", "--user", "is-enabled", "--", unit], timeout=10).stdout.strip()
    was_active = run(["systemctl", "--user", "is-active", "--", unit], timeout=10).stdout.strip()
    res = run(["systemctl", "--user", "disable", "--now", "--", unit], timeout=20)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"systemctl exited {res.returncode}")
    return {"unit": unit, "was_enabled": was_enabled, "was_active": was_active}


def _apply_cron(action: Action, journal: Journal) -> Dict[str, Any]:
    from .scan.autostart import cron_line_id

    text = read_crontab() or ""
    backup = journal.unique_file("cron", "crontab")
    backup.write_text(text)
    new_lines = []
    hit = False
    for line in text.splitlines():
        if not hit and cron_line_id(line.strip()) == action.data["line_id"]:
            new_lines.append(f"# agent-hygiene disabled: {line}")
            hit = True
        else:
            new_lines.append(line)
    if not hit:
        raise RuntimeError("crontab line not found (changed since scan?)")
    new_text = "\n".join(new_lines) + "\n"
    res = run(["crontab", "-"], input_text=new_text, timeout=10)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "crontab write failed")
    return {"backup": str(backup), "line_id": action.data["line_id"]}


def _apply_stop_daemon(action: Action, journal: Journal) -> Dict[str, Any]:
    spec = agents.by_name(action.agent)
    if spec is None or spec.daemon is None:
        raise RuntimeError(f"{action.agent} has no background server")
    folders = spec.own_folders()
    binary = action.data.get("binary") or ""
    stop_rc = None
    if inside(binary, folders) and os.access(binary, os.X_OK):
        # the agent's own graceful stop lets in-flight work drain first
        stop_rc = run([binary, *spec.daemon.stop_args], timeout=330).returncode
    current = {p.pid: p for p in list_processes()}
    stopped = []
    for rec in action.data["procs"]:
        p = current.get(int(rec["pid"]))
        # same pid, same command line, and still running from the agent's own folders
        if p is None or p.command != rec["command"] or not runs_from(p, folders):
            continue
        stopped.append({"pid": p.pid, "role": rec["role"], "signal": _terminate(p.pid)})
    return {"binary": binary, "server_running": bool(action.data.get("server_running")),
            "stop_rc": stop_rc, "stopped": stopped}


def _apply_setting(action: Action, journal: Journal) -> Dict[str, Any]:
    spec = agents.by_name(action.agent)
    s = spec.setting(action.data["path"], tuple(action.data["key"])) if spec else None
    if s is None:
        raise RuntimeError(f"{action.agent} has no setting {'.'.join(action.data['key'])}")
    # Edit the real file behind a symlinked settings file (dotfile repos), keeping the link.
    path = Path(os.path.realpath(expand(s.path)))
    existed = path.is_file()
    backup = None
    created_dirs: List[str] = []
    text = ""
    if existed:
        backup = journal.unique_file("settings", f"{action.agent}-{path.name}")
        shutil.copy2(str(path), str(backup))
        text = path.read_text()
    if s.fmt == "toml":
        try:
            new_text = tomlkeys.set_value(text, ".".join(s.key[:-1]) or None, s.key[-1], s.disabled_value)
        except ValueError as exc:
            raise RuntimeError(f"{path}: {exc}")
    else:
        try:
            data = json.loads(text or "{}")
        except ValueError as exc:
            raise RuntimeError(f"{path} is not valid JSON: {exc}")
        if not isinstance(data, dict):
            raise RuntimeError(f"{path} does not contain a JSON object")
        cur = data
        for k in s.key[:-1]:
            if not isinstance(cur.get(k), dict):
                cur[k] = {}
            cur = cur[k]
        cur[s.key[-1]] = s.disabled_value
        new_text = json.dumps(data, indent=2) + "\n"
    if not existed:
        missing = [p for p in [path.parent, *path.parent.parents] if not p.exists()]
        path.parent.mkdir(parents=True, exist_ok=True)
        created_dirs = [str(p) for p in missing]
    mode = path.stat().st_mode & 0o7777 if existed else 0o600
    atomic_write(path, new_text, mode=mode)
    return {"path": str(path), "existed": existed, "backup": str(backup) if backup else None,
            "created_dirs": created_dirs}


def _apply_prune(action: Action, journal: Journal) -> Dict[str, Any]:
    src = Path(action.data["path"])
    # checked again here: a session may have started from this version since the scan
    busy = running_from(list_processes(), str(src))
    if busy:
        raise RuntimeError(f"still in use by pid {', '.join(str(p.pid) for p in busy)}; left in place")
    dest = journal.trash_slot(action.agent, src.name)
    # rename within the same filesystem is instant and keeps every attribute intact
    shutil.move(str(src), str(dest))
    return {"original": str(src), "trash": str(dest), "bytes": action.bytes}


def _apply_kill(action: Action, journal: Journal) -> Dict[str, Any]:
    pid = int(action.data["pid"])
    # The pid may have exited and been reused since the scan; only signal the same process.
    current = next((p for p in list_processes() if p.pid == pid), None)
    if current is None:
        raise RuntimeError("process already exited")
    if current.command != action.data["command"]:
        raise RuntimeError("pid now belongs to a different process; not touching it")
    return {"pid": pid, "signal": _terminate(pid), "command": action.data["command"]}


def _terminate(pid: int, grace: float = 5) -> str:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return "gone"
    deadline = time.time() + grace
    while time.time() < deadline:
        if not is_running(pid):
            return "TERM"
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return "TERM"
    return "KILL"


_APPLIERS = {
    "stop-daemon": _apply_stop_daemon,
    "disable-launchagent": _apply_launchagent,
    "disable-systemd": _apply_systemd,
    "disable-cron": _apply_cron,
    "disable-setting": _apply_setting,
    "prune-version": _apply_prune,
    "kill-process": _apply_kill,
}
