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
from typing import Any, Dict, List, Optional

from . import agents
from .journal import Journal
from .model import AutostartEntry, Inventory
from .output import human_bytes, shorten_home, table
from .platform import atomic_write, have, run, uid
from .scan.autostart import read_crontab
from .scan.footprint import select_prunable
from .scan.processes import list_processes

DEFAULT_KEEP = 2


@dataclass
class Action:
    kind: str  # disable-launchagent | disable-systemd | disable-cron | disable-self-update | prune-version | kill-process
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

    if autostart:
        for e in inv.autostarts:
            if not e.enabled:
                continue
            if not e.user_writable:
                plan.skipped.append(f"{e.kind} {e.id} is system-wide ({e.path}); needs sudo, skipped")
                continue
            plan.actions.append(_plan_autostart(e))

    if self_update:
        for a in inv.agents:
            su = a.self_update
            if su is None or not su.supported or su.disabled or not a.installed:
                continue
            plan.actions.append(Action(
                kind="disable-self-update", agent=a.name, target=su.path or "",
                description=f"set {su.key} in {shorten_home(su.path or '')} (backup of file kept)",
                data={"path": su.path},
            ))

    if prune:
        for a in inv.agents:
            n = keep_per_agent.get(a.name, keep)
            for v in select_prunable(a.versions, n):
                plan.actions.append(Action(
                    kind="prune-version", agent=a.name, target=v.path, bytes=v.bytes,
                    description=f"move {a.name} {v.version} ({human_bytes(v.bytes)}) to trash; keep newest {n}",
                    data={"path": v.path, "version": v.version},
                ))

    if kill:
        for p in inv.processes:
            if p.orphaned:
                plan.actions.append(Action(
                    kind="kill-process", agent=p.agent or "?", target=str(p.pid), reversible=False,
                    description=f"terminate pid {p.pid} ({p.command[:60]}) — session ended, parent gone",
                    data={"pid": p.pid, "command": p.command},
                ))
    return plan


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


def _apply_self_update(action: Action, journal: Journal) -> Dict[str, Any]:
    spec = agents.by_name(action.agent)
    if spec is None or spec.self_update is None:
        raise RuntimeError(f"{action.agent} has no self-update setting")
    # Edit the real file behind a symlinked settings file (dotfile repos), keeping the link.
    path = Path(os.path.realpath(action.data["path"]))
    existed = path.is_file()
    backup = None
    created_dirs: List[str] = []
    if existed:
        backup = journal.unique_file("settings", f"{action.agent}-{path.name}")
        shutil.copy2(str(path), str(backup))
        try:
            data = json.loads(path.read_text() or "{}")
        except ValueError as exc:
            raise RuntimeError(f"{path} is not valid JSON: {exc}")
        if not isinstance(data, dict):
            raise RuntimeError(f"{path} does not contain a JSON object")
    else:
        data = {}
        missing = [p for p in [path.parent, *path.parent.parents] if not p.exists()]
        path.parent.mkdir(parents=True, exist_ok=True)
        created_dirs = [str(p) for p in missing]
    cur = data
    for k in spec.self_update.key[:-1]:
        if not isinstance(cur.get(k), dict):
            cur[k] = {}
        cur = cur[k]
    cur[spec.self_update.key[-1]] = spec.self_update.disabled_value
    mode = path.stat().st_mode & 0o7777 if existed else 0o600
    atomic_write(path, json.dumps(data, indent=2) + "\n", mode=mode)
    return {"path": str(path), "existed": existed, "backup": str(backup) if backup else None,
            "created_dirs": created_dirs}


def _apply_prune(action: Action, journal: Journal) -> Dict[str, Any]:
    src = Path(action.data["path"])
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
    os.kill(pid, signal.SIGTERM)
    deadline = time.time() + 5
    while time.time() < deadline:
        if not _alive(pid):
            return {"pid": pid, "signal": "TERM", "command": action.data["command"]}
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    return {"pid": pid, "signal": "KILL", "command": action.data["command"]}


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # zombie check on Linux
    try:
        with open(f"/proc/{pid}/stat") as fh:
            return fh.read().split(") ")[-1][0] != "Z"
    except OSError:
        return True


_APPLIERS = {
    "disable-launchagent": _apply_launchagent,
    "disable-systemd": _apply_systemd,
    "disable-cron": _apply_cron,
    "disable-self-update": _apply_self_update,
    "prune-version": _apply_prune,
    "kill-process": _apply_kill,
}
