"""Undo a `clean` run from its journal, and `purge` trash to free space for good."""
from __future__ import annotations

import datetime as dt
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import agents
from .journal import Journal
from .output import human_bytes, table
from .platform import have, run, uid
from .scan.processes import list_processes, running_from


def render_backups(journals: List[Journal]) -> str:
    if not journals:
        return "no backups"
    rows = []
    for j in journals:
        status = "restored" if j.restored_at else ("purged" if j.purged_at else "pending")
        kinds: Dict[str, int] = {}
        for a in j.actions:
            kinds[a["kind"]] = kinds.get(a["kind"], 0) + 1
        rows.append([j.id, j.created_at, status, human_bytes(j.trash_bytes()),
                     ", ".join(f"{k}×{n}" for k, n in sorted(kinds.items())) or "-"])
    return table(["id", "created", "status", "in trash", "actions"], rows)


def restore(journal: Journal, log=print) -> int:
    """Reverse every reversible action, newest first. Returns the number of failures."""
    if journal.restored_at:
        log(f"backup {journal.id} was already restored at {journal.restored_at}")
        return 0
    if journal.purged_at:
        log(f"backup {journal.id} was purged at {journal.purged_at}; pruned versions cannot come back, "
            f"restoring the remaining settings and auto-start entries")
    failures = 0
    for rec in reversed(journal.actions):
        if not rec.get("reversible", True):
            log(f"  skip   {rec['kind']} {rec['target']} (not reversible)")
            continue
        if rec.get("restored"):
            continue
        handler = _RESTORERS.get(rec["kind"])
        if handler is None:
            log(f"  skip   {rec['kind']} (unknown)")
            continue
        try:
            for key in ("backup", "trash"):
                if rec.get(key) and not journal.owns(rec[key]):
                    raise ValueError(f"manifest {key} path {rec[key]} is outside the backup folder; refusing")
            handler(rec)
            rec["restored"] = True
            journal.save()
            log(f"  undone {rec['kind']} {rec['target']}")
        except Exception as exc:
            failures += 1
            log(f"  FAILED {rec['kind']} {rec['target']}: {exc}")
    if failures == 0:
        journal.mark("restored_at")
    return failures


def _restore_launchagent(rec: Dict[str, Any]) -> None:
    backup, original = Path(rec["backup"]), Path(rec["original"])
    if not backup.exists():
        raise FileNotFoundError(f"backup plist missing: {backup}")
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(backup), str(original))
    if have("launchctl"):
        res = run(["launchctl", "bootstrap", f"gui/{uid()}", str(original)], timeout=15)
        if res.returncode != 0:
            run(["launchctl", "load", str(original)], timeout=15)


def _restore_systemd(rec: Dict[str, Any]) -> None:
    unit = rec["unit"]
    if rec.get("was_enabled") in ("enabled", "enabled-runtime"):
        res = run(["systemctl", "--user", "enable", "--", unit], timeout=20)
        if res.returncode != 0:
            raise RuntimeError(res.stderr.strip())
    if rec.get("was_active") == "active":
        run(["systemctl", "--user", "start", "--", unit], timeout=20)


def _restore_cron(rec: Dict[str, Any]) -> None:
    text = Path(rec["backup"]).read_text()
    if text.strip():
        res = run(["crontab", "-"], input_text=text, timeout=10)
    else:
        res = run(["crontab", "-r"], timeout=10)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "crontab write failed")


def _restore_daemon(rec: Dict[str, Any]) -> None:
    if not rec.get("server_running"):
        return
    spec = agents.by_name(rec.get("agent", ""))
    if spec is None or spec.daemon is None:
        raise RuntimeError(f"{rec.get('agent')} has no background server")
    binary = rec.get("binary") or ""
    # the manifest is only trusted to name a program inside the agent's own folders
    real = os.path.realpath(binary) if binary else ""
    if not real or not any(real.startswith(os.path.realpath(f).rstrip(os.sep) + os.sep) for f in spec.own_folders()):
        raise RuntimeError(f"{binary or 'binary'} is not inside {spec.name}'s own folders; refusing to run it")
    if not (os.path.isfile(real) and os.access(real, os.X_OK)):
        raise FileNotFoundError(f"{binary} is missing; start the server with `{spec.name} "
                                f"{' '.join(spec.daemon.start_args)}`")
    res = run([real, *spec.daemon.start_args], timeout=120)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or f"exited {res.returncode}")


def _restore_self_update(rec: Dict[str, Any]) -> None:
    path = Path(rec["path"])
    if rec.get("existed") and rec.get("backup"):
        shutil.copy2(rec["backup"], str(path))
    else:
        if path.exists():
            path.unlink()
        # remove the directories we created, deepest first, only while they are empty
        for d in rec.get("created_dirs", []):
            try:
                os.rmdir(d)
            except OSError:
                break


def _restore_prune(rec: Dict[str, Any]) -> None:
    trash, original = Path(rec["trash"]), Path(rec["original"])
    if not os.path.lexists(trash):
        raise FileNotFoundError(f"trashed version missing (purged?): {trash}")
    if os.path.lexists(original):
        raise FileExistsError(f"{original} already exists; not overwriting")
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(trash), str(original))


_RESTORERS = {
    "stop-daemon": _restore_daemon,
    "disable-launchagent": _restore_launchagent,
    "disable-systemd": _restore_systemd,
    "disable-cron": _restore_cron,
    "disable-setting": _restore_self_update,
    "disable-self-update": _restore_self_update,  # journals written by 0.1.x
    "prune-version": _restore_prune,
}


# --- purge -----------------------------------------------------------------------------

def purgeable(journals: List[Journal], older_than_days: Optional[float]) -> List[Journal]:
    out = []
    now = dt.datetime.now(dt.timezone.utc)
    for j in journals:
        if j.purged_at or j.restored_at or j.trash_bytes() == 0:
            continue
        if older_than_days is not None:
            created = dt.datetime.fromisoformat(j.created_at)
            if (now - created).total_seconds() < older_than_days * 86400:
                continue
        out.append(j)
    return out


def purge(journal: Journal, log=print) -> int:
    if journal.trash.is_symlink() or not journal.owns(str(journal.trash)):
        raise RuntimeError(f"{journal.trash} is not a real folder inside the backup; refusing to purge")
    procs = list_processes()
    before = journal.trash_bytes()
    kept = []
    for agent_dir in list(journal.trash.iterdir()):
        slots = list(agent_dir.iterdir()) if agent_dir.is_dir() and not agent_dir.is_symlink() else [agent_dir]
        for child in slots:
            # a process can keep running from a version after it was moved to trash
            busy = running_from(procs, str(child))
            if busy:
                kept.append(child)
                log(f"  kept   {child.name}: still in use by pid {', '.join(str(p.pid) for p in busy)}")
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        if agent_dir.is_dir() and not agent_dir.is_symlink() and not any(agent_dir.iterdir()):
            agent_dir.rmdir()
    freed = before - journal.trash_bytes()
    if not kept:
        journal.mark("purged_at")
    log(f"  purged {journal.id}: freed {human_bytes(freed)}"
        + (f"; {len(kept)} in-use version(s) kept, purge again once they exit" if kept else ""))
    return freed
