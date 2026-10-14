"""Auto-start entries: macOS LaunchAgents, systemd user units, and user crontab lines."""
from __future__ import annotations

import hashlib
import os
import plistlib
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

from .. import agents
from ..model import AutostartEntry
from .processes import redact
from ..platform import IS_LINUX, IS_MACOS, have, launch_agents_dirs, run, systemd_user_dirs, uid


def scan_autostarts(warnings: List[str]) -> List[AutostartEntry]:
    out: List[AutostartEntry] = []
    if IS_MACOS:
        out += scan_launch_agents(warnings)
    if IS_LINUX:
        out += scan_systemd_user(warnings)
    out += scan_cron(warnings)
    return out


# --- macOS LaunchAgents --------------------------------------------------------

def _launchctl_disabled_labels() -> Set[str]:
    res = run(["launchctl", "print-disabled", f"gui/{uid()}"], timeout=10)
    disabled: Set[str] = set()
    for line in res.stdout.splitlines():
        m = re.search(r'"([^"]+)"\s*=>\s*(disabled|true)', line)
        if m:
            disabled.add(m.group(1))
    return disabled


def _launchctl_loaded_labels() -> Set[str]:
    res = run(["launchctl", "list"], timeout=10)
    loaded: Set[str] = set()
    for line in res.stdout.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 3:
            loaded.add(parts[2].strip())
    return loaded


def parse_plist(path: Path) -> Optional[Dict]:
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None


def plist_program(data: Dict) -> str:
    if data.get("ProgramArguments"):
        return " ".join(str(a) for a in data["ProgramArguments"])
    return str(data.get("Program", ""))


def scan_launch_agents(warnings: List[str]) -> List[AutostartEntry]:
    entries: List[AutostartEntry] = []
    disabled = _launchctl_disabled_labels() if have("launchctl") else set()
    loaded = _launchctl_loaded_labels() if have("launchctl") else set()
    for d in launch_agents_dirs():
        if not d.is_dir():
            continue
        for plist in sorted(d.glob("*.plist")):
            data = parse_plist(plist)
            if data is None:
                warnings.append(f"could not parse {plist}")
                continue
            label = str(data.get("Label") or plist.stem)
            program = plist_program(data)
            agent = agents.match_autostart(f"{label} {program} {plist.name}")
            if not agent:
                continue
            flags = []
            if data.get("RunAtLoad"):
                flags.append("RunAtLoad")
            if data.get("KeepAlive"):
                flags.append("KeepAlive")
            if data.get("StartInterval"):
                flags.append(f"every {data['StartInterval']}s")
            if data.get("StartCalendarInterval"):
                flags.append("calendar")
            is_disabled = bool(data.get("Disabled")) or label in disabled
            entries.append(AutostartEntry(
                kind="launchagent", id=label, path=str(plist), agent=agent,
                enabled=not is_disabled, program=redact(program),
                detail=", ".join(flags) + (" (loaded)" if label in loaded else ""),
                user_writable=os.access(plist.parent, os.W_OK),
            ))
    return entries


# --- systemd user units ---------------------------------------------------------

def parse_unit(text: str) -> Dict[str, str]:
    """Minimal INI reader that tolerates duplicate keys (last one wins) and no interpolation."""
    out: Dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            out[f"{section}.{k.strip()}"] = v.strip()
    return out


def _systemd_unit_states() -> Dict[str, str]:
    states: Dict[str, str] = {}
    if not have("systemctl"):
        return states
    res = run(["systemctl", "--user", "list-unit-files", "--no-legend", "--no-pager", "--plain"], timeout=10)
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            states[parts[0]] = parts[1]
    return states


def scan_systemd_user(warnings: List[str]) -> List[AutostartEntry]:
    entries: List[AutostartEntry] = []
    states = _systemd_unit_states()
    seen: Set[str] = set()
    for d in systemd_user_dirs():
        if not d.is_dir():
            continue
        for unit in sorted(list(d.glob("*.service")) + list(d.glob("*.timer"))):
            if unit.name in seen:
                continue
            try:
                text = unit.read_text()
            except OSError:
                continue
            fields = parse_unit(text)
            program = fields.get("Service.ExecStart", "") or fields.get("Timer.Unit", "")
            desc = fields.get("Unit.Description", "")
            agent = agents.match_autostart(f"{unit.name} {program} {desc}")
            if not agent:
                continue
            seen.add(unit.name)
            state = states.get(unit.name, "unknown")
            entries.append(AutostartEntry(
                kind="systemd-user", id=unit.name, path=str(unit), agent=agent,
                enabled=state in ("enabled", "enabled-runtime", "static", "linked", "alias"),
                program=redact(program), detail=redact(f"{state}; {desc}".strip("; ")),
                user_writable=os.access(unit.parent, os.W_OK),
            ))
    return entries


# --- cron ------------------------------------------------------------------------

def read_crontab() -> Optional[str]:
    if not have("crontab"):
        return None
    res = run(["crontab", "-l"], timeout=10)
    if res.returncode != 0:
        return None  # "no crontab for user" is the common case
    return res.stdout


def cron_line_id(line: str) -> str:
    return hashlib.sha256(line.strip().encode()).hexdigest()[:10]


def scan_cron(warnings: List[str]) -> List[AutostartEntry]:
    text = read_crontab()
    if not text:
        return []
    entries: List[AutostartEntry] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" in stripped.split()[0]:
            continue
        agent = agents.match_autostart(stripped)
        if not agent:
            continue
        parts = stripped.split(None, 5)
        schedule = " ".join(parts[:5]) if len(parts) >= 6 else parts[0]
        program = parts[5] if len(parts) >= 6 else stripped
        entries.append(AutostartEntry(
            kind="cron", id=cron_line_id(stripped), path="crontab", agent=agent,
            enabled=True, program=redact(program), detail=schedule,
        ))
    return entries
