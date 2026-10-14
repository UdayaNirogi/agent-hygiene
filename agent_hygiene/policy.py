"""Optional policy file: what a team allows. `policy check` exits non-zero on violations so
it can run in CI or an onboarding script.

Example (JSON):
{
  "keep_versions": 2,
  "max_disk_per_agent": "5GB",
  "max_disk_total": "20GB",
  "allowed_autostarts": ["com.example.allowed.*"],
  "allow_self_update": false,
  "allow_leftover_processes": false,
  "agents": { "codex": { "keep_versions": 1, "max_disk": "2GB" } }
}
"""
from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .model import Inventory
from .output import human_bytes, table
from .platform import parse_bytes

TEMPLATE: Dict[str, Any] = {
    "keep_versions": 2,
    "max_disk_per_agent": "5GB",
    "max_disk_total": "20GB",
    "allowed_autostarts": [],
    "allow_self_update": False,
    "allow_leftover_processes": False,
    "agents": {},
}

DEFAULT_LOCATIONS = [
    "./agent-hygiene.policy.json",
    "./.agent-hygiene.json",
    "~/.config/agent-hygiene/policy.json",
]


@dataclass
class Violation:
    rule: str
    agent: str
    detail: str
    fix: str


_INT_KEYS = ("keep_versions",)
_SIZE_KEYS = ("max_disk_per_agent", "max_disk_total", "max_disk")
_BOOL_KEYS = ("allow_self_update", "allow_leftover_processes")


def _validate_block(block: Dict[str, Any], where: str) -> None:
    for k in _INT_KEYS:
        if k in block and (not isinstance(block[k], int) or isinstance(block[k], bool) or not 1 <= block[k] <= 1000):
            raise ValueError(f"{where}{k} must be an integer between 1 and 1000")
    for k in _SIZE_KEYS:
        if k in block and block[k] not in (None, ""):
            try:
                parse_bytes(block[k])
            except (TypeError, ValueError):
                raise ValueError(f"{where}{k} must be a size like \"5GB\"")
    for k in _BOOL_KEYS:
        if k in block and not isinstance(block[k], bool):
            raise ValueError(f"{where}{k} must be true or false")


def validate(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("policy must be a JSON object")
    _validate_block(data, "")
    allowed = data.get("allowed_autostarts", [])
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise ValueError("allowed_autostarts must be a list of strings")
    per_agent = data.get("agents", {}) or {}
    if not isinstance(per_agent, dict):
        raise ValueError("agents must be an object")
    for name, cfg in per_agent.items():
        if not isinstance(cfg, dict):
            raise ValueError(f"agents.{name} must be an object")
        _validate_block(cfg, f"agents.{name}.")
    return data


class Policy:
    def __init__(self, data: Dict[str, Any], source: str = "<inline>"):
        self.data = validate(data)
        self.source = source

    @classmethod
    def load(cls, path: Optional[str], include_cwd: bool = True) -> Optional["Policy"]:
        """`include_cwd=False` ignores policy files in the current directory, so a cloned
        repository cannot change what `clean` does just by shipping a policy file."""
        defaults = [loc for loc in DEFAULT_LOCATIONS if include_cwd or not loc.startswith("./")]
        candidates = [path] if path else ([os.environ.get("AGENT_HYGIENE_POLICY")] + defaults)
        for cand in candidates:
            if not cand:
                continue
            p = Path(os.path.expanduser(cand))
            if p.is_file():
                try:
                    data = json.loads(p.read_text())
                except ValueError as exc:
                    raise ValueError(f"{p}: invalid JSON: {exc}")
                try:
                    return cls(data, str(p))
                except ValueError as exc:
                    raise ValueError(f"{p}: {exc}")
            if path:
                raise FileNotFoundError(f"policy file not found: {p}")
        return None

    def agent_cfg(self, name: str) -> Dict[str, Any]:
        return (self.data.get("agents") or {}).get(name, {}) or {}

    def keep_versions(self, name: Optional[str] = None) -> int:
        if name and "keep_versions" in self.agent_cfg(name):
            return int(self.agent_cfg(name)["keep_versions"])
        return int(self.data.get("keep_versions", 2))

    def keep_per_agent(self) -> Dict[str, int]:
        return {n: int(cfg["keep_versions"]) for n, cfg in (self.data.get("agents") or {}).items()
                if isinstance(cfg, dict) and "keep_versions" in cfg}

    def max_disk(self, name: str) -> Optional[int]:
        cfg = self.agent_cfg(name)
        raw = cfg.get("max_disk", self.data.get("max_disk_per_agent"))
        return parse_bytes(raw) if raw not in (None, "") else None

    def autostart_allowed(self, ident: str) -> bool:
        return any(fnmatch.fnmatch(ident, pat) for pat in self.data.get("allowed_autostarts", []) or [])

    def evaluate(self, inv: Inventory) -> List[Violation]:
        v: List[Violation] = []
        total = 0
        for a in inv.agents:
            total += a.total_bytes
            keep = self.keep_versions(a.name)
            extra = [x for x in a.versions[keep:] if not x.is_current]
            if extra:
                v.append(Violation("keep_versions", a.name,
                                   f"{len(a.versions)} versions installed, policy keeps {keep} "
                                   f"({human_bytes(sum(x.bytes for x in extra))} over)",
                                   f"agent-hygiene clean --agent {a.name} --keep {keep}"))
            limit = self.max_disk(a.name)
            if limit is not None and a.total_bytes > limit:
                v.append(Violation("max_disk", a.name,
                                   f"uses {human_bytes(a.total_bytes)}, limit {human_bytes(limit)}",
                                   f"agent-hygiene clean --agent {a.name}"))
            if not a.installed:
                continue
            if not self.data.get("allow_self_update", True):
                for s in a.settings_on("self-update"):
                    v.append(Violation("allow_self_update", a.name, f"self-update is on ({s.key} in {s.path})",
                                       f"agent-hygiene clean --agent {a.name} --self-update"))
            for s in a.settings_on("auto-start"):
                ident = f"{a.name}:{s.key}"
                if not self.autostart_allowed(ident):
                    v.append(Violation("allowed_autostarts", a.name, f"setting {ident} is on ({s.path})",
                                       f"agent-hygiene clean --agent {a.name} --autostart"))
        limit_total = self.data.get("max_disk_total")
        if limit_total and total > parse_bytes(limit_total):
            v.append(Violation("max_disk_total", "*", f"all agents use {human_bytes(total)}, limit {limit_total}",
                               "agent-hygiene clean"))
        for e in inv.autostarts:
            if e.enabled and not self.autostart_allowed(e.id):
                v.append(Violation("allowed_autostarts", e.agent or "?", f"{e.kind} {e.id} is enabled",
                                   f"agent-hygiene clean --agent {e.agent} --autostart"))
        if not self.data.get("allow_leftover_processes", True):
            for p in inv.processes:
                if p.orphaned:
                    v.append(Violation("allow_leftover_processes", p.agent or "?",
                                       f"pid {p.pid} ({p.command[:50]}) outlived its session",
                                       f"agent-hygiene clean --agent {p.agent} --kill"))
        return v


def render_violations(violations: List[Violation], source: str) -> str:
    if not violations:
        return f"policy {source}: OK"
    rows = [[x.rule, x.agent, x.detail, x.fix] for x in violations]
    return f"policy {source}: {len(violations)} violation(s)\n" + table(["rule", "agent", "detail", "fix"], rows, max_col=90)


def write_template(path: str) -> Path:
    p = Path(os.path.expanduser(path))
    if p.exists():
        raise FileExistsError(f"{p} already exists")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(TEMPLATE, indent=2) + "\n")
    return p
