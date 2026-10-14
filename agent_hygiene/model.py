"""Plain dataclasses that make up a scan inventory. Everything here serialises to JSON."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DiskEntry:
    path: str
    bytes: int
    kind: str  # home | npm | pipx | uv | versions | binary | data


@dataclass
class NpmInstall:
    package: str
    version: str
    path: str
    bytes: int
    manager: str  # npm | pnpm | bun | volta | nvm


@dataclass
class VersionEntry:
    path: str
    root: str
    version: str
    bytes: int
    mtime: float
    is_dir: bool
    is_current: bool


@dataclass
class SelfUpdateSetting:
    agent: str
    supported: bool
    path: Optional[str] = None
    key: Optional[str] = None
    current_value: Any = None
    disabled: Optional[bool] = None
    note: str = ""


@dataclass
class AgentFootprint:
    name: str
    display: str
    installed: bool
    paths: List[DiskEntry] = field(default_factory=list)
    npm: List[NpmInstall] = field(default_factory=list)
    binaries: List[str] = field(default_factory=list)
    versions_roots: List[str] = field(default_factory=list)
    versions: List[VersionEntry] = field(default_factory=list)  # sorted newest-first within each root
    self_update: Optional[SelfUpdateSetting] = None
    total_bytes: int = 0

    def versions_by_root(self) -> Dict[str, List[VersionEntry]]:
        out: Dict[str, List[VersionEntry]] = {}
        for v in self.versions:
            out.setdefault(v.root, []).append(v)
        return out

    @property
    def stale_versions(self) -> List[VersionEntry]:
        """Per root: everything except the newest and the current one."""
        return [v for vs in self.versions_by_root().values() for v in vs[1:] if not v.is_current]


@dataclass
class AutostartEntry:
    kind: str  # launchagent | systemd-user | cron
    id: str  # label, unit name, or cron line hash
    path: str  # plist/unit path, or "crontab"
    agent: Optional[str]
    enabled: bool
    program: str
    detail: str = ""
    user_writable: bool = True


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    pgid: int
    tty: str
    etime_s: int
    rss_kb: int
    command: str
    agent: Optional[str] = None
    orphaned: bool = False
    parent_command: str = ""


@dataclass
class PortInfo:
    pid: int
    agent: Optional[str]
    proto: str
    local: str
    remote: str
    state: str


@dataclass
class Inventory:
    host: str
    os: str
    generated_at: str
    agents: List[AgentFootprint] = field(default_factory=list)
    autostarts: List[AutostartEntry] = field(default_factory=list)
    processes: List[ProcessInfo] = field(default_factory=list)
    ports: List[PortInfo] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        for a, fp in zip(d["agents"], self.agents):
            a["stale_versions"] = [v.path for v in fp.stale_versions]
        return d

    def agent(self, name: str) -> Optional[AgentFootprint]:
        for a in self.agents:
            if a.name == name:
                return a
        return None
