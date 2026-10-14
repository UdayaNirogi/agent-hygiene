"""Read-only inventory of agent footprints: files, auto-starts, processes, ports."""
from __future__ import annotations

import datetime as _dt
import socket
from typing import Iterable, Optional

from .. import agents as _agents
from ..model import Inventory
from ..platform import os_name
from .autostart import scan_autostarts
from .footprint import scan_agent
from .processes import scan_ports, scan_processes


def scan(only: Optional[Iterable[str]] = None, with_ports: bool = True) -> Inventory:
    wanted = set(only) if only else None
    inv = Inventory(
        host=socket.gethostname(),
        os=os_name(),
        generated_at=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    )
    for spec in _agents.AGENTS:
        if wanted and spec.name not in wanted:
            continue
        inv.agents.append(scan_agent(spec))

    inv.autostarts = [a for a in scan_autostarts(inv.warnings) if not wanted or a.agent in wanted]
    inv.processes = [p for p in scan_processes(inv.warnings) if not wanted or p.agent in wanted]
    if with_ports and inv.processes:
        inv.ports = scan_ports(inv.processes, inv.warnings)
    return inv
