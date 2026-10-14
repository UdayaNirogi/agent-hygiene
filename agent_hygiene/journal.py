"""Backup journal: every change `clean` makes is recorded here so `restore` can undo it.

Layout:
    ~/.agent-hygiene/backups/<id>/manifest.json   ordered list of applied actions
    ~/.agent-hygiene/backups/<id>/files/...        copies of edited files, moved plists
    ~/.agent-hygiene/backups/<id>/trash/...        pruned version folders (renamed, not copied)
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .platform import atomic_write, backups_dir, is_within, private_state_dir


class Journal:
    def __init__(self, root: Path):
        self.root = root
        self.files = root / "files"
        self.trash = root / "trash"
        self.manifest_path = root / "manifest.json"
        self.data: Dict[str, Any] = {
            "id": root.name,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "restored_at": None,
            "purged_at": None,
            "actions": [],
        }

    @classmethod
    def create(cls) -> "Journal":
        private_state_dir()
        base = backups_dir()
        base.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        root = base / stamp
        n = 1
        while root.exists():
            n += 1
            root = base / f"{stamp}-{n}"
        j = cls(root)
        j.files.mkdir(parents=True)
        j.trash.mkdir(parents=True)
        j.save()
        return j

    @classmethod
    def load(cls, root: Path) -> "Journal":
        j = cls(root)
        j.data = json.loads(j.manifest_path.read_text())
        return j

    @classmethod
    def list_all(cls) -> List["Journal"]:
        base = backups_dir()
        if not base.is_dir():
            return []
        out = []
        for d in sorted(base.iterdir()):
            if (d / "manifest.json").is_file():
                try:
                    out.append(cls.load(d))
                except (OSError, ValueError):
                    continue
        return out

    @classmethod
    def find(cls, ident: Optional[str]) -> Optional["Journal"]:
        all_ = cls.list_all()
        if ident:
            for j in all_:
                if j.id == ident:
                    return j
            return None
        pending = [j for j in all_ if j.restored_at is None and j.actions]
        return pending[-1] if pending else None

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def actions(self) -> List[Dict[str, Any]]:
        return self.data["actions"]

    @property
    def restored_at(self) -> Optional[str]:
        return self.data.get("restored_at")

    @property
    def purged_at(self) -> Optional[str]:
        return self.data.get("purged_at")

    @property
    def created_at(self) -> str:
        return self.data["created_at"]

    def record(self, action: Dict[str, Any]) -> None:
        self.actions.append(action)
        self.save()

    def mark(self, key: str) -> None:
        self.data[key] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        self.save()

    def save(self) -> None:
        atomic_write(self.manifest_path, json.dumps(self.data, indent=2, default=str), mode=0o600)

    def owns(self, path: str) -> bool:
        """Backup and trash paths in a manifest must point inside this journal."""
        return is_within(path, self.root)

    def unique_file(self, sub: str, name: str) -> Path:
        d = self.files / sub
        d.mkdir(parents=True, exist_ok=True)
        target = d / name
        n = 1
        while target.exists():
            n += 1
            target = d / f"{name}.{n}"
        return target

    def trash_slot(self, agent: str, name: str) -> Path:
        d = self.trash / agent
        d.mkdir(parents=True, exist_ok=True)
        target = d / name
        n = 1
        while os.path.lexists(target):
            n += 1
            target = d / f"{name}.{n}"
        return target

    def trash_bytes(self) -> int:
        total = 0
        for root, dirs, files in os.walk(self.trash, onerror=lambda e: None):
            for name in dirs + files:
                try:
                    st = os.lstat(os.path.join(root, name))
                    total += getattr(st, "st_blocks", 0) * 512 or st.st_size
                except OSError:
                    continue
        return total
