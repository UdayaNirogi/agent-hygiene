"""Shared test helpers: a fake $HOME and a tree fingerprint for identical-state checks."""
from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Tuple


class FakeHomeTestCase(unittest.TestCase):
    """Points $HOME (and the agent-hygiene state dir) at a temp directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.home = Path(self._tmp.name) / "home"
        self.home.mkdir()
        self._saved = {k: os.environ.get(k) for k in ("HOME", "AGENT_HYGIENE_HOME", "XDG_CONFIG_HOME")}
        os.environ["HOME"] = str(self.home)
        os.environ["AGENT_HYGIENE_HOME"] = str(self.home / ".agent-hygiene")
        os.environ.pop("XDG_CONFIG_HOME", None)

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._tmp.cleanup()

    def write(self, rel: str, content: str = "", size: int = 0) -> Path:
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if size:
            with open(p, "wb") as fh:
                fh.write(os.urandom(size))
        else:
            p.write_text(content)
        return p


def fingerprint(root: Path, ignore_prefixes: Tuple[str, ...] = ()) -> Dict[str, str]:
    """Relative path -> 'mode:size:sha1' for files, 'dir'/'link->target' otherwise."""
    out: Dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if any((rel_dir == p or rel_dir.startswith(p + os.sep)) for p in ignore_prefixes):
            dirnames[:] = []
            continue
        for name in dirnames:
            full = Path(dirpath) / name
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if rel in ignore_prefixes:
                continue
            out[rel] = f"link->{os.readlink(full)}" if full.is_symlink() else f"dir:{oct(full.stat().st_mode)}"
        for name in filenames:
            full = Path(dirpath) / name
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if full.is_symlink():
                out[rel] = f"link->{os.readlink(full)}"
                continue
            st = full.stat()
            h = hashlib.sha1(full.read_bytes()).hexdigest()
            out[rel] = f"{oct(st.st_mode)}:{st.st_size}:{h}"
    return out
