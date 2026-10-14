"""Where an agent lives on disk: home/config dirs, global installs, version folders."""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..agents import AgentSpec
from ..model import AgentFootprint, DiskEntry, NpmInstall, SelfUpdateSetting, VersionEntry
from ..platform import expand, have, home, run

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+(?:[-+.][0-9A-Za-z.]+)?)")


def path_size(path: Path) -> int:
    """Allocated bytes under path (not following symlinks). Errors are ignored."""
    try:
        st = path.lstat()
    except OSError:
        return 0
    if not path.is_dir() or path.is_symlink():
        return _alloc(st)
    total = _alloc(st)
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        for name in dirs + files:
            try:
                total += _alloc(os.lstat(os.path.join(root, name)))
            except OSError:
                continue
    return total


def _alloc(st: os.stat_result) -> int:
    blocks = getattr(st, "st_blocks", None)
    if blocks is not None:
        return blocks * 512
    return st.st_size


def _expand_all(patterns) -> List[Path]:
    out: List[Path] = []
    for pat in patterns:
        expanded = str(expand(pat))
        if any(ch in expanded for ch in "*?["):
            out.extend(Path(p) for p in sorted(glob.glob(expanded)))
        elif os.path.lexists(expanded):
            out.append(Path(expanded))
    return out


# --- global package managers -------------------------------------------------

def npm_global_roots() -> List[Tuple[Path, str]]:
    """Candidate global node_modules roots, tagged with the manager that owns them."""
    h = home()
    roots: List[Tuple[Path, str]] = [
        (Path("/usr/local/lib/node_modules"), "npm"),
        (Path("/opt/homebrew/lib/node_modules"), "npm"),
        (Path("/usr/lib/node_modules"), "npm"),
        (h / ".npm-global" / "lib" / "node_modules", "npm"),
        (h / ".local" / "lib" / "node_modules", "npm"),
        (h / ".bun" / "install" / "global" / "node_modules", "bun"),
        (h / ".local" / "share" / "pnpm" / "global" / "5" / "node_modules", "pnpm"),
        (h / "Library" / "pnpm" / "global" / "5" / "node_modules", "pnpm"),
        (h / ".volta" / "tools" / "image" / "packages", "volta"),
    ]
    roots += [(Path(p), "nvm") for p in sorted(glob.glob(str(h / ".nvm/versions/node/*/lib/node_modules")))]
    roots += [(Path(p), "fnm") for p in sorted(glob.glob(str(h / ".local/share/fnm/node-versions/*/installation/lib/node_modules")))]
    roots += [(Path(p), "fnm") for p in sorted(glob.glob(str(h / "Library/Application Support/fnm/node-versions/*/installation/lib/node_modules")))]
    roots += [(Path(p), "asdf") for p in sorted(glob.glob(str(h / ".asdf/installs/nodejs/*/lib/node_modules")))]
    prefix = os.environ.get("NPM_CONFIG_PREFIX")
    if prefix:
        roots.append((Path(prefix) / "lib" / "node_modules", "npm"))
    if have("npm"):
        res = run(["npm", "root", "-g"], timeout=10)
        if res.returncode == 0 and res.stdout.strip():
            roots.append((Path(res.stdout.strip()), "npm"))
    seen, uniq = set(), []
    for p, mgr in roots:
        key = str(p)
        if key not in seen and p.is_dir():
            seen.add(key)
            uniq.append((p, mgr))
    return uniq


def find_npm_installs(spec: AgentSpec, roots: Optional[List[Tuple[Path, str]]] = None) -> List[NpmInstall]:
    if not spec.npm_packages:
        return []
    roots = npm_global_roots() if roots is None else roots
    found: List[NpmInstall] = []
    for root, manager in roots:
        for pkg in spec.npm_packages:
            pkg_dir = root / pkg
            if manager == "volta":
                # volta stores packages/<name>/lib/node_modules/<name>
                pkg_dir = root / pkg.split("/")[-1] / "lib" / "node_modules" / pkg
            manifest = pkg_dir / "package.json"
            if not manifest.is_file():
                continue
            version = "?"
            try:
                version = str(json.loads(manifest.read_text()).get("version", "?"))
            except (OSError, ValueError):
                pass
            found.append(NpmInstall(pkg, version, str(pkg_dir), path_size(pkg_dir), manager))
    return found


# --- version folders ---------------------------------------------------------

def _version_key(name: str, mtime: float) -> Tuple[Tuple[int, ...], float]:
    m = _VERSION_RE.search(name)
    if not m:
        return ((), mtime)
    core = m.group(1).split("-")[0].split("+")[0]
    parts: List[int] = []
    for piece in core.split("."):
        digits = re.match(r"\d+", piece)
        parts.append(int(digits.group(0)) if digits else 0)
    return (tuple(parts), mtime)


def find_versions(spec: AgentSpec) -> Tuple[List[str], List[VersionEntry]]:
    """All version entries across every versions root, sorted newest-first within each root."""
    roots = [r for r in _expand_all(spec.versions_roots) if r.is_dir()]
    if not roots:
        return [], []
    current_targets = set()
    for link in _expand_all(spec.current_links):
        try:
            current_targets.add(os.path.realpath(link))
        except OSError:
            continue
    all_entries: List[VersionEntry] = []
    for root in roots:
        entries: List[VersionEntry] = []
        for child in root.iterdir():
            if child.name.startswith("."):
                continue
            m = _VERSION_RE.search(child.name)
            if not m:
                continue
            try:
                st = child.lstat()
            except OSError:
                continue
            real = os.path.realpath(child)
            is_current = any(t == real or t.startswith(real + os.sep) for t in current_targets)
            entries.append(VersionEntry(
                path=str(child), root=str(root), version=m.group(1), bytes=path_size(child),
                mtime=st.st_mtime, is_dir=child.is_dir() and not child.is_symlink(),
                is_current=is_current,
            ))
        entries.sort(key=lambda v: _version_key(v.version, v.mtime), reverse=True)
        all_entries.extend(entries)
    return [str(r) for r in roots], all_entries


def select_prunable(versions: List[VersionEntry], keep: int) -> List[VersionEntry]:
    """Per root: everything beyond the newest `keep`, never the current one.
    Input must be sorted newest-first within each root."""
    keep = max(keep, 1)
    by_root: Dict[str, List[VersionEntry]] = {}
    for v in versions:
        by_root.setdefault(v.root, []).append(v)
    out: List[VersionEntry] = []
    for vs in by_root.values():
        out.extend(v for v in vs[keep:] if not v.is_current)
    return out


# --- self-update setting ------------------------------------------------------

def read_nested(data: Dict[str, Any], key: Tuple[str, ...]):
    cur: Any = data
    for k in key:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def self_update_state(spec: AgentSpec) -> SelfUpdateSetting:
    if spec.self_update is None:
        return SelfUpdateSetting(agent=spec.name, supported=False, note=spec.self_update_note)
    su = spec.self_update
    path = expand(su.path)
    value = None
    if path.is_file():
        try:
            value = read_nested(json.loads(path.read_text() or "{}"), su.key)
        except (OSError, ValueError):
            value = None
    return SelfUpdateSetting(
        agent=spec.name, supported=True, path=str(path), key=".".join(su.key),
        current_value=value, disabled=(value == su.disabled_value), note=su.note,
    )


# --- put it together ----------------------------------------------------------

def scan_agent(spec: AgentSpec, npm_roots: Optional[List[Tuple[Path, str]]] = None) -> AgentFootprint:
    fp = AgentFootprint(name=spec.name, display=spec.display, installed=False)
    for p in _expand_all(spec.home_dirs):
        fp.paths.append(DiskEntry(str(p), path_size(p), "home"))
    for p in _expand_all(spec.data_dirs):
        fp.paths.append(DiskEntry(str(p), path_size(p), "data"))
    fp.npm = find_npm_installs(spec, npm_roots)
    for b in spec.binaries:
        found = shutil.which(b)
        if found:
            fp.binaries.append(found)
    fp.versions_roots, fp.versions = find_versions(spec)
    fp.self_update = self_update_state(spec)

    # Version roots usually sit inside a data dir that is already counted; only add
    # them separately when they are not.
    counted = [e.path for e in fp.paths]
    for root in fp.versions_roots:
        if not any(root == c or root.startswith(c + os.sep) for c in counted):
            fp.paths.append(DiskEntry(root, sum(v.bytes for v in fp.versions if v.root == root), "versions"))

    fp.total_bytes = sum(e.bytes for e in fp.paths) + sum(n.bytes for n in fp.npm)
    fp.installed = bool(fp.binaries or fp.npm or fp.versions or any(
        e.kind in ("home", "data") and e.bytes > 0 for e in fp.paths))
    return fp
