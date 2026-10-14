"""OS detection, well-known paths and small subprocess helpers."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence

IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")


def os_name() -> str:
    if IS_MACOS:
        return "macos"
    if IS_LINUX:
        return "linux"
    return sys.platform


def home() -> Path:
    # Path.home() honours $HOME, which lets tests and CI point at a fake home.
    return Path.home()


def expand(p: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(p)))


def state_dir() -> Path:
    override = os.environ.get("AGENT_HYGIENE_HOME")
    return Path(override) if override else home() / ".agent-hygiene"


def private_state_dir() -> Path:
    """The state dir, created owner-only (0700): backups can hold copies of settings files
    with API keys, and run logs list file names."""
    d = state_dir()
    if d.is_symlink():
        raise RuntimeError(f"{d} is a symlink; refusing to use it as the agent-hygiene state dir")
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def backups_dir() -> Path:
    return state_dir() / "backups"


def runs_dir() -> Path:
    return state_dir() / "runs"


def atomic_write(path: Path, text: str, mode: Optional[int] = None) -> None:
    """Write via a fresh O_EXCL temp file in the same dir, then rename over `path`."""
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise


def is_within(child: str, parent: Path) -> bool:
    """True if `child` lies inside `parent`, judged without following a final symlink."""
    c = os.path.join(os.path.realpath(os.path.dirname(child)), os.path.basename(child))
    p = os.path.realpath(parent)
    return c.startswith(p + os.sep)


def uid() -> int:
    return os.getuid()


def launch_agents_dirs() -> List[Path]:
    return [home() / "Library" / "LaunchAgents", Path("/Library/LaunchAgents")]


def systemd_user_dirs() -> List[Path]:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    user_cfg = Path(xdg) if xdg else home() / ".config"
    return [
        user_cfg / "systemd" / "user",
        home() / ".local" / "share" / "systemd" / "user",
        Path("/etc/systemd/user"),
        Path("/usr/lib/systemd/user"),
        Path("/lib/systemd/user"),
    ]


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(
    args: Sequence[str],
    timeout: float = 15,
    input_text: Optional[str] = None,
    check: bool = False,
) -> subprocess.CompletedProcess:
    """Run a command, never raising on missing binaries or timeouts unless check=True."""
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=check,
        )
    except FileNotFoundError:
        if check:
            raise
        return subprocess.CompletedProcess(list(args), 127, "", f"{args[0]}: not found")
    except subprocess.TimeoutExpired:
        if check:
            raise
        return subprocess.CompletedProcess(list(args), 124, "", f"{args[0]}: timed out")


def human_bytes(n: Optional[int]) -> str:
    if n is None:
        return "-"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{n} B"


def parse_bytes(text) -> int:
    """Parse '5GB', '500 MB', '1024', or an int into bytes."""
    if isinstance(text, (int, float)):
        return int(text)
    s = str(text).strip().upper().replace(" ", "")
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4,
             "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    for suffix in sorted(units, key=len, reverse=True):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * units[suffix])
    return int(float(s))


def human_duration(seconds: Optional[int]) -> str:
    if seconds is None:
        return "-"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    m, s = divmod(s, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h{m:02d}m"
    d, h = divmod(h, 24)
    return f"{d}d{h:02d}h"
