"""Registry of known coding-agent CLIs and where each one leaves its footprint.

Everything the scanner knows about a specific agent lives here, so adding an agent
means adding one AgentSpec. Paths are relative to $HOME unless absolute and may
contain glob characters.
"""
from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .platform import expand


@dataclass(frozen=True)
class SettingSpec:
    """A settings file plus the nested key that switches a self-updater or auto-start off."""

    path: str
    key: Tuple[str, ...]
    disabled_value: object
    kind: str = "self-update"  # self-update | auto-start
    fmt: str = "json"  # json | toml
    # only touch this setting when this path exists (e.g. the feature has been used)
    requires: str = ""
    note: str = ""


@dataclass(frozen=True)
class DaemonSpec:
    """A background server the agent leaves running, plus its separate updater process."""

    server_pattern: str
    updater_pattern: str
    stop_args: Tuple[str, ...]
    start_args: Tuple[str, ...]


@dataclass(frozen=True)
class AgentSpec:
    name: str
    display: str
    home_dirs: Tuple[str, ...] = ()
    data_dirs: Tuple[str, ...] = ()
    npm_packages: Tuple[str, ...] = ()
    pip_packages: Tuple[str, ...] = ()
    binaries: Tuple[str, ...] = ()
    versions_roots: Tuple[str, ...] = ()
    current_links: Tuple[str, ...] = ()
    process_patterns: Tuple[str, ...] = ()
    autostart_patterns: Tuple[str, ...] = ()
    settings: Tuple[SettingSpec, ...] = ()
    self_update_note: str = ""
    daemon: Optional[DaemonSpec] = None

    def process_regex(self) -> List["re.Pattern[str]"]:
        return [re.compile(p) for p in self.process_patterns]

    def autostart_regex(self) -> List["re.Pattern[str]"]:
        return [re.compile(p, re.IGNORECASE) for p in self.autostart_patterns]

    def matches_process(self, command: str) -> bool:
        return any(r.search(command) for r in self.process_regex())

    def matches_autostart(self, text: str) -> bool:
        return any(r.search(text) for r in self.autostart_regex())

    def setting(self, path: str, key: Tuple[str, ...]) -> Optional[SettingSpec]:
        for s in self.settings:
            if tuple(s.key) == tuple(key) and os.path.realpath(expand(s.path)) == os.path.realpath(path):
                return s
        return None

    def own_folders(self) -> List[str]:
        """The agent's own directories (literal and symlink-resolved forms)."""
        out: List[str] = []
        for pat in self.home_dirs + self.data_dirs + self.versions_roots:
            expanded = str(expand(pat))
            paths = glob.glob(expanded) if any(ch in expanded for ch in "*?[") else [expanded]
            for p in paths:
                if os.path.isdir(p):
                    for form in (os.path.abspath(p), os.path.realpath(p)):
                        if form not in out:
                            out.append(form)
        return out


_CURSOR_IDE_MAC = "~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-agent-worker"
_CURSOR_IDE_LINUX = "~/.config/Cursor/User/globalStorage/anysphere.cursor-agent-worker"

AGENTS: List[AgentSpec] = [
    AgentSpec(
        name="codex",
        display="OpenAI Codex CLI",
        home_dirs=("~/.codex",),
        npm_packages=("@openai/codex",),
        binaries=("codex",),
        # the standalone installer and the app-server daemon keep every release behind a `current` link
        versions_roots=("~/.codex/packages/standalone/releases", "~/.codex/packages/app-server-daemon/releases"),
        current_links=("~/.codex/packages/standalone/current", "~/.codex/packages/app-server-daemon/current",
                       "~/.local/bin/codex"),
        process_patterns=(r"(^|/)codex(\s|$)", r"@openai/codex", r"codex-(x86_64|aarch64)-"),
        autostart_patterns=(r"openai", r"\bcodex\b"),
        settings=(
            SettingSpec(
                path="~/.codex/config.toml", key=("features", "daemon_auto_start"), disabled_value=False,
                kind="auto-start", fmt="toml",
                note="Sets [features] daemon_auto_start = false in ~/.codex/config.toml.",
            ),
            SettingSpec(
                path="~/.codex/app-server-daemon/settings.json", key=("updater", "autoUpdateEnabled"),
                disabled_value=False, requires="~/.codex/app-server-daemon",
                note="Sets updater.autoUpdateEnabled=false in ~/.codex/app-server-daemon/settings.json.",
            ),
        ),
        daemon=DaemonSpec(
            server_pattern=r"(^|/)codex\S*\s+app-server(\s|$)",
            updater_pattern=r"\bapp-server\s+daemon\s+pid-update-loop\b",
            stop_args=("app-server", "daemon", "stop"),
            start_args=("app-server", "daemon", "start"),
        ),
    ),
    AgentSpec(
        name="claude",
        display="Anthropic Claude Code",
        home_dirs=("~/.claude", "~/.claude.json", "~/.claude.json.backup"),
        data_dirs=("~/.local/share/claude", "~/.cache/claude", "~/Library/Caches/claude-cli-nodejs"),
        npm_packages=("@anthropic-ai/claude-code",),
        binaries=("claude",),
        versions_roots=("~/.local/share/claude/versions",),
        current_links=("~/.local/bin/claude", "~/.claude/local/claude"),
        process_patterns=(
            r"(^|/)claude(\s|$)",
            r"/\.local/share/claude/versions/",
            r"@anthropic-ai/claude-code",
        ),
        autostart_patterns=(r"anthropic", r"\bclaude\b"),
        settings=(SettingSpec(
            path="~/.claude/settings.json",
            key=("env", "DISABLE_AUTOUPDATER"),
            disabled_value="1",
            note="Sets env.DISABLE_AUTOUPDATER=\"1\" in ~/.claude/settings.json.",
        ),),
    ),
    AgentSpec(
        name="cursor",
        display="Cursor Agent CLI",
        home_dirs=("~/.cursor",),
        data_dirs=(
            "~/.local/share/cursor-agent",
            "~/.cache/cursor-agent",
            # the Cursor IDE ships its own copy of the agent CLI and keeps every version
            _CURSOR_IDE_MAC + "/agent-cli",
            _CURSOR_IDE_LINUX + "/agent-cli",
        ),
        binaries=("cursor-agent", "agent"),
        versions_roots=(
            "~/.local/share/cursor-agent/versions",
            _CURSOR_IDE_MAC + "/agent-cli/.local/share/cursor-agent/versions",
            _CURSOR_IDE_LINUX + "/agent-cli/.local/share/cursor-agent/versions",
        ),
        current_links=(
            "~/.local/bin/cursor-agent",
            "~/.local/bin/agent",
            _CURSOR_IDE_MAC + "/agent-cli/.local/bin/cursor-agent",
            _CURSOR_IDE_LINUX + "/agent-cli/.local/bin/cursor-agent",
        ),
        process_patterns=(r"cursor[-_]agent", r"/\.local/share/cursor-agent/"),
        autostart_patterns=(r"cursor[-_.]agent", r"anysphere.*agent"),
        self_update_note="Cursor Agent CLI versions are managed by `cursor-agent update`; "
        "there is no documented setting to disable the updater.",
    ),
    AgentSpec(
        name="gemini",
        display="Google Gemini CLI",
        home_dirs=("~/.gemini",),
        npm_packages=("@google/gemini-cli",),
        binaries=("gemini",),
        process_patterns=(r"(^|/)gemini(\s|$)", r"@google/gemini-cli"),
        autostart_patterns=(r"gemini[-_.]cli", r"\bgemini\b"),
        settings=(SettingSpec(
            path="~/.gemini/settings.json",
            key=("general", "disableAutoUpdate"),
            disabled_value=True,
            note="Sets general.disableAutoUpdate=true in ~/.gemini/settings.json.",
        ),),
    ),
    AgentSpec(
        name="copilot",
        display="GitHub Copilot CLI",
        home_dirs=("~/.copilot",),
        npm_packages=("@github/copilot",),
        binaries=("copilot",),
        process_patterns=(r"(^|/)copilot(\s|$)", r"@github/copilot"),
        autostart_patterns=(r"github[-_.]copilot", r"\bcopilot\b"),
        self_update_note="No documented setting; update with `npm i -g @github/copilot`.",
    ),
    AgentSpec(
        name="opencode",
        display="OpenCode",
        home_dirs=("~/.config/opencode",),
        data_dirs=("~/.local/share/opencode", "~/.cache/opencode", "~/.opencode"),
        npm_packages=("opencode-ai",),
        binaries=("opencode",),
        process_patterns=(r"(^|/)opencode(\s|$)",),
        autostart_patterns=(r"\bopencode\b",),
        settings=(SettingSpec(
            path="~/.config/opencode/opencode.json",
            key=("autoupdate",),
            disabled_value=False,
            note="Sets autoupdate=false in ~/.config/opencode/opencode.json.",
        ),),
    ),
    AgentSpec(
        name="devin",
        display="Devin CLI",
        data_dirs=("~/.local/share/devin", "~/.config/devin"),
        binaries=("devin",),
        process_patterns=(r"(^|/)devin(\s|$)", r"/\.local/share/devin/"),
        autostart_patterns=(r"\bdevin\b", r"cognition"),
        self_update_note="No documented setting to disable updates.",
    ),
    AgentSpec(
        name="aider",
        display="Aider",
        home_dirs=("~/.aider", "~/.aider.conf.yml", "~/.aider.model.settings.yml"),
        data_dirs=("~/.local/pipx/venvs/aider-chat", "~/.local/share/uv/tools/aider-chat"),
        pip_packages=("aider-chat",),
        binaries=("aider",),
        process_patterns=(r"(^|/)aider(\s|$)",),
        autostart_patterns=(r"\baider\b",),
        self_update_note="Aider checks for updates at start; disable with --no-check-update "
        "in ~/.aider.conf.yml (check-update: false).",
    ),
]

# Anything matching these is never attributed to an agent, even if an agent pattern hits.
EXCLUDE_PROCESS_PATTERNS = [
    re.compile(r"agent[-_]hygiene"),
    re.compile(r"(^|/)(rg|grep|egrep|ps|lsof|less|more|tail|cat|vim|nano|code)\s"),
]


def by_name(name: str) -> Optional[AgentSpec]:
    for spec in AGENTS:
        if spec.name == name:
            return spec
    return None


def names() -> List[str]:
    return [a.name for a in AGENTS]


def match_process(command: str) -> Optional[str]:
    if any(p.search(command) for p in EXCLUDE_PROCESS_PATTERNS):
        return None
    for spec in AGENTS:
        if spec.matches_process(command):
            return spec.name
    return None


def daemon_role(agent: Optional[str], command: str) -> str:
    """'updater' or 'daemon' when the command is that agent's background server, else ''."""
    spec = by_name(agent) if agent else None
    if spec is None or spec.daemon is None:
        return ""
    if re.search(spec.daemon.updater_pattern, command):
        return "updater"
    if re.search(spec.daemon.server_pattern, command):
        return "daemon"
    return ""


def match_autostart(text: str) -> Optional[str]:
    for spec in AGENTS:
        if spec.matches_autostart(text):
            return spec.name
    return None


def guess_from_argv0(argv0: str) -> Optional[str]:
    """Map the executable passed to `run -- <agent>` to a registered agent."""
    base = argv0.rsplit("/", 1)[-1]
    for spec in AGENTS:
        if base in spec.binaries:
            return spec.name
    return match_process(argv0 + " ")
