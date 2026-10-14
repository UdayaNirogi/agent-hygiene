"""Registry of known coding-agent CLIs and where each one leaves its footprint.

Everything the scanner knows about a specific agent lives here, so adding an agent
means adding one AgentSpec. Paths are relative to $HOME unless absolute and may
contain glob characters.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class SelfUpdateSpec:
    """A JSON settings file plus the nested key that turns self-update off."""

    path: str
    key: Tuple[str, ...]
    disabled_value: object
    note: str = ""


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
    self_update: Optional[SelfUpdateSpec] = None
    self_update_note: str = ""

    def process_regex(self) -> List["re.Pattern[str]"]:
        return [re.compile(p) for p in self.process_patterns]

    def autostart_regex(self) -> List["re.Pattern[str]"]:
        return [re.compile(p, re.IGNORECASE) for p in self.autostart_patterns]

    def matches_process(self, command: str) -> bool:
        return any(r.search(command) for r in self.process_regex())

    def matches_autostart(self, text: str) -> bool:
        return any(r.search(text) for r in self.autostart_regex())


_CURSOR_IDE_MAC = "~/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-agent-worker"
_CURSOR_IDE_LINUX = "~/.config/Cursor/User/globalStorage/anysphere.cursor-agent-worker"

AGENTS: List[AgentSpec] = [
    AgentSpec(
        name="codex",
        display="OpenAI Codex CLI",
        home_dirs=("~/.codex",),
        npm_packages=("@openai/codex",),
        binaries=("codex",),
        process_patterns=(r"(^|/)codex(\s|$)", r"@openai/codex", r"codex-(x86_64|aarch64)-"),
        autostart_patterns=(r"openai", r"\bcodex\b"),
        self_update_note="Codex CLI has no background self-updater; it only prints an "
        "update notice. Update with `npm i -g @openai/codex`.",
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
        self_update=SelfUpdateSpec(
            path="~/.claude/settings.json",
            key=("env", "DISABLE_AUTOUPDATER"),
            disabled_value="1",
            note="Sets env.DISABLE_AUTOUPDATER=\"1\" in ~/.claude/settings.json.",
        ),
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
        self_update=SelfUpdateSpec(
            path="~/.gemini/settings.json",
            key=("general", "disableAutoUpdate"),
            disabled_value=True,
            note="Sets general.disableAutoUpdate=true in ~/.gemini/settings.json.",
        ),
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
        self_update=SelfUpdateSpec(
            path="~/.config/opencode/opencode.json",
            key=("autoupdate",),
            disabled_value=False,
            note="Sets autoupdate=false in ~/.config/opencode/opencode.json.",
        ),
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
