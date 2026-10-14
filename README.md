# agent-hygiene

A small local CLI for macOS and Linux that shows what coding-agent CLIs (Codex, Claude Code,
Cursor Agent, Gemini CLI, Copilot CLI, OpenCode, Devin, Aider) leave behind on your machine,
and cleans it up safely.

Agent CLIs can leave auto-starting background processes, self-updaters, and gigabytes of old
version folders, and some keep running after you quit. `agent-hygiene` is **read-only by
default**, and **every change it makes is reversible**.

Think of it as Task Manager + the Startup tab + "Programs and Features", scoped to agents.

```
$ agent-hygiene scan

Agents
======
agent   present  disk    versions  stale  self-update  install
------  -------  ------  --------  -----  -----------  -------
claude  yes      221 MB  1         0      on           ~/.local/bin/claude
cursor  yes      6.8 GB  16        15     n/a          -
gemini  yes      18 MB   0         0      on           -

Processes
=========
agent   pid    ppid  tty  uptime  rss             command                                   parent
------  -----  ----  ---  ------  -----  --------  ----------------------------------------  -------------
cursor  34836  1     ??   1h24m   30 MB  LEFTOVER  …/cursor-agent --api-key ***              /sbin/launchd

total agent disk use: 6.8 GB   stale versions: 6.0 GB   auto-start entries: 0   leftover processes: 1
```

## Install

Requires Python 3.9+ (preinstalled on macOS with the Command Line Tools and on most Linux
distributions). No third-party dependencies.

```sh
pip install agent-hygiene          # or: pipx install agent-hygiene
# or run straight from a checkout:
python3 -m agent_hygiene scan
```

## Commands

### `scan` — the inventory (read-only)

Finds every agent's footprint:

- folders such as `~/.codex`, `~/.claude`, `~/.cursor`, `~/.gemini`, data dirs under
  `~/.local/share`, and global installs from npm, pnpm, bun, volta, nvm, fnm, pipx and uv;
- auto-start entries: macOS LaunchAgents, systemd user units and timers, user crontab lines;
- running processes with their parent process, flagged `LEFTOVER` when the session that
  started them has ended, plus their open sockets (`lsof` / `ss`);
- disk use for each agent and each installed version, with old versions marked `stale`.

```sh
agent-hygiene scan                 # table
agent-hygiene scan --json          # machine-readable
agent-hygiene scan --agent cursor  # one agent
```

Command lines are printed with API keys and tokens redacted.

### `clean` — the fixes (preview, then confirm)

`clean` always prints a preview first and asks for confirmation. With no flags it does every
*reversible* fix; pass flags to pick:

| flag | what it does | undo |
| --- | --- | --- |
| `--autostart` | unloads LaunchAgents / disables systemd user units / comments out cron lines | plist and crontab are backed up; `restore` puts them back and re-enables |
| `--self-update` | turns off the agent's self-updater setting (e.g. `DISABLE_AUTOUPDATER` for Claude Code, `general.disableAutoUpdate` for Gemini) | the settings file is backed up byte-for-byte |
| `--prune [--keep N]` | moves old version folders to a trash dir, keeping the newest N (default 2) and never the version in use | `restore` renames them back |
| `--kill` | terminates leftover processes whose session already ended | **not reversible**, so it is never on by default |

```sh
agent-hygiene clean                     # preview everything reversible, then confirm
agent-hygiene clean --prune --keep 1    # only prune, keep the newest one
agent-hygiene clean --dry-run           # preview only
agent-hygiene clean --yes               # no prompt (scripts)
```

Pruned versions are *renamed* into `~/.agent-hygiene/backups/<id>/trash/`, which is instant
and keeps them on disk so `restore` is exact. Disk space is reclaimed when you decide:

```sh
agent-hygiene purge                     # delete trashed versions from all pending backups
agent-hygiene purge --older-than 7      # only trash older than a week
```

### `restore` — undo

```sh
agent-hygiene restore --list            # show backups
agent-hygiene restore                   # undo the most recent clean
agent-hygiene restore 20261013-221500   # undo a specific one
```

Actions are reversed in reverse order. After `clean` + `restore`, the file tree is identical
(the test suite asserts this with a content hash of the whole home directory).

### `run -- <agent>` — the wrapper

Launches the agent in its own process group (and, on Linux with systemd, a transient
`systemd-run --user --scope` cgroup). When the agent exits:

1. everything it started is sent SIGTERM, then SIGKILL after a grace period — including
   children that detached into their own session, as long as they still look like the agent;
2. files it created or modified outside its own folders are listed;
3. a JSON report is written to `~/.agent-hygiene/runs/`.

```sh
agent-hygiene run -- claude
agent-hygiene run -- codex --model o3
agent-hygiene run --watch . --grace 5 -- cursor-agent
```

The agent keeps the terminal (interactive TUIs work; Ctrl-C goes to the agent, not the
wrapper) and its exit code is passed through.

### `policy` — team rules

An optional JSON file lets a team enforce the same rules in CI or onboarding scripts.
`policy check` exits 1 when anything violates it.

```sh
agent-hygiene policy init               # writes agent-hygiene.policy.json
agent-hygiene policy check              # finds ./agent-hygiene.policy.json, ~/.config/agent-hygiene/policy.json, or $AGENT_HYGIENE_POLICY
agent-hygiene clean --policy team.json  # prune with the policy's keep_versions
```

```json
{
  "keep_versions": 2,
  "max_disk_per_agent": "5GB",
  "max_disk_total": "20GB",
  "allowed_autostarts": ["com.example.allowed.*"],
  "allow_self_update": false,
  "allow_leftover_processes": false,
  "agents": { "codex": { "keep_versions": 1, "max_disk": "2GB" } }
}
```

## Privacy and security

- **Nothing leaves your machine.** No network calls, telemetry, analytics or update checks;
  a test fails the build if a networking module is ever imported.
- **Only your own processes.** `scan` reads processes owned by the current user, never other
  accounts on the machine.
- **Secrets are redacted** from every command line it prints or logs: API-key and token flags,
  `*_KEY=`/`*_TOKEN=` variables, `Bearer` headers, `user:password@` URLs, and known key formats
  (OpenAI, Anthropic, Cursor, GitHub, GitLab, Slack, Google, AWS, npm, PyPI, JWTs).
- **Private state.** `~/.agent-hygiene` (backups and run logs) is created owner-only (`0700`),
  because a settings backup can contain the same API keys as the original file.
- **Tamper-resistant undo.** `restore` only moves files that live inside the backup folder,
  `purge` refuses a trash folder that has been replaced by a symlink, and files are written
  through fresh temp files rather than predictable names.
- **Careful with processes.** `--kill` re-checks that a pid still runs the same command before
  signalling it, and `run` matches tracked children by pid *and* command, so a reused pid is
  never killed.
- **No surprises from cloned repos.** `clean` ignores policy files in the current directory;
  pass `--policy FILE` or use `~/.config/agent-hygiene/policy.json`.
- **Not as root.** `clean`, `restore`, `purge` and `run` refuse to run under `sudo`.
- Zero third-party dependencies, and no `shell=True` anywhere.

Report a vulnerability privately through GitHub's "Report a vulnerability" button on the
repository's Security tab.

## What it will not do

- No hosted sandbox; `run` is a local process supervisor, not an isolation boundary.
- No security claims. A process that really wants to hide can.
- No Windows in version 1.
- It never touches system-wide LaunchAgents or units that need `sudo`; it reports them and skips.

## Adding an agent

Every agent is one `AgentSpec` entry in `agent_hygiene/agents.py`: home and data dirs,
package names, version-folder roots, the symlink that marks the current version, regexes for
process and auto-start matching, and (if the agent has one) the settings key that disables
self-update.

## Development

```sh
python3 -m unittest discover -s tests -t .
```

Tests run against a fake `$HOME` and never touch your real agent installs. The `run` tests
spawn real background processes to prove that nothing survives the wrapper.

## License

GPL-3.0. See [LICENSE](LICENSE).
