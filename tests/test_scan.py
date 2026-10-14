import os
import plistlib
import subprocess
import sys
import time
import unittest
from unittest import mock

from agent_hygiene import agents
from agent_hygiene.model import ProcessInfo
from agent_hygiene.scan import autostart, footprint, processes
from tests.helpers import FakeHomeTestCase


class TestAgentMatching(unittest.TestCase):
    def test_process_patterns(self):
        self.assertEqual(agents.match_process("/Users/me/.local/bin/claude --resume"), "claude")
        self.assertEqual(agents.match_process("node /usr/local/lib/node_modules/@openai/codex/bin/codex.js"), "codex")
        self.assertEqual(agents.match_process("/x/.local/share/cursor-agent/versions/1.0/index.js"), "cursor")
        self.assertEqual(agents.match_process("gemini -p hi"), "gemini")

    def test_not_false_positives(self):
        # The Cursor IDE itself is not the agent CLI, and neither are our own processes.
        self.assertIsNone(agents.match_process("/Applications/Cursor.app/Contents/MacOS/Cursor"))
        self.assertIsNone(agents.match_process("python3 -m agent_hygiene run -- claude"))
        self.assertIsNone(agents.match_process("rg -i claude"))
        self.assertIsNone(agents.match_process("/Applications/Claude.app/Contents/MacOS/Claude"))
        self.assertIsNone(agents.match_process("vim claude-notes.md"))

    def test_self_exclusion_is_by_program_name_only(self):
        # our own processes, however they were started
        for cmd in ("agent-hygiene scan", "/x/.venv/bin/agent-hygiene clean --kill",
                    "python3 -m agent_hygiene run -- claude", "/usr/bin/python3.12 -u -m agent_hygiene.cli scan",
                    "/x/.venv/bin/python3 /x/.venv/bin/agent-hygiene clean"):
            with self.subTest(cmd):
                self.assertTrue(agents.is_self(cmd))
                self.assertIsNone(agents.match_process(cmd))
        # a checkout or venv in a folder named agent-hygiene must not hide real agents
        for cmd, want in (("/home/me/agent-hygiene/.local/bin/claude serve", "claude"),
                          ("/opt/venvs/agent-hygiene/bin/python3 /h/.codex/bin/codex app-server", "codex"),
                          ("node /Users/me/agent-hygiene/node_modules/@openai/codex/bin/codex.js", "codex"),
                          ("gemini -p 'tidy agent-hygiene'", "gemini")):
            with self.subTest(cmd):
                self.assertFalse(agents.is_self(cmd))
                self.assertEqual(agents.match_process(cmd), want)

    def test_guess_from_argv0(self):
        self.assertEqual(agents.guess_from_argv0("claude"), "claude")
        self.assertEqual(agents.guess_from_argv0("/opt/homebrew/bin/codex"), "codex")
        self.assertEqual(agents.guess_from_argv0("cursor-agent"), "cursor")
        self.assertIsNone(agents.guess_from_argv0("bash"))


class TestProcesses(unittest.TestCase):
    def test_parse_etime(self):
        self.assertEqual(processes.parse_etime("05"), 5)
        self.assertEqual(processes.parse_etime("01:05"), 65)
        self.assertEqual(processes.parse_etime("02:01:05"), 7265)
        self.assertEqual(processes.parse_etime("3-02:01:05"), 3 * 86400 + 7265)

    def test_parse_ps_and_redact(self):
        out = (
            "  100     1   100   501 S    ??       01:00  3000 /x/.local/bin/claude --api-key sk-abcdefghijklmnop serve\n"
            "  101   100   100   501 S    ??       00:30  1000 node child.js TOKEN=verysecretvalue\n"
            "  200   999   200     0 Ss+  ttys001  00:10   500 /bin/zsh\n"
        )
        procs = processes.parse_ps(out)
        self.assertEqual([p.pid for p in procs], [100, 101, 200])
        self.assertEqual([p.uid for p in procs], [501, 501, 0])
        self.assertIn("--api-key ***", procs[0].command)
        self.assertNotIn("sk-abcdefghijklmnop", procs[0].command)
        self.assertIn("TOKEN=***", procs[1].command)
        self.assertEqual(procs[0].etime_s, 60)

    def test_list_processes_only_returns_current_user(self):
        me = os.getuid()
        out = (f"  10  1 10 {me} S ?? 00:01 1 /x/claude\n"
               f"  11  1 11 {me + 1} S ?? 00:01 1 /x/claude --other-user\n"
               f"  12  1 12 {me} Z ?? 00:01 0 <defunct>\n")
        fake = subprocess.CompletedProcess([], 0, out, "")
        with mock.patch.object(processes, "run", return_value=fake):
            self.assertEqual([p.pid for p in processes.list_processes()], [10])

    def test_redact_known_token_shapes(self):
        fake = {
            "cursor": "crsr_" + "0" * 40,
            "openai": "sk-proj-" + "A" * 30,
            "anthropic": "sk-ant-api03-" + "B" * 30,
            "github": "ghp_" + "C" * 36,
            "github_pat": "github_pat_" + "D" * 40,
            "slack": "xoxb-" + "1" * 20,
            "google": "AIza" + "E" * 35,
            "aws": "AKIA" + "F" * 16,
            "jwt": "eyJ" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20,
            "pypi": "pypi-" + "G" * 40,
            "npm": "npm_" + "H" * 36,
        }
        for name, secret in fake.items():
            with self.subTest(name):
                self.assertEqual(processes.redact(f"x {secret} y"), "x *** y")

    def test_redact_flags_headers_urls(self):
        cases = {
            "tool --api-key=abc123 run": "tool --api-key=*** run",
            "tool --openai-api-key abc123": "tool --openai-api-key ***",
            "tool --password hunter2": "tool --password ***",
            "curl -H Authorization: Bearer abcdefghijkl": "curl -H Authorization: Bearer ***",
            "git clone https://user:s3cret@example.com/repo": "git clone https://***:***@example.com/repo",
            "env ANTHROPIC_API_KEY=abc OTHER=1 claude": "env ANTHROPIC_API_KEY=*** OTHER=1 claude",
        }
        for raw, want in cases.items():
            with self.subTest(raw):
                self.assertEqual(processes.redact(raw), want)

    def test_redact_leaves_ordinary_commands_alone(self):
        for cmd in ("plain command --flag value", "agent-hygiene clean --keep 2",
                    "/x/.local/share/claude/versions/2.1.201", "node index.js --use-system-ca"):
            with self.subTest(cmd):
                self.assertEqual(processes.redact(cmd), cmd)

    def test_autostart_program_is_redacted(self):
        crontab = "0 * * * * /usr/local/bin/codex --api-key sk-abcdefghijklmnop update\n"
        with mock.patch.object(autostart, "read_crontab", return_value=crontab):
            entries = autostart.scan_cron([])
        self.assertNotIn("sk-abcdefghijklmnop", entries[0].program)

    def test_annotate_orphans_and_children(self):
        procs = [
            ProcessInfo(1, 0, 1, "??", 0, 0, "/sbin/launchd"),
            ProcessInfo(50, 1, 50, "ttys000", 0, 0, "/bin/zsh"),
            ProcessInfo(60, 50, 60, "ttys000", 0, 0, "claude"),               # live session
            ProcessInfo(70, 1, 70, "??", 0, 0, "/x/.local/bin/claude serve"),  # orphaned
            ProcessInfo(71, 70, 70, "??", 0, 0, "node helper.js @anthropic-ai/claude-code"),  # child of orphan
            ProcessInfo(80, 1, 80, "??", 0, 0, "/usr/libexec/other"),
            ProcessInfo(90, 50, 90, "ttys000", 0, 0, "python3 -m agent_hygiene scan"),
        ]
        matched = processes.annotate(procs, self_pid=90)
        by_pid = {p.pid: p for p in matched}
        self.assertEqual(set(by_pid), {60, 70, 71})
        self.assertFalse(by_pid[60].orphaned)
        self.assertTrue(by_pid[70].orphaned)
        self.assertTrue(by_pid[71].orphaned)
        self.assertEqual(by_pid[60].parent_command, "/bin/zsh")

    def test_desktop_subreaper_children_are_leftovers(self):
        # On a Linux desktop an ended session's processes go to `systemd --user`, not pid 1.
        procs = [
            ProcessInfo(1, 0, 1, "?", 0, 0, "/sbin/init splash"),
            ProcessInfo(900, 1, 900, "?", 0, 0, "/usr/lib/systemd/systemd --user"),
            ProcessInfo(901, 900, 901, "?", 0, 0, "/home/me/.local/bin/claude serve"),
            ProcessInfo(902, 900, 902, "?", 0, 0, "/usr/bin/gnome-terminal-server"),
            ProcessInfo(903, 902, 903, "pts/0", 0, 0, "bash"),
            ProcessInfo(904, 903, 904, "pts/0", 0, 0, "claude"),
            ProcessInfo(905, 1, 905, "??", 0, 0, "/Users/me/.local/bin/claude serve"),
        ]
        by_pid = {p.pid: p for p in processes.annotate(procs, self_pid=1)}
        self.assertTrue(by_pid[901].orphaned)
        self.assertFalse(by_pid[904].orphaned)  # live terminal session
        self.assertTrue(by_pid[905].orphaned)

    def test_codex_daemon_roles(self):
        bin_ = "/h/.codex/packages/app-server-daemon/current/bin/codex"
        self.assertEqual(agents.daemon_role("codex", f"{bin_} app-server --listen unix:///x"), "daemon")
        self.assertEqual(agents.daemon_role("codex", f"{bin_} app-server daemon pid-update-loop"), "updater")
        self.assertEqual(agents.daemon_role("codex", f"{bin_} exec hi"), "")
        self.assertEqual(agents.daemon_role("claude", "claude app-server"), "")

    def test_runs_from_needs_the_program_inside_the_folders(self):
        folders = ["/h/.codex"]
        inside = ProcessInfo(10, 1, 10, "??", 0, 0, "codex app-server", exe="/h/.codex/packages/x/bin/codex")
        named_only = ProcessInfo(11, 1, 11, "??", 0, 0, "codex app-server", exe="/home/me/bin/codex")
        spoofed = ProcessInfo(12, 1, 12, "??", 0, 0, "/h/.codex/bin/codex serve", exe="/opt/other/codex")
        script = ProcessInfo(13, 1, 13, "??", 0, 0, "node --no-warnings /h/.codex/app/index.js", exe="/usr/bin/node")
        tail = ProcessInfo(14, 1, 14, "??", 0, 0, "sh -c tail -f /h/.codex/log.txt", exe="/bin/sh")
        self.assertTrue(processes.runs_from(inside, folders))
        self.assertFalse(processes.runs_from(named_only, folders))
        self.assertFalse(processes.runs_from(spoofed, folders))  # argv cannot fake the program path
        self.assertTrue(processes.runs_from(script, folders))
        self.assertFalse(processes.runs_from(tail, folders))
        self.assertFalse(processes.runs_from(inside, []))

    def test_running_from(self):
        procs = [ProcessInfo(1, 0, 1, "", 0, 0, "x", exe="/v/2.0/claude"),
                 ProcessInfo(2, 0, 2, "", 0, 0, "node /v/1.0/cli.js", exe="/usr/bin/node"),
                 ProcessInfo(3, 0, 3, "", 0, 0, "node /v/1.0.1/cli.js", exe="/usr/bin/node")]
        self.assertEqual([p.pid for p in processes.running_from(procs, "/v/2.0", resolve=False)], [1])
        self.assertEqual([p.pid for p in processes.running_from(procs, "/v/1.0", resolve=False)], [2])

    def test_exe_path_of_self(self):
        exe = processes.exe_path(os.getpid())
        self.assertIsNotNone(exe)
        self.assertTrue(os.path.samefile(exe, os.path.realpath(sys.executable)) or "python" in exe.lower())

    def test_parse_lsof(self):
        out = (
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
            "node 100 me 20u IPv4 0x1 0t0 TCP 127.0.0.1:4096 (LISTEN)\n"
            "node 100 me 21u IPv4 0x2 0t0 TCP 10.0.0.5:5000->1.2.3.4:443 (ESTABLISHED)\n"
            "node 100 me 22u IPv4 0x3 0t0 UDP *:5353\n"
        )
        ports = processes.parse_lsof(out, {100: "claude"})
        self.assertEqual(len(ports), 3)
        self.assertEqual((ports[0].local, ports[0].state), ("127.0.0.1:4096", "LISTEN"))
        self.assertEqual((ports[1].remote, ports[1].state), ("1.2.3.4:443", "ESTABLISHED"))
        self.assertEqual(ports[2].state, "UDP")

    def test_descendants(self):
        procs = [ProcessInfo(1, 0, 1, "", 0, 0, ""), ProcessInfo(2, 1, 2, "", 0, 0, ""),
                 ProcessInfo(3, 2, 2, "", 0, 0, ""), ProcessInfo(4, 3, 2, "", 0, 0, ""),
                 ProcessInfo(5, 1, 5, "", 0, 0, "")]
        self.assertEqual(sorted(p.pid for p in processes.descendants(procs, 2)), [3, 4])


class TestFootprint(FakeHomeTestCase):
    def _claude_spec(self):
        return agents.by_name("claude")

    def test_versions_sorted_current_marked_and_prunable(self):
        root = self.home / ".local/share/claude/versions"
        for v, size in (("2.1.201", 30), ("2.1.99", 20), ("2.0.5", 10), ("1.9.0", 10)):
            self.write(f".local/share/claude/versions/{v}", size=size)
        (self.home / ".local/share/claude/versions/.tmp-junk").mkdir()
        (self.home / ".local/bin").mkdir(parents=True)
        # the user pinned an older version as current
        os.symlink(root / "2.1.99", self.home / ".local/bin/claude")

        roots, versions = footprint.find_versions(self._claude_spec())
        self.assertEqual(roots, [str(root)])
        self.assertEqual([v.version for v in versions], ["2.1.201", "2.1.99", "2.0.5", "1.9.0"])
        self.assertEqual([v.is_current for v in versions], [False, True, False, False])
        self.assertFalse(versions[0].is_dir)

        prunable = footprint.select_prunable(versions, keep=1)
        self.assertEqual([v.version for v in prunable], ["2.0.5", "1.9.0"])  # current survives keep=1
        self.assertEqual([v.version for v in footprint.select_prunable(versions, keep=2)], ["2.0.5", "1.9.0"])
        self.assertEqual([v.version for v in footprint.select_prunable(versions, keep=3)], ["1.9.0"])

    def test_running_version_is_never_prunable(self):
        for v in ("3.0", "2.0", "1.0"):
            self.write(f".local/share/claude/versions/{v}/claude",
                       f"#!{sys.executable}\nimport time\ntime.sleep(60)\n")
            os.chmod(self.home / f".local/share/claude/versions/{v}/claude", 0o755)
        old = self.home / ".local/share/claude/versions/1.0/claude"
        proc = subprocess.Popen([str(old)])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        time.sleep(0.3)
        _, versions = footprint.find_versions(self._claude_spec())
        footprint.mark_in_use(versions, processes.list_processes())
        by_version = {v.version: v for v in versions}
        self.assertIn(proc.pid, by_version["1.0"].in_use_by)
        self.assertEqual(by_version["2.0"].in_use_by, [])
        self.assertEqual(footprint.select_prunable(versions, keep=1), [by_version["2.0"]])
        # ...unless the process using it is about to be stopped
        self.assertEqual(len(footprint.select_prunable(versions, keep=1, ignore_pids={proc.pid})), 2)

    def test_codex_release_layout(self):
        rel = self.home / ".codex/packages/standalone/releases"
        for v in ("0.162.1-aarch64-apple-darwin", "0.161.0-aarch64-apple-darwin", "0.157.0-aarch64-apple-darwin"):
            self.write(f".codex/packages/standalone/releases/{v}/bin/codex", size=64)
        os.symlink(rel / "0.161.0-aarch64-apple-darwin", self.home / ".codex/packages/standalone/current")
        roots, versions = footprint.find_versions(agents.by_name("codex"))
        self.assertEqual(roots, [str(rel)])
        self.assertEqual([v.version.split("-")[0] for v in versions], ["0.162.1", "0.161.0", "0.157.0"])
        self.assertEqual([v.is_current for v in versions], [False, True, False])
        self.assertEqual([v.version.split("-")[0] for v in footprint.select_prunable(versions, keep=1)], ["0.157.0"])

    def test_codex_settings_state(self):
        self.write(".codex/config.toml", 'model = "o3"\n\n[features]\ndaemon_auto_start = false\n')
        fp = footprint.scan_agent(agents.by_name("codex"), npm_roots=[])
        by_key = {s.key: s for s in fp.settings}
        self.assertTrue(by_key["features.daemon_auto_start"].disabled)
        self.assertFalse(by_key["updater.autoUpdateEnabled"].applicable)  # daemon never ran
        self.assertEqual(fp.settings_on(), [])

    def test_version_key_handles_date_builds(self):
        k1 = footprint._version_key("2026.10.12-d47ca18", 0)
        k2 = footprint._version_key("2026.09.26-dd393fe", 0)
        self.assertGreater(k1, k2)

    def test_scan_agent_totals_and_self_update(self):
        self.write(".claude/settings.json", '{"env": {"DISABLE_AUTOUPDATER": "1"}}')
        self.write(".local/share/claude/versions/2.1.201", size=4096)
        fp = footprint.scan_agent(self._claude_spec(), npm_roots=[])
        self.assertTrue(fp.installed)
        self.assertTrue(fp.settings[0].disabled)
        self.assertEqual(fp.settings_on(), [])
        self.assertGreater(fp.total_bytes, 4096)
        self.assertEqual(len(fp.versions), 1)

    def test_npm_roots_found_without_running_npm(self):
        # a Homebrew-style layout: bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js
        prefix = self.home / "prefix"
        (prefix / "lib/node_modules/npm/bin").mkdir(parents=True)
        (prefix / "lib/node_modules/npm/bin/npm-cli.js").write_text("#!/usr/bin/env node\n")
        (prefix / "lib/node_modules/npm/bin/npm-cli.js").chmod(0o755)
        (prefix / "bin").mkdir()
        os.symlink("../lib/node_modules/npm/bin/npm-cli.js", prefix / "bin/npm")
        (self.home / "custom/lib/node_modules").mkdir(parents=True)
        self.write(".npmrc", f"registry=https://example.invalid\nprefix={self.home}/custom\n")
        env = {"PATH": str(prefix / "bin"), "HOME": str(self.home)}
        with mock.patch.dict(os.environ, env, clear=False), \
             mock.patch.object(subprocess, "run", side_effect=AssertionError("a subprocess was started")):
            os.environ.pop("NPM_CONFIG_PREFIX", None)
            roots = [str(p) for p, _ in footprint.npm_global_roots()]
        self.assertIn(str(prefix / "lib/node_modules"), roots)
        self.assertIn(str(self.home / "custom/lib/node_modules"), roots)

    def test_npm_global_detection(self):
        pkg = self.home / "node_modules/@openai/codex"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text('{"version": "0.42.0"}')
        found = footprint.find_npm_installs(agents.by_name("codex"), roots=[(self.home / "node_modules", "npm")])
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].version, found[0].manager), ("0.42.0", "npm"))


class TestAutostart(FakeHomeTestCase):
    def test_launchagent_plist_matching(self):
        d = self.home / "Library/LaunchAgents"
        d.mkdir(parents=True)
        with open(d / "com.anthropic.claude.updater.plist", "wb") as fh:
            plistlib.dump({"Label": "com.anthropic.claude.updater", "ProgramArguments": ["/x/claude", "update"],
                           "RunAtLoad": True, "StartInterval": 3600}, fh)
        with open(d / "com.google.keystone.agent.plist", "wb") as fh:
            plistlib.dump({"Label": "com.google.keystone.agent", "Program": "/x/ksagent"}, fh)
        with mock.patch.object(autostart, "have", return_value=False), \
             mock.patch.object(autostart, "launch_agents_dirs", return_value=[d]):
            entries = autostart.scan_launch_agents([])
        self.assertEqual(len(entries), 1)
        e = entries[0]
        self.assertEqual((e.agent, e.kind, e.id, e.enabled), ("claude", "launchagent", "com.anthropic.claude.updater", True))
        self.assertIn("RunAtLoad", e.detail)
        self.assertIn("every 3600s", e.detail)

    def test_systemd_unit_parsing(self):
        text = "[Unit]\nDescription=Codex updater\n\n[Service]\nExecStart=/usr/bin/codex --update\nExecStart=/bin/true\n"
        fields = autostart.parse_unit(text)
        self.assertEqual(fields["Unit.Description"], "Codex updater")
        self.assertEqual(fields["Service.ExecStart"], "/bin/true")

    def test_cron_scan(self):
        crontab = "SHELL=/bin/sh\n# comment\n0 * * * * /usr/local/bin/codex --check-update\n*/5 * * * * /usr/bin/backup\n"
        with mock.patch.object(autostart, "read_crontab", return_value=crontab):
            entries = autostart.scan_cron([])
        self.assertEqual(len(entries), 1)
        self.assertEqual((entries[0].agent, entries[0].detail), ("codex", "0 * * * *"))
        self.assertEqual(entries[0].program, "/usr/local/bin/codex --check-update")


if __name__ == "__main__":
    unittest.main()
