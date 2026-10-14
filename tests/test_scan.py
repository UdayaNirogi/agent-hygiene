import os
import plistlib
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
            "  100     1   100 ??       01:00  3000 /x/.local/bin/claude --api-key sk-abcdefghijklmnop serve\n"
            "  101   100   100 ??       00:30  1000 node child.js TOKEN=verysecretvalue\n"
            "  200   999   200 ttys001  00:10   500 /bin/zsh\n"
        )
        procs = processes.parse_ps(out)
        self.assertEqual([p.pid for p in procs], [100, 101, 200])
        self.assertIn("--api-key ***", procs[0].command)
        self.assertNotIn("sk-abcdefghijklmnop", procs[0].command)
        self.assertIn("TOKEN=***", procs[1].command)
        self.assertEqual(procs[0].etime_s, 60)

    def test_redact_known_token_shapes(self):
        self.assertEqual(processes.redact("x crsr_dd27c3554921041e818582fb y"), "x *** y")
        self.assertEqual(processes.redact("x ghp_abcdefghijklmnop y"), "x *** y")
        self.assertEqual(processes.redact("plain command --flag value"), "plain command --flag value")

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

    def test_version_key_handles_date_builds(self):
        k1 = footprint._version_key("2026.10.12-d47ca18", 0)
        k2 = footprint._version_key("2026.09.26-dd393fe", 0)
        self.assertGreater(k1, k2)

    def test_scan_agent_totals_and_self_update(self):
        self.write(".claude/settings.json", '{"env": {"DISABLE_AUTOUPDATER": "1"}}')
        self.write(".local/share/claude/versions/2.1.201", size=4096)
        fp = footprint.scan_agent(self._claude_spec(), npm_roots=[])
        self.assertTrue(fp.installed)
        self.assertTrue(fp.self_update.disabled)
        self.assertGreater(fp.total_bytes, 4096)
        self.assertEqual(len(fp.versions), 1)

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
