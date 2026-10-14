"""Hardening checks: private state, tamper-resistant restore/purge, symlinks, pid reuse,
policy validation, root refusal, and no network use."""
import ast
import contextlib
import io
import json
import os
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from agent_hygiene import cli, clean, restore
from agent_hygiene.journal import Journal
from agent_hygiene.model import Inventory, ProcessInfo
from agent_hygiene.policy import Policy
from agent_hygiene.scan import scan
from tests.helpers import FakeHomeTestCase, fingerprint

STATE = (".agent-hygiene",)


def _quiet(*_a, **_k):
    pass


def _scan():
    with mock.patch("agent_hygiene.scan.scan_autostarts", return_value=[]), \
         mock.patch("agent_hygiene.scan.scan_processes", return_value=[]), \
         mock.patch("agent_hygiene.scan.footprint.npm_global_roots", return_value=[]):
        return scan(with_ports=False)


class TestPrivateState(FakeHomeTestCase):
    def test_state_dir_is_owner_only(self):
        self.write(".claude/settings.json", '{"env": {"ANTHROPIC_API_KEY": "sk-ant-' + "x" * 20 + '"}}')
        self.write(".local/share/claude/versions/2.1.0", size=10)
        journal = clean.apply_plan(clean.build_plan(_scan(), prune=False, autostart=False), log=_quiet)
        state = self.home / ".agent-hygiene"
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(journal.manifest_path.stat().st_mode), 0o600)

    def test_symlinked_state_dir_is_refused(self):
        target = self.home / "elsewhere"
        target.mkdir()
        os.symlink(target, self.home / ".agent-hygiene")
        with self.assertRaises(RuntimeError):
            Journal.create()


class TestTamperResistance(FakeHomeTestCase):
    def _seeded_journal(self):
        for v in ("3.0.0", "2.0.0", "1.0.0"):
            self.write(f".local/share/claude/versions/{v}", size=64)
        return clean.apply_plan(clean.build_plan(_scan(), keep=2, self_update=False), log=_quiet)

    def test_restore_refuses_manifest_paths_outside_backup(self):
        journal = self._seeded_journal()
        victim = self.home / "important.txt"
        victim.write_text("keep me")
        rec = journal.actions[0]
        rec["trash"] = str(victim)
        rec["original"] = str(self.home / "stolen.txt")
        journal.save()
        failures = restore.restore(Journal.load(journal.root), log=_quiet)
        self.assertEqual(failures, 1)
        self.assertEqual(victim.read_text(), "keep me")
        self.assertFalse((self.home / "stolen.txt").exists())

    def test_restore_never_runs_a_daemon_binary_outside_the_agent_folder(self):
        (self.home / ".codex").mkdir()
        marker = self.home / "pwned"
        evil = self.write("evil.sh", f"#!/bin/sh\ntouch {marker}\n")
        evil.chmod(0o755)
        journal = Journal.create()
        journal.record({"kind": "stop-daemon", "agent": "codex", "target": "daemon 1", "reversible": True,
                        "binary": str(evil), "server_running": True, "stopped": []})
        self.assertEqual(restore.restore(Journal.load(journal.root), log=_quiet), 1)
        self.assertFalse(marker.exists())

    def test_purge_refuses_symlinked_trash(self):
        journal = self._seeded_journal()
        precious = self.home / "precious"
        precious.mkdir()
        (precious / "file").write_text("x")
        import shutil
        shutil.rmtree(journal.trash)
        os.symlink(precious, journal.trash)
        with self.assertRaises(RuntimeError):
            restore.purge(journal, log=_quiet)
        self.assertTrue((precious / "file").exists())


class TestSymlinkedSettings(FakeHomeTestCase):
    def test_dotfile_symlink_is_kept_and_restore_is_identical(self):
        real = self.write("dotfiles/claude-settings.json", '{"theme": "dark"}\n')
        os.chmod(real, 0o600)
        (self.home / ".claude").mkdir()
        os.symlink(real, self.home / ".claude/settings.json")
        self.write(".local/share/claude/versions/2.1.0", size=10)
        before = fingerprint(self.home, ignore_prefixes=STATE)

        journal = clean.apply_plan(clean.build_plan(_scan(), prune=False, autostart=False), log=_quiet)
        link = self.home / ".claude/settings.json"
        self.assertTrue(link.is_symlink())
        self.assertEqual(json.loads(real.read_text())["env"], {"DISABLE_AUTOUPDATER": "1"})
        self.assertEqual(stat.S_IMODE(real.stat().st_mode), 0o600)

        self.assertEqual(restore.restore(journal, log=_quiet), 0)
        self.assertEqual(before, fingerprint(self.home, ignore_prefixes=STATE))

    def test_nested_dirs_created_for_new_settings_are_removed_on_restore(self):
        # opencode's settings live in ~/.config/opencode/, which may not exist yet
        self.write(".local/share/opencode/bin", size=10)
        before = fingerprint(self.home, ignore_prefixes=STATE)
        journal = clean.apply_plan(clean.build_plan(_scan(), prune=False, autostart=False), log=_quiet)
        self.assertTrue((self.home / ".config/opencode/opencode.json").is_file())
        self.assertEqual(restore.restore(journal, log=_quiet), 0)
        self.assertEqual(before, fingerprint(self.home, ignore_prefixes=STATE))


class TestKillSafety(FakeHomeTestCase):
    def _plan_for(self, pid, command):
        inv = Inventory("h", "macos", "now")
        inv.processes = [ProcessInfo(pid, 1, pid, "??", 1, 1, command, agent="claude", orphaned=True)]
        return clean.build_plan(inv, kill=True, prune=False, self_update=False, autostart=False)

    def test_reused_pid_is_not_killed(self):
        bystander = subprocess.Popen(["sleep", "30"])
        self.addCleanup(bystander.wait)
        self.addCleanup(bystander.kill)
        plan = self._plan_for(bystander.pid, "/x/.local/bin/claude serve")
        journal = clean.apply_plan(plan, log=_quiet)
        self.assertEqual(journal.actions, [])  # the action failed instead of killing
        self.assertIsNone(bystander.poll())

    def test_matching_process_is_killed(self):
        target = subprocess.Popen(["sleep", "30"])
        self.addCleanup(target.wait)
        command = next(p.command for p in clean.list_processes() if p.pid == target.pid)
        journal = clean.apply_plan(self._plan_for(target.pid, command), log=_quiet)
        self.assertEqual(len(journal.actions), 1)
        target.wait(timeout=5)


class TestPolicyHardening(FakeHomeTestCase):
    def test_invalid_values_rejected(self):
        for bad in ({"keep_versions": 0}, {"keep_versions": "2"}, {"keep_versions": True},
                    {"max_disk_total": "lots"}, {"allow_self_update": "no"},
                    {"allowed_autostarts": "*"}, {"agents": {"claude": {"keep_versions": -1}}}, []):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Policy(bad)

    def test_clean_ignores_policy_in_current_directory(self):
        repo = self.home / "cloned-repo"
        repo.mkdir()
        (repo / "agent-hygiene.policy.json").write_text(json.dumps({"keep_versions": 1}))
        cwd = os.getcwd()
        os.chdir(repo)
        try:
            self.assertIsNone(Policy.load(None, include_cwd=False))
            self.assertEqual(Policy.load(None).keep_versions(), 1)  # `policy check` still sees it
        finally:
            os.chdir(cwd)


class TestRootRefusal(unittest.TestCase):
    def test_mutating_commands_refuse_root(self):
        with mock.patch.object(cli.os, "geteuid", return_value=0), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            for argv in (["clean", "--dry-run"], ["restore"], ["purge"], ["run", "--", "true"]):
                with self.subTest(argv=argv):
                    self.assertEqual(cli.main(argv), 2)
        self.assertIn("refusing to run this command as root", err.getvalue())


class TestNoNetwork(unittest.TestCase):
    """The package must never talk to the network: no telemetry, no update checks."""

    NETWORK_MODULES = {"socket", "urllib", "http", "requests", "httpx", "aiohttp", "ftplib",
                       "smtplib", "telnetlib", "xmlrpc", "ssl", "asyncio"}

    def test_no_network_modules_imported(self):
        pkg = Path(__file__).resolve().parent.parent / "agent_hygiene"
        offenders = []
        for f in pkg.rglob("*.py"):
            tree = ast.parse(f.read_text())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names = [node.module]
                for n in names:
                    if n.split(".")[0] in self.NETWORK_MODULES:
                        offenders.append(f"{f.name}: {n}")
        # socket is only used for gethostname(), which makes no network connection
        self.assertEqual([o for o in offenders if o != "__init__.py: socket"], [])

    def test_footprint_scan_starts_no_subprocess(self):
        # `npm root -g` would write ~/.npm/_logs/*.log on every scan; the file scan must
        # stay purely a file scan (only ps/lsof/launchctl/systemctl/crontab are ever run).
        from agent_hygiene.scan import footprint
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess started")):
            footprint.npm_global_roots()
            for spec in cli.agents.AGENTS:
                footprint.scan_agent(spec, npm_roots=[])

    def test_scan_opens_no_sockets(self):
        import socket as _socket
        with mock.patch.object(_socket.socket, "connect", side_effect=AssertionError("network used")), \
             mock.patch.object(_socket, "create_connection", side_effect=AssertionError("network used")):
            _scan()


if __name__ == "__main__":
    unittest.main()
