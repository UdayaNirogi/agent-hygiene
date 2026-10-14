import json
import os
import plistlib
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

from agent_hygiene import clean, restore
from agent_hygiene.journal import Journal
from agent_hygiene.model import AutostartEntry
from agent_hygiene.policy import Policy
from agent_hygiene.scan import scan
from tests.helpers import FakeHomeTestCase, fingerprint

STATE = (".agent-hygiene",)


def _quiet(*_a, **_k):
    pass


class TestCleanRestoreRoundTrip(FakeHomeTestCase):
    def _seed(self):
        for v in ("2.1.201", "2.1.100", "2.0.0", "1.5.0"):
            self.write(f".local/share/claude/versions/{v}", size=2048)
        (self.home / ".local/bin").mkdir(parents=True)
        os.symlink(self.home / ".local/share/claude/versions/2.1.201", self.home / ".local/bin/claude")
        self.write(".claude/settings.json", '{"permissions": {"allow": []}, "env": {"FOO": "bar"}}\n')
        self.write(".gemini/settings.json", '{"theme": "dark"}\n')
        for v in ("2026.10.12-abc", "2026.09.01-def", "2026.08.01-ghi"):
            d = self.home / f".local/share/cursor-agent/versions/{v}"
            d.mkdir(parents=True)
            (d / "index.js").write_text(f"// {v}\n")
            (d / "node_modules").mkdir()
            (d / "node_modules" / "x.js").write_text("x")

    def _scan(self):
        with mock.patch("agent_hygiene.scan.scan_autostarts", return_value=[]), \
             mock.patch("agent_hygiene.scan.scan_processes", return_value=[]), \
             mock.patch("agent_hygiene.scan.footprint.npm_global_roots", return_value=[]):
            return scan(with_ports=False)

    def test_clean_then_restore_is_identical(self):
        self._seed()
        before = fingerprint(self.home, ignore_prefixes=STATE)

        inv = self._scan()
        plan = clean.build_plan(inv, keep=2)
        kinds = sorted(a.kind for a in plan.actions)
        self.assertEqual(kinds, ["disable-setting", "disable-setting", "prune-version",
                                 "prune-version", "prune-version"])
        pruned = sorted(a.data["version"] for a in plan.actions if a.kind == "prune-version")
        self.assertEqual(pruned, ["1.5.0", "2.0.0", "2026.08.01-ghi"])
        self.assertIn("would move to trash", clean.render_plan(plan))

        journal = clean.apply_plan(plan, log=_quiet)
        self.assertIsNotNone(journal)
        self.assertEqual(len(journal.actions), 5)

        after_clean = fingerprint(self.home, ignore_prefixes=STATE)
        self.assertNotEqual(before, after_clean)
        self.assertFalse((self.home / ".local/share/claude/versions/1.5.0").exists())
        self.assertTrue((self.home / ".local/share/claude/versions/2.1.201").exists())
        settings = json.loads((self.home / ".claude/settings.json").read_text())
        self.assertEqual(settings["env"], {"FOO": "bar", "DISABLE_AUTOUPDATER": "1"})
        self.assertEqual(settings["permissions"], {"allow": []})
        gem = json.loads((self.home / ".gemini/settings.json").read_text())
        self.assertEqual(gem, {"theme": "dark", "general": {"disableAutoUpdate": True}})

        # a second scan sees nothing left to do
        self.assertEqual(clean.build_plan(self._scan(), keep=2).actions, [])
        self.assertGreater(journal.trash_bytes(), 0)

        failures = restore.restore(Journal.find(None), log=_quiet)
        self.assertEqual(failures, 0)
        after_restore = fingerprint(self.home, ignore_prefixes=STATE)
        self.assertEqual(before, after_restore)
        self.assertIsNotNone(Journal.load(journal.root).restored_at)
        self.assertIsNone(Journal.find(None))  # nothing pending

    def test_self_update_file_created_then_removed_on_restore(self):
        self.write(".local/share/claude/versions/2.1.201", size=10)
        before = fingerprint(self.home, ignore_prefixes=STATE)
        inv = self._scan()
        plan = clean.build_plan(inv, prune=False, autostart=False)
        self.assertEqual([a.kind for a in plan.actions], ["disable-setting"])
        journal = clean.apply_plan(plan, log=_quiet)
        self.assertTrue((self.home / ".claude/settings.json").is_file())
        restore.restore(journal, log=_quiet)
        self.assertEqual(before, fingerprint(self.home, ignore_prefixes=STATE))

    def test_purge_frees_trash_and_blocks_restore_of_pruned(self):
        self._seed()
        journal = clean.apply_plan(clean.build_plan(self._scan(), keep=1, self_update=False), log=_quiet)
        self.assertGreater(journal.trash_bytes(), 0)
        self.assertEqual(restore.purgeable([journal], older_than_days=None), [journal])
        self.assertEqual(restore.purgeable([journal], older_than_days=1), [])
        freed = restore.purge(journal, log=_quiet)
        self.assertGreater(freed, 0)
        self.assertEqual(journal.trash_bytes(), 0)
        failures = restore.restore(journal, log=_quiet)
        self.assertGreater(failures, 0)  # pruned versions are gone for good

    def test_policy_keep_per_agent(self):
        self._seed()
        pol = Policy({"keep_versions": 3, "agents": {"cursor": {"keep_versions": 1}}})
        plan = clean.build_plan(self._scan(), keep=pol.keep_versions(), keep_per_agent=pol.keep_per_agent(),
                                self_update=False)
        pruned = sorted(a.data["version"] for a in plan.actions)
        self.assertEqual(pruned, ["1.5.0", "2026.08.01-ghi", "2026.09.01-def"])

    def test_launchagent_apply_and_restore_without_launchctl(self):
        d = self.home / "Library/LaunchAgents"
        d.mkdir(parents=True)
        plist = d / "com.anthropic.claude.updater.plist"
        with open(plist, "wb") as fh:
            plistlib.dump({"Label": "com.anthropic.claude.updater", "ProgramArguments": ["/x/claude"]}, fh)
        before = fingerprint(self.home, ignore_prefixes=STATE)
        entry = AutostartEntry("launchagent", "com.anthropic.claude.updater", str(plist), "claude", True, "/x/claude")
        plan = clean.Plan(actions=[clean._plan_autostart(entry)])
        with mock.patch.object(clean, "have", return_value=False), mock.patch.object(restore, "have", return_value=False):
            journal = clean.apply_plan(plan, log=_quiet)
            self.assertFalse(plist.exists())
            self.assertEqual(restore.restore(journal, log=_quiet), 0)
        self.assertEqual(before, fingerprint(self.home, ignore_prefixes=STATE))

    def test_cron_apply_and_restore(self):
        original = "0 * * * * /usr/local/bin/codex --check-update\n*/5 * * * * /usr/bin/backup\n"
        store = {"text": original}

        def fake_run(args, timeout=15, input_text=None, check=False):
            import subprocess
            if args[:2] == ["crontab", "-l"]:
                return subprocess.CompletedProcess(args, 0, store["text"], "")
            if args[:2] == ["crontab", "-"]:
                store["text"] = input_text
                return subprocess.CompletedProcess(args, 0, "", "")
            return subprocess.CompletedProcess(args, 1, "", "unexpected")

        from agent_hygiene.scan import autostart as au
        with mock.patch.object(au, "have", return_value=True), mock.patch.object(au, "run", fake_run), \
             mock.patch.object(clean, "run", fake_run), mock.patch.object(restore, "run", fake_run):
            entries = au.scan_cron([])
            self.assertEqual(len(entries), 1)
            plan = clean.Plan(actions=[clean._plan_autostart(entries[0])])
            journal = clean.apply_plan(plan, log=_quiet)
            self.assertTrue(store["text"].startswith("# agent-hygiene disabled: 0 * * * * /usr/local/bin/codex"))
            self.assertIn("*/5 * * * * /usr/bin/backup", store["text"])
            self.assertEqual(restore.restore(journal, log=_quiet), 0)
        self.assertEqual(store["text"], original)

    def test_old_journal_kind_still_restores(self):
        self.write(".local/share/claude/versions/2.1.201", size=10)
        before = fingerprint(self.home, ignore_prefixes=STATE)
        journal = clean.apply_plan(clean.build_plan(self._scan(), prune=False, autostart=False), log=_quiet)
        journal.actions[0]["kind"] = "disable-self-update"  # as written by 0.1.x
        journal.save()
        self.assertEqual(restore.restore(Journal.load(journal.root), log=_quiet), 0)
        self.assertEqual(before, fingerprint(self.home, ignore_prefixes=STATE))

    def _python_script(self, rel, body="import time\ntime.sleep(60)\n"):
        p = self.write(rel, f"#!{sys.executable}\n{body}")
        p.chmod(0o755)
        return p

    def _start(self, path, *args):
        proc = subprocess.Popen([str(path), *args])
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        time.sleep(0.4)
        return proc

    def test_prune_rechecks_right_before_moving(self):
        for v in ("3.0", "2.0", "1.0"):
            self._python_script(f".local/share/claude/versions/{v}/claude")
        plan = clean.build_plan(self._scan(), keep=2, self_update=False, autostart=False)
        self.assertEqual([a.data["version"] for a in plan.actions], ["1.0"])
        # a session starts from 1.0 between the preview and the confirm
        self._start(self.home / ".local/share/claude/versions/1.0/claude")
        journal = clean.apply_plan(plan, log=_quiet)
        self.assertEqual(journal.actions, [])
        self.assertTrue((self.home / ".local/share/claude/versions/1.0/claude").exists())

    def test_scan_skips_running_version(self):
        for v in ("3.0", "2.0", "1.0"):
            self._python_script(f".local/share/claude/versions/{v}/claude")
        proc = self._start(self.home / ".local/share/claude/versions/1.0/claude")
        with mock.patch("agent_hygiene.scan.scan_autostarts", return_value=[]), \
             mock.patch("agent_hygiene.scan.footprint.npm_global_roots", return_value=[]):
            inv = scan(only=["claude"], with_ports=False)
        plan = clean.build_plan(inv, keep=2, self_update=False, autostart=False)
        self.assertEqual(plan.actions, [])
        self.assertTrue(any(f"pid {proc.pid}" in s for s in plan.skipped))

    def test_purge_keeps_a_trashed_version_that_is_running(self):
        for v in ("3.0", "2.0", "1.0"):
            self._python_script(f".local/share/claude/versions/{v}/claude")
        journal = clean.apply_plan(clean.build_plan(self._scan(), keep=2, self_update=False), log=_quiet)
        trashed = Path(journal.actions[0]["trash"])
        self._start(trashed / "claude")
        restore.purge(journal, log=_quiet)
        self.assertTrue((trashed / "claude").exists())
        self.assertIsNone(Journal.load(journal.root).purged_at)

    def test_codex_settings_and_releases_round_trip(self):
        self.write(".codex/config.toml", '# mine\nmodel = "o3"\n\n[features]\nweb_search = true\n')
        self.write(".codex/app-server-daemon/settings.json", '{"remoteControlEnabled": false}\n')
        rel = self.home / ".codex/packages/standalone/releases"
        for v in ("0.162.1-x86_64-unknown-linux-musl", "0.161.0-x86_64-unknown-linux-musl",
                  "0.157.0-x86_64-unknown-linux-musl"):
            self.write(f".codex/packages/standalone/releases/{v}/codex", size=128)
        os.symlink(rel / "0.162.1-x86_64-unknown-linux-musl", self.home / ".codex/packages/standalone/current")
        before = fingerprint(self.home, ignore_prefixes=STATE)

        plan = clean.build_plan(self._scan(), keep=2)
        kinds = sorted((a.kind, a.agent) for a in plan.actions)
        self.assertEqual(kinds, [("disable-setting", "codex"), ("disable-setting", "codex"),
                                 ("prune-version", "codex")])
        journal = clean.apply_plan(plan, log=_quiet)
        toml = (self.home / ".codex/config.toml").read_text()
        self.assertIn("[features]\ndaemon_auto_start = false\nweb_search = true\n", toml)
        self.assertTrue(toml.startswith('# mine\nmodel = "o3"\n'))
        daemon = json.loads((self.home / ".codex/app-server-daemon/settings.json").read_text())
        self.assertEqual(daemon, {"remoteControlEnabled": False, "updater": {"autoUpdateEnabled": False}})
        self.assertFalse((rel / "0.157.0-x86_64-unknown-linux-musl").exists())
        self.assertEqual(clean.build_plan(self._scan(), keep=2).actions, [])

        self.assertEqual(restore.restore(journal, log=_quiet), 0)
        self.assertEqual(before, fingerprint(self.home, ignore_prefixes=STATE))

    def test_codex_daemon_stopped_only_from_inside_codex_folder(self):
        log = self.home / "daemon.log"
        body = (
            "import sys, time\n"
            "args = ' '.join(sys.argv[1:])\n"
            "if args in ('app-server daemon stop', 'app-server daemon start'):\n"
            f"    open({str(log)!r}, 'a').write(args.split()[-1] + '\\n')\n"
            "    sys.exit(0)\n"
            "time.sleep(60)\n"
        )
        codex = self._python_script(".codex/packages/standalone/releases/0.162.1-x/bin/codex", body)
        os.symlink(self.home / ".codex/packages/standalone/releases/0.162.1-x",
                   self.home / ".codex/packages/standalone/current")
        other = self._python_script("elsewhere/codex", body)
        server = self._start(codex, "app-server", "--listen", "unix:///tmp/x")
        updater = self._start(codex, "app-server", "daemon", "pid-update-loop")
        bystander = self._start(other, "app-server", "daemon", "pid-update-loop")

        with mock.patch("agent_hygiene.scan.scan_autostarts", return_value=[]), \
             mock.patch("agent_hygiene.scan.footprint.npm_global_roots", return_value=[]):
            inv = scan(only=["codex"], with_ports=False)
        plan = clean.build_plan(inv, self_update=False, prune=False)
        stops = [a for a in plan.actions if a.kind == "stop-daemon"]
        self.assertEqual(len(stops), 1)
        self.assertEqual(sorted(p["pid"] for p in stops[0].data["procs"]), sorted([server.pid, updater.pid]))
        self.assertTrue(any(f"pid {bystander.pid}" in s for s in plan.skipped))

        journal = clean.apply_plan(clean.Plan(actions=stops), log=_quiet)
        self.assertEqual(log.read_text(), "stop\n")
        server.wait(timeout=10)
        updater.wait(timeout=10)
        self.assertIsNone(bystander.poll())

        self.assertEqual(restore.restore(journal, log=_quiet), 0)
        self.assertEqual(log.read_text(), "stop\nstart\n")

    def test_kill_is_irreversible_and_opt_in(self):
        from agent_hygiene.model import Inventory, ProcessInfo
        inv = Inventory("h", "macos", "now")
        inv.processes = [ProcessInfo(4242, 1, 4242, "??", 10, 10, "claude serve", agent="claude", orphaned=True)]
        self.assertEqual(clean.build_plan(inv).actions, [])
        plan = clean.build_plan(inv, kill=True)
        self.assertEqual(len(plan.actions), 1)
        self.assertFalse(plan.actions[0].reversible)


if __name__ == "__main__":
    unittest.main()
