import json
import os
import plistlib
import unittest
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
        self.assertEqual(kinds, ["disable-self-update", "disable-self-update", "prune-version",
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
        self.assertEqual([a.kind for a in plan.actions], ["disable-self-update"])
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
