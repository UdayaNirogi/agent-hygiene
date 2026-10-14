import json
import unittest

from agent_hygiene.model import AgentFootprint, AutostartEntry, Inventory, ProcessInfo, SettingState, VersionEntry
from agent_hygiene.platform import human_bytes, parse_bytes
from agent_hygiene.policy import Policy, render_violations, write_template
from tests.helpers import FakeHomeTestCase


def _inv():
    inv = Inventory("h", "linux", "now")
    claude = AgentFootprint("claude", "Claude", True, total_bytes=6 * 1024**3)
    claude.versions = [VersionEntry(f"/v/{v}", "/v", v, 1024**3, 0, False, i == 0) for i, v in
                       enumerate(("2.3", "2.2", "2.1", "2.0"))]
    claude.settings = [SettingState("claude", True, "/s.json", "env.X", None, False)]
    codex = AgentFootprint("codex", "Codex", True, total_bytes=100 * 1024**2)
    codex.settings = [SettingState("codex", True, "/c.toml", "features.daemon_auto_start", None, False,
                                   kind="auto-start"),
                      SettingState("codex", True, "/d.json", "updater.autoUpdateEnabled", None, False,
                                   applicable=False)]
    inv.agents = [claude, codex]
    inv.autostarts = [AutostartEntry("systemd-user", "claude-updater.timer", "/u", "claude", True, "claude update"),
                      AutostartEntry("cron", "abc123", "crontab", "codex", True, "codex", "0 * * * *")]
    inv.processes = [ProcessInfo(9, 1, 9, "?", 100, 100, "claude serve", "claude", True)]
    return inv


class TestPolicy(unittest.TestCase):
    def test_bytes_helpers(self):
        self.assertEqual(parse_bytes("5GB"), 5 * 1024**3)
        self.assertEqual(parse_bytes("500 MB"), 500 * 1024**2)
        self.assertEqual(parse_bytes(1024), 1024)
        self.assertEqual(human_bytes(5 * 1024**3), "5.0 GB")

    def test_violations(self):
        pol = Policy({
            "keep_versions": 2,
            "max_disk_per_agent": "5GB",
            "max_disk_total": "6GB",
            "allowed_autostarts": ["claude-updater.*"],
            "allow_self_update": False,
            "allow_leftover_processes": False,
        })
        rules = sorted(v.rule for v in pol.evaluate(_inv()))
        # the codex daemon updater setting is not applicable (daemon never ran), so it is not flagged
        self.assertEqual(rules, ["allow_leftover_processes", "allow_self_update", "allowed_autostarts",
                                 "allowed_autostarts", "keep_versions", "max_disk", "max_disk_total"])
        text = render_violations(pol.evaluate(_inv()), "p.json")
        self.assertIn("7 violation(s)", text)
        self.assertIn("codex:features.daemon_auto_start", text)
        allowed = Policy({"allowed_autostarts": ["*", "codex:features.daemon_auto_start"]})
        self.assertNotIn("allowed_autostarts", [v.rule for v in allowed.evaluate(_inv())])
        self.assertIn("agent-hygiene clean --agent claude --keep 2", text)

    def test_permissive_policy_passes(self):
        pol = Policy({"keep_versions": 4, "allow_self_update": True, "allow_leftover_processes": True,
                      "allowed_autostarts": ["*"]})
        self.assertEqual(pol.evaluate(_inv()), [])
        self.assertEqual(render_violations([], "p.json"), "policy p.json: OK")

    def test_per_agent_override(self):
        pol = Policy({"keep_versions": 1, "agents": {"claude": {"keep_versions": 4, "max_disk": "10GB"}}})
        rules = [v.rule for v in pol.evaluate(_inv())]
        self.assertNotIn("keep_versions", rules)
        self.assertNotIn("max_disk", rules)


class TestPolicyFiles(FakeHomeTestCase):
    def test_init_and_load(self):
        p = write_template(str(self.home / "pol.json"))
        loaded = Policy.load(str(p))
        self.assertEqual(loaded.keep_versions(), 2)
        with self.assertRaises(FileExistsError):
            write_template(str(p))
        with self.assertRaises(FileNotFoundError):
            Policy.load(str(self.home / "missing.json"))

    def test_default_location_in_home(self):
        (self.home / ".config/agent-hygiene").mkdir(parents=True)
        (self.home / ".config/agent-hygiene/policy.json").write_text(json.dumps({"keep_versions": 7}))
        import os
        cwd = os.getcwd()
        os.chdir(self.home)
        try:
            self.assertEqual(Policy.load(None).keep_versions(), 7)
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
