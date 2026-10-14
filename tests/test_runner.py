"""End-to-end checks for `run`: the agent's children die with it, escaped daemons are
swept, and files created outside the agent's folders are reported."""
import json
import os

import subprocess
import sys
import time
import unittest
from unittest import mock

from agent_hygiene.model import ProcessInfo
from agent_hygiene.runner import Supervisor, diff_snapshots, run_agent, snapshot
from agent_hygiene.scan.processes import list_processes
from tests.helpers import FakeHomeTestCase


def _quiet(*_a, **_k):
    pass


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class TestRunner(FakeHomeTestCase):
    def setUp(self):
        super().setUp()
        self.work = self.home / "work"
        self.work.mkdir()

    def _pids_matching(self, needle):
        return [p.pid for p in list_processes() if needle in p.command]

    def _kill_matching(self, needle):
        for pid in self._pids_matching(needle):
            try:
                os.kill(pid, 9)
            except OSError:
                pass

    def test_background_children_are_stopped_and_exit_code_preserved(self):
        marker = f"ah-test-{os.getpid()}"
        # The "agent" forks two sleepers into the background and exits 3.
        script = f"sleep 300 & sleep 300 & echo {marker} > {self.work}/out.txt; exit 3"
        rc = run_agent(["sh", "-c", script], agent="codex", watch=[str(self.work)], grace=1.0, log=_quiet)
        self.assertEqual(rc, 3)
        logs = list((self.home / ".agent-hygiene/runs").glob("*.json"))
        self.assertEqual(len(logs), 1)
        report = json.loads(logs[0].read_text())
        self.assertEqual(report["exit_code"], 3)
        self.assertEqual(report["leftovers"], [])
        self.assertGreaterEqual(len(report["killed"]), 2)
        for k in report["killed"]:
            self.assertFalse(_alive(k["pid"]), f"pid {k['pid']} still alive")
        self.assertEqual([os.path.realpath(p) for p in report["files_created"]],
                         [os.path.realpath(self.work / "out.txt")])

    def test_daemon_that_escapes_the_process_group_is_swept(self):
        # Simulate a double-forked self-updater: a new session, re-parented to pid 1,
        # running a program from the agent's own folders, which in turn has a child of
        # its own (`sleep 299`) that must go with it.
        fake_bin = self.home / ".local/share/claude/versions/9.9.9"
        fake_bin.mkdir(parents=True)
        script = fake_bin / "claude"
        # `exit $?` stops sh from exec'ing the last command, so sh stays the parent
        script.write_text("#!/bin/sh\nsleep 299\nexit $?\n")
        script.chmod(0o755)
        daemon = (
            "import subprocess; "
            f"subprocess.Popen([{str(script)!r}, 'serve'], start_new_session=True, "
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
        )
        self._kill_matching("sleep 299")  # leftovers from an earlier aborted run
        self.addCleanup(self._kill_matching, "sleep 299")
        self.addCleanup(self._kill_matching, str(script))
        rc = run_agent([sys.executable, "-c", daemon], agent="claude", watch=[str(self.work)], grace=1.0, log=_quiet)
        self.assertEqual(rc, 0)
        time.sleep(0.3)
        self.assertEqual(self._pids_matching(str(script)), [])
        self.assertEqual(self._pids_matching("sleep 299"), [])
        report = json.loads(next((self.home / ".agent-hygiene/runs").glob("*.json")).read_text())
        self.assertEqual(report["leftovers"], [])
        self.assertTrue(any("claude serve" in k["command"] for k in report["killed"]))
        self.assertTrue(any("sleep 299" in k["command"] for k in report["killed"]))

    def test_unrelated_process_is_left_alone(self):
        bystander = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            rc = run_agent(["sh", "-c", "exit 0"], agent="gemini", watch=[str(self.work)], grace=0.5, log=_quiet)
            self.assertEqual(rc, 0)
            self.assertIsNone(bystander.poll())
        finally:
            bystander.kill()
            bystander.wait()

    def test_escape_sweep_requires_the_agents_own_folders(self):
        (self.home / ".codex/packages/x/bin").mkdir(parents=True)
        inside_exe = str(self.home / ".codex/packages/x/bin/codex")
        launchd = ProcessInfo(1, 0, 1, "??", 0, 0, "/sbin/launchd")
        shell = ProcessInfo(50, 1, 50, "ttys000", 0, 0, "-zsh")
        by_pid = {1: launchd, 50: shell}

        def proc(pid, exe, ppid=1, etime=2, cmd="codex app-server daemon pid-update-loop"):
            return ProcessInfo(pid, ppid, pid, "??", etime, 0, cmd, exe=exe)

        with mock.patch("agent_hygiene.runner.find_npm_installs", return_value=[]):
            sup = Supervisor(["true"], "codex", [self.work], 1.0, False, _quiet)
            anon = Supervisor(["sleep", "5"], None, [self.work], 1.0, False, _quiet)
        for s in (sup, anon):
            s.initial_pids = {300}
            s.started = time.time() - 10
        self.assertTrue(sup._escaped(proc(100, inside_exe), by_pid))
        # an unrelated program that is merely *named* codex is never touched
        self.assertFalse(sup._escaped(proc(101, "/usr/local/bin/codex"), by_pid))
        self.assertFalse(sup._escaped(proc(102, "/Users/me/tools/codex", cmd="codex serve"), by_pid))
        self.assertFalse(sup._escaped(proc(300, inside_exe), by_pid))  # existed before the run
        self.assertFalse(sup._escaped(proc(103, inside_exe, etime=600), by_pid))  # older than the run
        self.assertFalse(sup._escaped(proc(104, inside_exe, ppid=50), by_pid))  # still has a live parent
        # `run -- sleep 5` has no agent folders, so nothing is ever swept by name
        self.assertFalse(anon._escaped(proc(100, inside_exe), by_pid))
        self.assertFalse(anon._escaped(proc(101, "/usr/local/bin/codex"), by_pid))

    def test_missing_command(self):
        self.assertEqual(run_agent(["definitely-not-a-real-binary-xyz"], watch=[str(self.work)], log=_quiet), 127)

    def test_snapshot_diff_excludes_agent_dirs(self):
        (self.home / ".claude").mkdir()
        (self.work / "a.txt").write_text("a")
        before, _ = snapshot([self.home], [str(self.home / ".claude")], [3])
        (self.work / "b.txt").write_text("b")
        (self.work / "a.txt").write_text("changed")
        (self.home / ".claude" / "history.jsonl").write_text("x")
        after, _ = snapshot([self.home], [str(self.home / ".claude")], [3])
        created, modified = diff_snapshots(before, after)
        self.assertEqual(created, [str(self.work / "b.txt")])
        self.assertEqual(modified, [str(self.work / "a.txt")])


if __name__ == "__main__":
    unittest.main()
