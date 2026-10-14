"""Command-line entry point: scan, clean, restore, purge, run, policy."""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from . import __version__, agents
from .clean import DEFAULT_KEEP, apply_plan, build_plan, render_plan
from .journal import Journal
from .output import confirm, dump_json, human_bytes, render_inventory
from .platform import IS_LINUX, IS_MACOS
from .policy import Policy, render_violations, write_template
from .restore import purge, purgeable, render_backups, restore
from .runner import run_agent
from .scan import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-hygiene",
        description="Inventory and clean up what coding-agent CLIs leave behind. "
                    "Read-only unless you run clean/purge/run, and every clean is reversible with restore.",
    )
    p.add_argument("--version", action="version", version=f"agent-hygiene {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="command")
    sub.required = True

    def add_common(sp):
        sp.add_argument("--agent", action="append", choices=agents.names(), metavar="NAME",
                        help="limit to one agent (repeatable): " + ", ".join(agents.names()))
        sp.add_argument("--json", action="store_true", help="machine-readable output")

    s = sub.add_parser("scan", help="inventory: folders, installs, auto-start, processes, ports (read-only)")
    add_common(s)
    s.add_argument("--no-ports", action="store_true", help="skip the lsof/ss port scan")
    s.add_argument("-v", "--verbose", action="store_true", help="also list agents that are not present")

    c = sub.add_parser("clean", help="preview fixes, confirm, apply with a backup journal")
    add_common(c)
    c.add_argument("--autostart", action="store_true", help="disable agent auto-start entries")
    c.add_argument("--self-update", action="store_true", help="turn off agent self-update settings")
    c.add_argument("--prune", action="store_true", help="move old version folders to trash")
    c.add_argument("--kill", action="store_true", help="terminate leftover processes (NOT reversible)")
    c.add_argument("--keep", type=int, metavar="N", help=f"versions to keep when pruning (default {DEFAULT_KEEP})")
    c.add_argument("--policy", metavar="FILE", help="read keep_versions from a policy file")
    c.add_argument("--dry-run", action="store_true", help="show the preview and exit")
    c.add_argument("-y", "--yes", action="store_true", help="apply without prompting")

    r = sub.add_parser("restore", help="undo a previous clean (default: the most recent)")
    r.add_argument("id", nargs="?", help="backup id from `restore --list`")
    r.add_argument("--list", action="store_true", help="list backups")
    r.add_argument("--json", action="store_true")

    g = sub.add_parser("purge", help="permanently delete trashed version folders to free disk")
    g.add_argument("id", nargs="?", help="backup id; default: all pending")
    g.add_argument("--older-than", type=float, metavar="DAYS", help="only trash older than DAYS")
    g.add_argument("-y", "--yes", action="store_true")

    w = sub.add_parser("run", help="run an agent in its own process group; stop everything it started on exit",
                       usage="agent-hygiene run [--agent NAME] [--watch DIR]... [--grace S] -- <command> [args...]")
    w.add_argument("--agent", choices=agents.names(), metavar="NAME", help="agent name if not obvious from the command")
    w.add_argument("--watch", action="append", metavar="DIR", help="dirs to diff for files created (default: cwd and ~)")
    w.add_argument("--grace", type=float, default=3.0, metavar="SECONDS", help="SIGTERM grace before SIGKILL (default 3)")
    w.add_argument("--no-cgroup", action="store_true", help="Linux: don't wrap in a transient systemd scope")
    w.add_argument("command", nargs=argparse.REMAINDER, help="the agent command, after --")

    po = sub.add_parser("policy", help="check the machine against a team policy file (exit 1 on violations)")
    posub = po.add_subparsers(dest="policy_cmd", metavar="action")
    posub.required = True
    pc = posub.add_parser("check", help="evaluate policy against a fresh scan")
    pc.add_argument("--file", metavar="FILE", help="policy file (default: ./agent-hygiene.policy.json, "
                                                   "~/.config/agent-hygiene/policy.json, $AGENT_HYGIENE_POLICY)")
    pc.add_argument("--json", action="store_true")
    pi = posub.add_parser("init", help="write a template policy file")
    pi.add_argument("--file", default="agent-hygiene.policy.json", metavar="FILE")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    if not (IS_MACOS or IS_LINUX):
        print("agent-hygiene supports macOS and Linux only.", file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    if os.geteuid() == 0 and args.cmd in ("clean", "restore", "purge", "run"):
        # As root, "user-writable" covers system LaunchAgents and other users' processes,
        # and backups would land root-owned in the wrong home. Run as the agent's user.
        print("agent-hygiene: refusing to run this command as root; run it as your normal user.",
              file=sys.stderr)
        return 2
    return {
        "scan": cmd_scan, "clean": cmd_clean, "restore": cmd_restore,
        "purge": cmd_purge, "run": cmd_run, "policy": cmd_policy,
    }[args.cmd](args)


def cmd_scan(args) -> int:
    inv = scan(args.agent, with_ports=not args.no_ports)
    if args.json:
        dump_json(inv.to_dict())
    else:
        print(render_inventory(inv, verbose=args.verbose))
    return 0


def cmd_clean(args) -> int:
    all_default = not (args.autostart or args.self_update or args.prune or args.kill)
    keep = args.keep if args.keep is not None else DEFAULT_KEEP
    keep_per_agent = None
    if keep < 1:
        print("error: --keep must be at least 1", file=sys.stderr)
        return 2
    if args.policy or args.keep is None:
        try:
            pol = Policy.load(args.policy, include_cwd=False)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if pol is not None:
            if args.keep is None:
                keep = pol.keep_versions()
            keep_per_agent = pol.keep_per_agent()
            if not args.json:
                print(f"using policy {pol.source}")

    inv = scan(args.agent, with_ports=False)
    plan = build_plan(
        inv,
        autostart=all_default or args.autostart,
        self_update=all_default or args.self_update,
        prune=all_default or args.prune,
        kill=args.kill,
        keep=keep,
        keep_per_agent=keep_per_agent,
    )
    if args.json:
        dump_json({"actions": [a.__dict__ for a in plan.actions], "skipped": plan.skipped,
                   "bytes_to_trash": plan.bytes_to_trash})
        if args.dry_run or not args.yes:
            return 0
    else:
        print("Preview — nothing has been changed yet.\n")
        print(render_plan(plan))
    if not plan.actions or args.dry_run:
        return 0
    irreversible = [a for a in plan.actions if not a.reversible]
    prompt = f"\nApply {len(plan.actions)} change(s)?"
    if irreversible:
        prompt = f"\nApply {len(plan.actions)} change(s), including {len(irreversible)} that cannot be undone?"
    if not confirm(prompt, assume_yes=args.yes):
        print("aborted; nothing changed")
        return 1
    journal = apply_plan(plan, log=print)
    if journal:
        print(f"\ndone. undo with: agent-hygiene restore {journal.id}")
    return 0


def cmd_restore(args) -> int:
    journals = Journal.list_all()
    if args.list:
        if args.json:
            dump_json([j.data for j in journals])
        else:
            print(render_backups(journals))
        return 0
    j = Journal.find(args.id)
    if j is None:
        print("no matching backup to restore" if args.id else "no pending backups", file=sys.stderr)
        return 1
    print(f"restoring backup {j.id} ({len(j.actions)} action(s))")
    failures = restore(j, log=print)
    if failures:
        print(f"{failures} action(s) could not be restored; the backup stays pending", file=sys.stderr)
        return 1
    print("restored")
    return 0


def cmd_purge(args) -> int:
    journals = Journal.list_all()
    if args.id:
        chosen = [j for j in journals if j.id == args.id]
        if not chosen:
            print(f"no backup {args.id}", file=sys.stderr)
            return 1
    else:
        chosen = purgeable(journals, args.older_than)
    chosen = [j for j in chosen if j.trash_bytes() > 0 and not j.purged_at]
    if not chosen:
        print("nothing to purge")
        return 0
    total = sum(j.trash_bytes() for j in chosen)
    print("Preview — permanently delete trashed versions from:")
    for j in chosen:
        print(f"  {j.id}  {human_bytes(j.trash_bytes())}")
    print(f"\nThis frees {human_bytes(total)} and cannot be undone.")
    if not confirm("Purge?", assume_yes=args.yes):
        print("aborted; nothing changed")
        return 1
    for j in chosen:
        purge(j, log=print)
    return 0


def cmd_run(args) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    return run_agent(command, agent=args.agent, watch=args.watch, grace=args.grace,
                     use_cgroup=not args.no_cgroup, log=print)


def cmd_policy(args) -> int:
    if args.policy_cmd == "init":
        try:
            p = write_template(args.file)
        except FileExistsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"wrote {p}")
        return 0
    try:
        pol = Policy.load(args.file)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if pol is None:
        print("no policy file found; run `agent-hygiene policy init` or pass --file", file=sys.stderr)
        return 2
    inv = scan(with_ports=False)
    violations = pol.evaluate(inv)
    if args.json:
        dump_json({"policy": pol.source, "violations": [v.__dict__ for v in violations]})
    else:
        print(render_violations(violations, pol.source))
    return 1 if violations else 0
