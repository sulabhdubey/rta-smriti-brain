"""Unified local setup and bounded native hook entrypoints."""

import argparse
import sqlite3
from pathlib import Path

from .agent_setup import (
    apply_setup,
    drain_setup,
    handle_hook,
    plan_removal,
    plan_setup,
    remove_setup,
    setup_status,
    stop_setup,
)
from .continuity_bridge import HOSTS
from .continuity_bridge_cli import _print, _run_worker, bounded_hook


def add_parser(sub, add_common_options):
    setup = sub.add_parser(
        "agent-setup", help="Consent-based Codex/Claude Code capture and recall"
    )
    actions = setup.add_subparsers(dest="setup_action", required=True)
    for action in (
        "plan",
        "apply",
        "status",
        "stop",
        "sync",
        "plan-remove",
        "remove",
        "hook",
        "_hook-worker",
    ):
        parser = actions.add_parser(action)
        add_common_options(parser)
        parser.add_argument("--project", required=True)
        if action in {"plan", "apply"}:
            parser.add_argument("--root", required=True)
            parser.add_argument("--host", action="append", choices=HOSTS)
        if action in {"apply", "remove"}:
            parser.add_argument("--expected-digest", required=True)
        if action == "apply":
            parser.add_argument("--allow-capture", action="store_true")
            parser.add_argument("--allow-model-context", action="store_true")
        if action in {"hook", "_hook-worker"}:
            parser.add_argument("--host", required=True, choices=HOSTS)


def dispatch(args):
    database = Path(args.db)
    if args.setup_action == "hook":
        _print(bounded_hook(database, args.project, args.host, unified=True))
        return 0
    if args.setup_action == "_hook-worker":
        return _run_worker(args, handle_hook)
    try:
        if args.setup_action == "stop":
            result = stop_setup(database, args.project)
        elif args.setup_action == "plan-remove":
            result = plan_removal(database, args.project)
        elif args.setup_action == "remove":
            result = remove_setup(
                database, args.project, expected_digest=args.expected_digest
            )
        elif args.setup_action == "status":
            result = setup_status(database, args.project)
        elif args.setup_action == "sync":
            result = drain_setup(database, args.project)
        else:
            plan = plan_setup(
                database, args.project, Path(args.root), hosts=args.host or HOSTS
            )
            result = (
                plan
                if args.setup_action == "plan"
                else apply_setup(
                    plan,
                    expected_digest=args.expected_digest,
                    allow_capture=args.allow_capture,
                    allow_model_context=args.allow_model_context,
                )
            )
        _print(result)
        return 0
    except (ValueError, TypeError, OSError, RuntimeError, sqlite3.Error) as exc:
        _print({"state": "error", "error": str(exc)})
        return 1


def worker_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--host", choices=HOSTS, required=True)
    return _run_worker(parser.parse_args(), handle_hook)


if __name__ == "__main__":
    raise SystemExit(worker_main())
