"""Bounded, advisory native hooks. No host configuration is changed here."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sqlite3
import subprocess
import sys
from pathlib import Path

from .capture_spool import _validate_json_shape
from .continuity_bridge import (
    HOSTS,
    MAX_INPUT_BYTES,
    _empty,
    disable_bridge,
    enable_bridge,
    preview_bridge,
    recall_bridge,
)
from .continuity_bridge_process import initialize_worker_containment, kill_worker_tree
from .runtime_control import isolated_module_bootstrap, runtime_executable

TIMEOUT_SECONDS = 5
HOST_TIMEOUT_SECONDS = 15  # Includes the host shell, launcher startup and cleanup.
MAX_OUTPUT_BYTES = 131_072  # JSON ASCII escaping can expand a bounded UTF-8 payload.
RECURSION_GUARD = "RTA_SMIRTI_BRIDGE_ACTIVE"


def add_parser(sub, add_common_options):
    bridge = sub.add_parser(
        "continuity-bridge", help="Opt-in native session-start handoffs"
    )
    actions = bridge.add_subparsers(dest="bridge_action", required=True)
    for action in ("plan", "enable", "disable", "hook", "_hook-worker"):
        parser = actions.add_parser(action)
        add_common_options(parser)
        parser.add_argument("--project", required=True)
        parser.add_argument("--host", choices=HOSTS, required=True)
        if action in {"plan", "enable"}:
            parser.add_argument("--root", required=True)
            parser.add_argument("--checkpoint-field", action="append", default=[])
            parser.add_argument("--decision-id", type=int, action="append", default=[])
            parser.add_argument("--max-bytes", type=int, default=8192)
            parser.add_argument("--max-age-hours", type=int, default=168)
        if action == "enable":
            parser.add_argument("--expected-digest", required=True)
            parser.add_argument("--allow-model-context", action="store_true")


def _launcher():
    executable = runtime_executable()
    if getattr(sys, "frozen", False):
        return [str(executable)]
    script = Path(__file__).resolve().parents[1] / "rta-brain.py"
    return (
        [str(executable), "-I", str(script)]
        if script.is_file()
        else [str(executable), "-I", "-m", "rta_brain.cli"]
    )


def _powershell_command(parts):
    unsupported = ('\0', '\r', '\n', '"', '%', '!', '&', '|', '<', '>', '^')
    if any(character in part for part in parts for character in unsupported):
        raise ValueError("Windows bridge command contains unsupported characters")
    return "& " + " ".join("'" + part.replace("'", "''") + "'" for part in parts)


def configuration_fragment(database, project, host):
    launcher = _launcher()
    parts = [
        *launcher,
        "continuity-bridge",
        "hook",
        "--db",
        str(Path(database).absolute()),
        "--project",
        project,
        "--host",
        host,
    ]
    if any("\0" in value or "\r" in value or "\n" in value for value in parts):
        raise ValueError("invalid hook command")
    posix_parts = (
        [
            part.replace("\\", "/")
            if index < len(launcher) or index == len(launcher) + 3
            else part
            for index, part in enumerate(parts)
        ]
        if os.name == "nt"
        else parts
    )
    handler = {
        "type": "command",
        "command": shlex.join(posix_parts),
        "timeout": HOST_TIMEOUT_SECONDS,
    }
    if os.name == "nt" and host == "codex":
        handler["commandWindows"] = _powershell_command(parts)
    return {
        "hooks": {
            "SessionStart": [
                {"matcher": "^(startup|resume|clear|compact|fork)$", "hooks": [handler]}
            ]
        }
    }


def _worker_command(database, project, host):
    arguments = ["--db", str(database), "--project", project, "--host", host]
    if getattr(sys, "frozen", False):
        return [
            str(runtime_executable()),
            "continuity-bridge",
            "_hook-worker",
            *arguments,
        ]
    return [
        str(runtime_executable()),
        "-I",
        "-c",
        isolated_module_bootstrap(
            "rta_brain.continuity_bridge_cli", Path(__file__).resolve().parents[1]
        ),
        *arguments,
    ]


def bounded_hook(
    database, project, host, *, stdin=None, timeout_seconds=TIMEOUT_SECONDS
):
    if os.environ.get(RECURSION_GUARD):
        return _empty("recursive_invocation")["output"]
    try:
        command = _worker_command(database, project, host)
        with subprocess.Popen(
            command,
            stdin=sys.stdin if stdin is None else stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={**os.environ, RECURSION_GUARD: "1"},
            creationflags=0x08000000 if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        ) as child:
            try:
                stdout, _ = child.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                kill_worker_tree(child)
                child.communicate()
                return _empty("timeout")["output"]
        if child.returncode or len(stdout) > MAX_OUTPUT_BYTES:
            return _empty("unavailable")["output"]
        result = json.loads(stdout.decode("utf-8"))
        if not isinstance(result, dict):
            return _empty("unavailable")["output"]
        return result
    except (ValueError, OSError, subprocess.SubprocessError):
        return _empty("unavailable")["output"]


def _print(value):
    print(json.dumps(value, ensure_ascii=True, separators=(",", ":")))


def dispatch(args):
    if args.bridge_action == "hook":
        _print(bounded_hook(Path(args.db), args.project, args.host))
        return 0
    if args.bridge_action == "_hook-worker":
        return _run_worker(args)
    try:
        if args.bridge_action == "disable":
            result = disable_bridge(Path(args.db), args.project, args.host)
        else:
            options = {
                "database": Path(args.db),
                "project": args.project,
                "host": args.host,
                "root": Path(args.root),
                "selection": {
                    "checkpoint_fields": args.checkpoint_field,
                    "decision_ids": args.decision_id,
                },
                "max_bytes": args.max_bytes,
                "max_age_hours": args.max_age_hours,
            }
            fragment = configuration_fragment(args.db, args.project, args.host)
            result = (
                preview_bridge(**options)
                if args.bridge_action == "plan"
                else enable_bridge(
                    **options,
                    expected_digest=args.expected_digest,
                    allow_model_context=args.allow_model_context,
                )
            )
            result["configuration_fragment"] = fragment
            result["host_configuration_changed"] = False
            result["activation"] = (
                "Review and merge this fragment once; accept host trust and verify in a fresh session."
            )
        _print(result)
        return 0
    except (
        KeyError,
        TypeError,
        ValueError,
        OSError,
        RuntimeError,
        sqlite3.Error,
    ) as exc:
        _print({"state": "error", "error": str(exc)})
        return 1


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _run_worker(args):
    if os.environ.get(RECURSION_GUARD) != "1":
        _print(_empty("invalid_invocation")["output"])
        return 0
    try:
        initialize_worker_containment()
    except OSError:
        _print(_empty("isolation_unavailable")["output"])
        return 0
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("input too large")
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
        _validate_json_shape(record, max_depth=12, max_items=1000)
        result = recall_bridge(
            Path(args.db), args.project, args.host, record, cwd=Path.cwd()
        )["output"]
    except (ValueError, TypeError, OSError, RecursionError, MemoryError):
        result = _empty("invalid_input")["output"]
    _print(result)
    return 0


def worker_main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--host", choices=HOSTS, required=True)
    return _run_worker(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(worker_main())
