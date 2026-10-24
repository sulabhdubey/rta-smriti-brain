"""Synthetic host contracts, not native-agent or model efficacy claims."""

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import pytest

from rta_brain import db


@pytest.fixture
def brain(tmp_path):
    root = tmp_path / "atlas"
    root.mkdir()
    (root / "README.md").write_text("Atlas uses UTC timestamps.\n", encoding="utf-8")
    database = tmp_path / "private" / "brain.sqlite"
    database.parent.mkdir(mode=0o700)
    with closing(db.connect(database)) as conn:
        db.init_project(conn, "atlas", str(root))
        db.ingest_repo(conn, root, project="atlas")
        decision = db.remember(
            conn, "Use UTC timestamps.", project="atlas", memory_type="decision"
        )["memory"]["id"]
        db.remember(
            conn, "Foreign private decision.", project="other", memory_type="decision"
        )
        db.save_checkpoint(
            conn,
            "atlas",
            "Finish timestamp migration",
            remaining_gaps="Check leap-day case",
            next_action="Run focused tests",
        )
    return database, root, decision


def enable(brain, host="codex", **options):
    from rta_brain.continuity_bridge import enable_bridge, preview_bridge

    database, root, decision = brain
    args = {
        "database": database,
        "project": "atlas",
        "root": root,
        "host": host,
        "selection": {
            "checkpoint_fields": ["objective", "remaining_gaps"],
            "decision_ids": [decision],
        },
        "max_bytes": 8192,
        "max_age_hours": 168,
    }
    args.update(options)
    preview = preview_bridge(**args)
    enable_bridge(
        **args, expected_digest=preview["plan_digest"], allow_model_context=True
    )
    return preview


def event(root, **overrides):
    return {
        "hook_event_name": "SessionStart",
        "source": "startup",
        "session_id": "synthetic-session",
        "cwd": str(root),
        "transcript_path": "not-read.jsonl",
        **overrides,
    }


def test_selected_handoff_requires_explicit_host_consent(brain):
    from rta_brain.continuity_bridge import recall_bridge

    database, root, _ = brain
    denied = recall_bridge(database, "atlas", "codex", event(root), cwd=root)
    assert denied["state"] == "not_enabled"
    assert "hookSpecificOutput" not in denied["output"]
    enable(brain)
    with closing(db.connect_readonly(database)) as conn:
        before = conn.total_changes
        result = recall_bridge(database, "atlas", "codex", event(root), cwd=root)
        assert conn.total_changes == before
    assert result["state"] == "prepared"
    text = result["output"]["hookSpecificOutput"]["additionalContext"]
    assert "Finish timestamp migration" in text
    assert "Use UTC timestamps" in text
    assert "Check leap-day case" in text
    assert "Run focused tests" not in text
    assert "Foreign private" not in text
    assert str(root) not in text
    assert "untrusted" in text.lower()
    assert (
        "not_enabled"
        == recall_bridge(database, "atlas", "claude-code", event(root), cwd=root)[
            "state"
        ]
    )


@pytest.mark.parametrize("source", ["startup", "resume", "clear", "compact", "fork"])
@pytest.mark.parametrize("host", ["codex", "claude-code"])
def test_both_host_contracts_keep_repeated_resume_valid(brain, host, source):
    from rta_brain.continuity_bridge import recall_bridge

    database, root, _ = brain
    enable(brain, host)
    with closing(db.connect(database)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        for _ in range(2):
            result = recall_bridge(
                database, "atlas", host, event(root, source=source), cwd=root
            )
            assert result["state"] == "prepared"
            assert result["delivery_verified"] is False
        writer.rollback()


def test_preview_change_and_revocation_fail_closed_with_backup(brain):
    from rta_brain.continuity_bridge import (
        consent_path,
        disable_bridge,
        enable_bridge,
        preview_bridge,
        recall_bridge,
    )

    database, root, decision = brain
    options = {
        "database": database,
        "project": "atlas",
        "root": root,
        "host": "codex",
        "selection": {"checkpoint_fields": ["objective"], "decision_ids": [decision]},
    }
    preview = preview_bridge(**options)
    with pytest.raises(ValueError, match="explicit"):
        enable_bridge(**options, expected_digest=preview["plan_digest"])
    with closing(db.connect(database)) as conn:
        db.save_checkpoint(conn, "atlas", "Corrected objective")
    with pytest.raises(ValueError, match="changed"):
        enable_bridge(
            **options, expected_digest=preview["plan_digest"], allow_model_context=True
        )
    enable(brain)
    path = consent_path(database, "atlas", "codex")
    old = json.loads(path.read_text(encoding="utf-8"))
    disable_bridge(database, "atlas", "codex")
    assert (
        recall_bridge(database, "atlas", "codex", event(root), cwd=root)["state"]
        == "not_enabled"
    )
    backups = list(path.parent.glob("*.backup.json"))
    assert len(backups) == 1
    assert json.loads(backups[0].read_text(encoding="utf-8")) == old


def test_root_host_and_payload_project_cannot_override_grant(brain, tmp_path):
    from rta_brain.continuity_bridge import recall_bridge

    database, root, _ = brain
    enable(brain)
    wrong = tmp_path / "other-root"
    wrong.mkdir()
    assert (
        recall_bridge(database, "atlas", "codex", event(wrong), cwd=wrong)["state"]
        == "scope_mismatch"
    )
    result = recall_bridge(
        database,
        "atlas",
        "codex",
        event(root, project="other", database="other.sqlite"),
        cwd=root,
    )
    assert result["state"] == "prepared"
    assert "Foreign private" not in json.dumps(result)
    assert (
        recall_bridge(
            database,
            "atlas",
            "codex",
            event(root, hook_event_name="PreModelSwitch"),
            cwd=root,
        )["state"]
        == "unsupported_event"
    )


def test_selected_corrections_are_seen_but_private_and_retired_decisions_are_not(brain):
    from rta_brain.continuity_bridge import recall_bridge

    database, root, decision = brain
    enable(brain, "claude-code")
    with closing(db.connect(database)) as conn:
        db.save_checkpoint(conn, "atlas", "Correction: use UTC with explicit offsets")
    result = recall_bridge(database, "atlas", "claude-code", event(root), cwd=root)
    assert "Correction: use UTC" in json.dumps(result)
    with closing(db.connect(database)) as conn:
        conn.execute(
            "UPDATE memories SET metadata_json=? WHERE id=?",
            (json.dumps({"privacy_class": "restricted"}), decision),
        )
        conn.commit()
    result = recall_bridge(database, "atlas", "claude-code", event(root), cwd=root)
    assert result["state"] == "unavailable"
    assert "hookSpecificOutput" not in result["output"]


def test_stale_or_replaced_database_does_not_reuse_consent(brain):
    from rta_brain.continuity_bridge import recall_bridge

    database, root, _ = brain
    enable(brain)
    with closing(db.connect(database)) as conn:
        conn.execute("UPDATE checkpoints SET updated_at='2000-01-01T00:00:00+00:00'")
        conn.commit()
    assert (
        recall_bridge(database, "atlas", "codex", event(root), cwd=root)["state"]
        == "stale_handoff"
    )
    replacement = database.with_suffix(".replacement")
    replacement.write_bytes(database.read_bytes())
    os.replace(replacement, database)
    assert (
        recall_bridge(database, "atlas", "codex", event(root), cwd=root)["state"]
        == "scope_mismatch"
    )


def test_unicode_secrets_large_records_and_duplicates_are_bounded(brain):
    from rta_brain.continuity_bridge import recall_bridge

    database, root, decision = brain
    secret = "sk-" + "z" * 30
    with closing(db.connect(database)) as conn:
        duplicate = db.remember(
            conn, "Use UTC timestamps.", project="atlas", memory_type="decision"
        )["memory"]["id"]
        db.save_checkpoint(
            conn,
            "atlas",
            "\ufeff\u0938\u094d\u092e\u0943\u0924\u093f " + secret,
            remaining_gaps="x" * 10_000,
        )
    enable(
        brain,
        selection={
            "checkpoint_fields": ["objective", "remaining_gaps"],
            "decision_ids": sorted({decision, duplicate}),
        },
        max_bytes=1024,
    )
    result = recall_bridge(database, "atlas", "codex", event(root), cwd=root)
    text = result["output"]["hookSpecificOutput"]["additionalContext"]
    assert len(text.encode("utf-8")) <= 1024
    assert secret not in text
    assert text.count("Use UTC timestamps.") <= 1
    assert "untrusted evidence" in text
    assert '"omitted_records":1' in text


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission-bit contract")
@pytest.mark.parametrize("target", ["directory", "database"])
def test_readable_private_storage_is_rejected_without_changing_permissions(brain, target):
    from rta_brain.continuity_bridge import preview_bridge, recall_bridge

    database, root, _ = brain
    enable(brain)
    assert (
        recall_bridge(database, "atlas", "codex", event(root), cwd=root)["state"]
        == "prepared"
    )
    path = database.parent if target == "directory" else database
    path.chmod(0o755 if target == "directory" else 0o644)
    mode_before = path.stat().st_mode
    bytes_before = database.read_bytes()

    with pytest.raises(PermissionError, match="must be private"):
        preview_bridge(
            database, "atlas", root, "codex", {"checkpoint_fields": ["objective"]}
        )
    rejected = recall_bridge(database, "atlas", "codex", event(root), cwd=root)
    assert rejected["state"] == "unavailable"
    assert "hookSpecificOutput" not in rejected["output"]
    result = run_bridge_process(brain, json.dumps(event(root)).encode())
    assert result.returncode == 0
    assert "hookSpecificOutput" not in json.loads(result.stdout)
    assert str(root).encode() not in result.stdout + result.stderr
    assert path.stat().st_mode == mode_before
    assert database.read_bytes() == bytes_before


def test_cli_parser_routes_bridge_without_database_bootstrap(brain):
    from rta_brain.cli import build_parser

    database, _, _ = brain
    args = build_parser().parse_args(
        [
            "continuity-bridge",
            "hook",
            "--db",
            str(database),
            "--project",
            "atlas",
            "--host",
            "codex",
        ]
    )
    assert args.command == "continuity-bridge"
    assert args.bridge_action == "hook"


def run_bridge_process(
    brain, payload, *, timeout=12, extra_env=None, host="codex", action="hook"
):
    database, root, _ = brain
    command = [
        sys.executable,
        "-I",
        str(Path(__file__).resolve().parents[1] / "rta-brain.py"),
        "continuity-bridge",
        action,
        "--db",
        str(database),
        "--project",
        "atlas",
        "--host",
        host,
    ]
    return subprocess.run(
        command,
        input=payload,
        capture_output=True,
        cwd=root,
        timeout=timeout,
        check=False,
        env={**os.environ, **(extra_env or {})},
        creationflags=0x08000000 if os.name == "nt" else 0,
    )


def test_real_cli_outputs_host_envelope_and_handles_bad_input(brain):
    enable(brain)
    _, root, _ = brain
    for payload in (b"{", b"[]", b"x" * 65_537):
        result = run_bridge_process(brain, payload)
        assert result.returncode == 0
        assert "hookSpecificOutput" not in json.loads(result.stdout)
        assert str(root).encode() not in result.stdout + result.stderr
    result = run_bridge_process(brain, json.dumps(event(root)).encode())
    assert result.returncode == 0
    assert (
        "Finish timestamp migration"
        in json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    )
    nested = run_bridge_process(
        brain, b"{}", extra_env={"RTA_SMIRTI_BRIDGE_ACTIVE": "1"}
    )
    assert "hookSpecificOutput" not in json.loads(nested.stdout)


@pytest.mark.skipif(
    os.name == "nt",
    reason="Windows rejects replacement while SQLite holds the file open",
)
def test_database_replacement_during_preview_is_rejected(brain):
    from rta_brain.continuity_bridge import preview_bridge
    from rta_brain.passport import passport_preview

    database, root, _ = brain

    def replace_after_read(*args, **kwargs):
        result = passport_preview(*args, **kwargs)
        replacement = database.with_suffix(".replacement")
        replacement.write_bytes(database.read_bytes())
        os.replace(replacement, database)
        return result

    with (
        patch("rta_brain.continuity_bridge.passport_preview", replace_after_read),
        pytest.raises(ValueError, match="changed"),
    ):
        preview_bridge(
            database, "atlas", root, "codex", {"checkpoint_fields": ["objective"]}
        )


@pytest.mark.parametrize("target", ["database", "root"])
def test_preview_checks_database_identity_on_both_sides_of_read(brain, target):
    from rta_brain.continuity_bridge import _identity, preview_bridge

    database, root, _ = brain
    calls = []

    def changed_identity(path):
        value = _identity(path)
        if Path(path) == (database if target == "database" else root):
            calls.append(path)
            if len(calls) > 1:
                value[1] += 1
        return value

    with (
        patch("rta_brain.continuity_bridge._identity", changed_identity),
        pytest.raises(ValueError, match="changed"),
    ):
        preview_bridge(
            database, "atlas", root, "codex", {"checkpoint_fields": ["objective"]}
        )


def test_frozen_worker_uses_same_binary_not_foreign_python(brain):
    from rta_brain.continuity_bridge_cli import _worker_command

    database, _, _ = brain
    with patch.object(sys, "frozen", True, create=True):
        command = _worker_command(database, "atlas", "codex")
    assert command[0] == str(Path(sys.executable).resolve())
    assert command[1:3] == ["continuity-bridge", "_hook-worker"]


def test_hanging_stdin_is_killed_and_reaped(brain):
    from rta_brain.continuity_bridge_cli import bounded_hook

    database, _, _ = brain
    enable(brain)
    read_fd, write_fd = os.pipe()
    children = []
    timings = []
    real_popen = subprocess.Popen

    def observe(*args, **kwargs):
        spawning = time.monotonic()
        child = real_popen(*args, **kwargs)
        timings.append(time.monotonic() - spawning)
        children.append(child)
        return child

    started = time.monotonic()
    try:
        with (
            os.fdopen(read_fd, "rb") as reader,
            patch("rta_brain.continuity_bridge_cli.subprocess.Popen", observe),
        ):
            result = bounded_hook(
                database, "atlas", "codex", stdin=reader, timeout_seconds=0.2
            )
    finally:
        os.close(write_fd)
    assert "timeout" in result["systemMessage"]
    elapsed = time.monotonic() - started
    print({"total_seconds": elapsed, "spawn_seconds": timings})
    assert elapsed < 4
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.parametrize(
    "mutation", ["hardlink", "malformed", "future_format", "newer_database_schema"]
)
def test_unsafe_consent_and_schema_fail_without_output(brain, mutation):
    from rta_brain.continuity_bridge import consent_path, recall_bridge

    database, root, _ = brain
    enable(brain)
    path = consent_path(database, "atlas", "codex")
    if mutation == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    elif mutation == "malformed":
        path.write_text("{", encoding="utf-8")
    elif mutation == "future_format":
        value = json.loads(path.read_text(encoding="utf-8"))
        value["format"] = "future"
        path.write_text(json.dumps(value), encoding="utf-8")
    else:
        with closing(db.connect(database)) as conn:
            conn.execute(f"PRAGMA user_version={db.SCHEMA_VERSION + 1}")
    result = recall_bridge(database, "atlas", "codex", event(root), cwd=root)
    assert "hookSpecificOutput" not in result["output"]
    assert str(root) not in json.dumps(result)


def test_hook_json_rejects_duplicate_identity_fields(brain):
    enable(brain)
    _, root, _ = brain
    payload = json.dumps(event(root))[:-1] + ',"cwd":' + json.dumps(str(root)) + "}"
    result = run_bridge_process(brain, payload.encode())
    assert "hookSpecificOutput" not in json.loads(result.stdout)


def test_real_cli_preserves_full_unicode_handoff_within_byte_budget(brain):
    database, root, _ = brain
    objective = "\U0001f4bb" * 3800
    with closing(db.connect(database)) as conn:
        db.save_checkpoint(conn, "atlas", objective)
    enable(brain, selection={"checkpoint_fields": ["objective"]}, max_bytes=16_384)
    result = run_bridge_process(brain, json.dumps(event(root)).encode())
    text = json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    assert objective in text
    assert len(text.encode("utf-8")) <= 16_384


def test_mcp_checkpoint_to_other_host_hook_and_back_without_recall_writes(brain):
    """Real stdio transports with synthetic client labels, not native model turns."""
    from rta_brain.runtime_control import isolated_module_bootstrap

    database, root, _ = brain
    enable(brain, "codex")
    enable(brain, "claude-code")
    for producer, consumer, objective in (
        ("codex", "claude-code", "Codex checkpoint: verify UTC offsets"),
        ("claude-code", "codex", "Claude correction: verify leap-day offsets too"),
    ):
        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "synthetic-" + producer, "version": "1"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "brain_checkpoint",
                    "arguments": {
                        "project": "atlas",
                        "objective": objective,
                        "next_action": "Unselected detail must remain private",
                    },
                },
            },
        ]
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-c",
                isolated_module_bootstrap(
                    "rta_brain.mcp_server", Path(__file__).resolve().parents[1]
                ),
                "--db",
                str(database),
                "--project",
                "atlas",
                "--allow-memory-writes",
            ],
            input="\n".join(map(json.dumps, messages)).encode() + b"\n",
            capture_output=True,
            cwd=root,
            timeout=15,
            check=False,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        assert result.returncode == 0, result.stderr
        replies = {
            row["id"]: row
            for line in result.stdout.splitlines()
            if (row := json.loads(line)).get("id")
        }
        assert "error" not in replies[2]
        assert not replies[2]["result"].get("isError")
        with closing(db.connect_readonly(database)) as conn:
            before = list(conn.iterdump())
        hook = run_bridge_process(
            brain, json.dumps(event(root)).encode(), host=consumer
        )
        context = json.loads(hook.stdout)["hookSpecificOutput"]["additionalContext"]
        assert objective in context
        assert "Unselected detail" not in context
        with closing(db.connect_readonly(database)) as conn:
            assert list(conn.iterdump()) == before


def test_recall_never_uses_write_connector_and_revocation_during_read_wins(brain):
    from rta_brain.continuity_bridge import (
        disable_bridge,
        preview_bridge,
        recall_bridge,
    )

    database, root, _ = brain
    enable(brain)
    with patch(
        "rta_brain.db.connect", side_effect=AssertionError("write connector forbidden")
    ):
        assert (
            recall_bridge(database, "atlas", "codex", event(root), cwd=root)["state"]
            == "prepared"
        )

    def revoke_after_read(*args, **kwargs):
        result = preview_bridge(*args, **kwargs)
        disable_bridge(database, "atlas", "codex")
        return result

    with patch("rta_brain.continuity_bridge.preview_bridge", revoke_after_read):
        result = recall_bridge(database, "atlas", "codex", event(root), cwd=root)
    assert result["state"] == "consent_changed"
    assert "hookSpecificOutput" not in result["output"]


@pytest.mark.parametrize("host", ["codex", "claude-code"])
def test_configuration_fragment_is_quoted_session_start_only_and_not_installed(
    brain, host
):
    from rta_brain.continuity_bridge_cli import configuration_fragment

    database, _, _ = brain
    fragment = configuration_fragment(database, "atlas", host)
    assert set(fragment["hooks"]) == {"SessionStart"}
    handler = fragment["hooks"]["SessionStart"][0]["hooks"][0]
    tokens = shlex.split(handler["command"])
    assert tokens[tokens.index("--db") + 1] == (
        database.as_posix() if os.name == "nt" else str(database)
    )
    assert tokens[-2:] == ["--host", host]
    assert handler["timeout"] == 7
    assert ("commandWindows" in handler) is (os.name == "nt" and host == "codex")
    if os.name == "nt" and host == "codex":
        with pytest.raises(ValueError, match="unsupported"):
            configuration_fragment(database, "bad%NAME%", host)


def test_internal_frozen_dispatch_uses_guard_and_same_protocol(brain):
    enable(brain)
    _, root, _ = brain
    rejected = run_bridge_process(brain, b"{}", action="_hook-worker")
    assert "invalid_invocation" in json.loads(rejected.stdout)["systemMessage"]
    result = run_bridge_process(
        brain,
        json.dumps(event(root)).encode(),
        action="_hook-worker",
        extra_env={"RTA_SMIRTI_BRIDGE_ACTIVE": "1"},
    )
    assert (
        "Finish timestamp migration"
        in json.loads(result.stdout)["hookSpecificOutput"]["additionalContext"]
    )


def test_missing_database_hook_does_not_create_files(tmp_path):
    database = tmp_path / "absent.sqlite"
    result = run_bridge_process(
        (database, tmp_path, None), json.dumps(event(tmp_path)).encode()
    )
    assert result.returncode == 0
    assert "not_enabled" in json.loads(result.stdout)["systemMessage"]
    assert not database.exists()


def test_timeout_also_terminates_a_worker_descendant(tmp_path):
    from rta_brain.continuity_bridge_cli import bounded_hook
    from rta_brain.runtime_control import process_alive

    marker = tmp_path / "owned-helper.pid"
    payload = tmp_path / "payload.json"
    payload.write_bytes(b"{}")
    code = f"""
import sys, time, subprocess
from pathlib import Path
sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})
from rta_brain import continuity_bridge_cli as bridge
def slow_read(*args, **kwargs):
    helper = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags={0x08000000 if os.name == "nt" else 0})
    Path({str(marker)!r}).write_text(str(helper.pid), encoding='ascii')
    time.sleep(30)
bridge.recall_bridge = slow_read
raise SystemExit(bridge.worker_main())
"""
    command = [
        sys.executable,
        "-I",
        "-c",
        code,
        "--db",
        str(tmp_path / "unused.sqlite"),
        "--project",
        "atlas",
        "--host",
        "codex",
    ]
    try:
        with (
            payload.open("rb") as reader,
            patch(
                "rta_brain.continuity_bridge_cli._worker_command", return_value=command
            ),
        ):
            result = bounded_hook(
                tmp_path / "unused.sqlite",
                "atlas",
                "codex",
                stdin=reader,
                timeout_seconds=3,
            )
        assert "timeout" in result["systemMessage"]
        assert marker.exists(), "the worker never reached the helper path"
        helper_pid = int(marker.read_text(encoding="ascii"))
        deadline = time.monotonic() + 1
        while process_alive(helper_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not process_alive(helper_pid), "timed-out worker left its helper alive"
    finally:
        if marker.exists():
            helper_pid = int(marker.read_text(encoding="ascii"))
            if process_alive(helper_pid):
                os.kill(helper_pid, signal.SIGTERM)


def test_containment_failure_does_not_read_project(brain, capsys):
    from argparse import Namespace

    from rta_brain.continuity_bridge_cli import RECURSION_GUARD, _run_worker

    database, _, _ = brain
    with (
        patch.dict(os.environ, {RECURSION_GUARD: "1"}),
        patch(
            "rta_brain.continuity_bridge_cli.initialize_worker_containment",
            side_effect=OSError("denied"),
        ),
        patch(
            "rta_brain.continuity_bridge_cli.recall_bridge",
            side_effect=AssertionError("must not read"),
        ),
    ):
        assert (
            _run_worker(Namespace(db=str(database), project="atlas", host="codex")) == 0
        )
    output = json.loads(capsys.readouterr().out)
    assert "isolation_unavailable" in output["systemMessage"]
    assert "hookSpecificOutput" not in output


def test_real_git_checkout_hook_preserves_canonical_binding(tmp_path):
    from rta_brain.repository import _git_environment, trusted_git_candidates

    candidates = trusted_git_candidates()
    if not candidates:
        pytest.skip("trusted Git executable unavailable")
    root = tmp_path / "git-atlas"
    root.mkdir()
    result = subprocess.run(
        [str(candidates[0]), "init", "--quiet", "--template=", str(root)],
        capture_output=True,
        check=False,
        timeout=10,
        env={
            **_git_environment(),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        },
        creationflags=0x08000000 if os.name == "nt" else 0,
    )
    assert result.returncode == 0, result.stderr
    database = tmp_path / "private" / "brain.sqlite"
    database.parent.mkdir(mode=0o700)
    with closing(db.connect(database)) as conn:
        db.init_project(conn, "atlas", str(root))
        db.save_checkpoint(conn, "atlas", "Git checkout handoff")
    synthetic = (database, root, None)
    enable(synthetic, selection={"checkpoint_fields": ["objective"]})
    output = run_bridge_process(synthetic, json.dumps(event(root)).encode())
    assert (
        "Git checkout handoff"
        in json.loads(output.stdout)["hookSpecificOutput"]["additionalContext"]
    )
