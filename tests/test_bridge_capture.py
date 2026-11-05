import hashlib
import json
from contextlib import closing
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from rta_brain import db
from rta_brain.capture import register_policy, register_source
from rta_brain.capture_daemon import (
    CAPTURE_INGRESS_FIELDS,
    capture_cycle,
    prepare_capture_spool_record,
)
from rta_brain.capture_spool import CaptureSpool
from rta_brain.capture_types import CapturePolicy, CaptureSource
from rta_brain.continuity_bridge import enable_bridge, preview_bridge, recall_bridge


@pytest.fixture
def captured_brain(tmp_path):
    root = tmp_path / "atlas"
    root.mkdir()
    database = tmp_path / "private" / "brain.sqlite"
    database.parent.mkdir(mode=0o700)
    with closing(db.connect(database)) as conn:
        db.init_project(conn, "atlas", str(root))
        policy = CapturePolicy.continuity()
        register_policy(
            conn,
            project="atlas",
            active_root=root,
            policy_id="flow",
            policy_version=1,
            policy=policy,
        )
        for source in ("flow-codex", "flow-claude", "unselected"):
            register_source(
                conn,
                project="atlas",
                active_root=root,
                source=CaptureSource(
                    source_id=source,
                    adapter="generic",
                    adapter_version="1",
                    installation_scope="api",
                    config_fingerprint=hashlib.sha256(source.encode()).hexdigest(),
                ),
                policy_digest=policy.digest,
            )
    return database, root


def capture(brain, source, sequence, text):
    database, root = brain
    with closing(db.connect(database)) as conn:
        prepared = prepare_capture_spool_record(
            conn,
            project="atlas",
            active_root=root,
            source_id=source,
            record={
                "source_cursor": str(sequence),
                "cursor_kind": "sequence",
                "session_id": "synthetic-session",
                "observed_at": datetime.now(UTC).isoformat(),
                "vendor_event": "agent.message",
                "payload": {"text": text},
            },
            original_bytes=len(text.encode()),
        )
        CaptureSpool(database).publish(
            source, prepared, project="atlas", allowed_fields=CAPTURE_INGRESS_FIELDS
        )
        return capture_cycle(conn, database, max_events=10, max_seconds=1)


def test_new_brain_can_consent_before_capture_then_recall_only_selected_future_events(
    captured_brain,
):
    database, root = captured_brain
    capture(captured_brain, "flow-codex", 1, "Do not backfill this older text")
    with closing(db.connect_readonly(database)) as conn:
        before = conn.execute(
            "SELECT MAX(project_sequence) FROM capture_events"
        ).fetchone()[0]
    options = {
        "database": database,
        "root": root,
        "project": "atlas",
        "host": "claude-code",
        "selection": {
            "capture_sources": ["flow-codex", "flow-claude"],
            "capture_after_sequence": before,
        },
    }
    preview = preview_bridge(**options)
    assert preview["context"] is None
    enable_bridge(
        **options, expected_digest=preview["plan_digest"], allow_model_context=True
    )
    event = {
        "hook_event_name": "SessionStart",
        "source": "startup",
        "session_id": "new-session",
        "cwd": str(root),
    }
    assert (
        recall_bridge(database, "atlas", "claude-code", event, cwd=root)["state"]
        == "waiting_for_capture"
    )

    capture(captured_brain, "unselected", 1, "Never send this unrelated stream")
    capture(captured_brain, "flow-codex", 2, "Use UTC timestamps; tests have not run")
    result = recall_bridge(database, "atlas", "claude-code", event, cwd=root)
    assert result["state"] == "prepared"
    text = result["output"]["hookSpecificOutput"]["additionalContext"]
    assert "Use UTC timestamps" in text
    assert "unverified" in text
    assert "older text" not in text
    assert "unrelated stream" not in text
    assert result["database_writes"] is False
    assert result["delivery_verified"] is False


def test_capture_recall_works_while_a_writer_is_active(captured_brain):
    database, root = captured_brain
    options = {
        "database": database,
        "root": root,
        "project": "atlas",
        "host": "codex",
        "selection": {"capture_sources": ["flow-claude"], "capture_after_sequence": 0},
    }
    preview = preview_bridge(**options)
    enable_bridge(
        **options, expected_digest=preview["plan_digest"], allow_model_context=True
    )
    capture(captured_brain, "flow-claude", 1, "Current handoff")
    with closing(db.connect(database)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        try:
            result = recall_bridge(
                database,
                "atlas",
                "codex",
                {
                    "hook_event_name": "SessionStart",
                    "source": "resume",
                    "session_id": "resume",
                    "cwd": str(root),
                },
                cwd=root,
            )
        finally:
            writer.rollback()
    assert result["state"] == "prepared", json.dumps(result)


@pytest.mark.parametrize("change", ["deleted", "expired", "tampered"])
def test_capture_recall_never_returns_deleted_expired_or_corrupt_content(
    captured_brain, change
):
    from rta_brain.capture import delete_capture_content

    database, root = captured_brain
    capture(captured_brain, "flow-codex", 1, "Remove this private observation")
    options = {
        "database": database,
        "root": root,
        "project": "atlas",
        "host": "claude-code",
        "selection": {"capture_sources": ["flow-codex"], "capture_after_sequence": 0},
    }
    preview = preview_bridge(**options)
    enable_bridge(
        **options, expected_digest=preview["plan_digest"], allow_model_context=True
    )
    if change == "deleted":
        with closing(db.connect(database)) as conn:
            event_id = conn.execute("SELECT event_id FROM capture_events").fetchone()[0]
            args = {
                "project": "atlas",
                "active_root": root,
                "scope": "event-content",
                "scope_token": event_id,
                "reason_class": "operator-request",
                "actor_id": "operator-test",
                "policy_digest": CapturePolicy.continuity().digest,
            }
            plan = delete_capture_content(conn, **args)
            delete_capture_content(
                conn,
                **args,
                confirm=True,
                confirmation_token=plan["confirmation_token"],
            )
    if change == "tampered":
        with closing(db.connect(database)) as conn:
            conn.execute("UPDATE capture_event_content SET content_json='{}'")
            conn.commit()
    with patch("rta_brain.capture.datetime", wraps=datetime) as clock:
        clock.now.return_value = datetime.now(UTC) + (
            timedelta(days=31) if change == "expired" else timedelta()
        )
        result = recall_bridge(
            database,
            "atlas",
            "claude-code",
            {
                "hook_event_name": "SessionStart",
                "source": "resume",
                "session_id": "new",
                "cwd": str(root),
            },
            cwd=root,
        )
    assert "Remove this private observation" not in json.dumps(result)
    assert result["state"] != "prepared"


def test_capture_only_preview_rejects_old_schema_without_migration(captured_brain):
    database, root = captured_brain
    with closing(db.connect(database)) as conn:
        conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
    with pytest.raises(ValueError, match="schema"):
        preview_bridge(
            database, "atlas", root, "codex", {"capture_sources": ["flow-codex"]}
        )
    with closing(db.connect_readonly(database)) as conn:
        assert (
            conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION - 1
        )
