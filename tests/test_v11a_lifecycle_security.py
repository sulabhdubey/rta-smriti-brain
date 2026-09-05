import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from rta_brain import db, trusted_lifecycle
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.trusted_lifecycle import (
    StaleLifecyclePlanError,
    apply_lifecycle,
    plan_lifecycle,
    plan_remove_lifecycle,
    plan_repair_lifecycle,
    remove_lifecycle,
    repair_lifecycle,
)


def _project(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    database = tmp_path / "brains" / "demo.sqlite"
    conn = db.connect(database)
    try:
        db.init_project(conn, "demo", root)
    finally:
        conn.close()
    request = {
        "tool_root": tmp_path,
        "brain_dir": database.parent,
        "db_path": database,
        "project": "demo",
        "root": root,
    }
    return database, root, request


def _confirmation(plan):
    return {
        "approved": True,
        "plan_digest": plan["plan_digest"],
        "observed_state_digest": plan["observed_state_digest"],
    }


def test_existing_older_schema_requires_supervised_migration(tmp_path):
    database, _root, _request = _project(tmp_path)
    raw = sqlite3.connect(database)
    raw.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
    raw.commit()
    raw.close()

    conn = db.connect(database)
    try:
        with pytest.raises(db.SchemaMigrationRequiredError, match="lifecycle"):
            db.init_schema(conn)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION - 1

        db.init_schema(conn, allow_migration=True)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    finally:
        conn.close()


def test_mcp_read_start_does_not_migrate_an_older_brain(tmp_path):
    database, root, _request = _project(tmp_path)
    raw = sqlite3.connect(database)
    raw.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
    raw.commit()
    raw.close()

    with pytest.raises(db.SchemaMigrationRequiredError, match="lifecycle"):
        RtaBrainMcpServer(database, "demo", expected_root=root)

    verify = sqlite3.connect(database)
    try:
        assert verify.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION - 1
    finally:
        verify.close()


def test_current_version_structural_patch_requires_backed_up_lifecycle(tmp_path):
    database, _root, request = _project(tmp_path)
    raw = sqlite3.connect(database)
    raw.execute("DROP TABLE capture_event_content")
    raw.commit()
    raw.close()

    blocked = plan_lifecycle(request, {"schema_policy": "current-only"})
    assert blocked["blocked"] is True
    assert "schema_migration_not_authorized" in blocked["blockers"]

    plan = plan_lifecycle(request, {"schema_policy": "migrate-with-backup"})
    assert [step["operation"] for step in plan["steps"][:3]] == [
        "backup_database",
        "migrate_database",
        "validate_database",
    ]
    result = apply_lifecycle(plan, _confirmation(plan))
    assert result["state"] == "complete"


def test_repair_requires_the_exact_previewed_plan(tmp_path):
    _database, _root, request = _project(tmp_path)
    initial = plan_lifecycle(request, {})
    applied = apply_lifecycle(initial, _confirmation(initial))
    repair_plan = plan_repair_lifecycle(request)

    with pytest.raises(PermissionError, match="plan digest"):
        repair_lifecycle(
            request,
            {
                "approved": True,
                "plan_digest": "0" * 64,
                "desired_state_digest": applied["desired_state_digest"],
                "observed_state_digest": repair_plan["observed_state_digest"],
            },
        )


def test_completed_receipt_replay_rejects_project_health_drift(tmp_path):
    database, _root, request = _project(tmp_path)
    plan = plan_lifecycle(request, {})
    confirmation = _confirmation(plan)
    apply_lifecycle(plan, confirmation)

    raw = sqlite3.connect(database)
    raw.execute("DELETE FROM projects WHERE name = 'demo'")
    raw.commit()
    raw.close()

    with pytest.raises(StaleLifecyclePlanError, match="completed receipt"):
        apply_lifecycle(plan, confirmation)


def test_removed_receipt_replay_rejects_a_restarted_service(tmp_path):
    _database, _root, request = _project(tmp_path)
    initial = plan_lifecycle(request, {})
    apply_lifecycle(initial, _confirmation(initial))
    remove_plan = plan_remove_lifecycle(request)
    confirmation = _confirmation(remove_plan)
    remove_lifecycle(remove_plan, confirmation)

    with patch(
        "rta_brain.trusted_lifecycle.watcher_status",
        return_value={"state": "running"},
    ), pytest.raises(StaleLifecyclePlanError, match="completed receipt"):
        remove_lifecycle(remove_plan, confirmation)


def test_interrupted_removal_is_restored_then_repaired_as_removal(tmp_path):
    _database, _root, request = _project(tmp_path)
    initial = plan_lifecycle(request, {"watcher": False})
    apply_lifecycle(initial, _confirmation(initial))
    remove_plan = plan_remove_lifecycle(request)
    original_write_once = trusted_lifecycle._write_once_json

    def fail_receipt(path, payload):
        if Path(path).parent.name == "receipts":
            raise OSError("receipt publication failed")
        return original_write_once(path, payload)

    with patch(
        "rta_brain.trusted_lifecycle._write_once_json",
        side_effect=fail_receipt,
    ), pytest.raises(OSError, match="receipt publication failed"):
        remove_lifecycle(remove_plan, _confirmation(remove_plan))

    desired_path = trusted_lifecycle._control_root(request) / "desired-state.json"
    assert desired_path.is_file()
    repair_plan = plan_repair_lifecycle(request)
    assert repair_plan["execution_kind"] == "remove"
    result = repair_lifecycle(
        request,
        {
            "approved": True,
            "plan_digest": repair_plan["plan_digest"],
            "desired_state_digest": repair_plan["source_desired_state_digest"],
            "observed_state_digest": repair_plan["observed_state_digest"],
        },
    )

    assert result["state"] == "removed"
    assert not desired_path.exists()


def test_remove_plan_cleans_stale_daemon_control_before_unenrollment(tmp_path):
    _database, _root, request = _project(tmp_path)
    initial = plan_lifecycle(request, {"watcher": False})
    apply_lifecycle(initial, _confirmation(initial))
    observed = trusted_lifecycle.inspect_lifecycle(request)
    observed["services"] = {**observed["services"], "watcher": "stale"}

    with patch.object(trusted_lifecycle, "inspect_lifecycle", return_value=observed):
        plan = plan_remove_lifecycle(request)

    assert plan["blocked"] is False
    assert {step["operation"] for step in plan["steps"]} >= {"stop_watcher"}


def test_remove_plan_blocks_live_daemon_with_unverifiable_authority(tmp_path):
    _database, _root, request = _project(tmp_path)
    initial = plan_lifecycle(request, {"watcher": False})
    apply_lifecycle(initial, _confirmation(initial))
    observed = trusted_lifecycle.inspect_lifecycle(request)
    observed["services"] = {
        **observed["services"],
        "watcher": "live-unverifiable",
    }

    with patch.object(trusted_lifecycle, "inspect_lifecycle", return_value=observed):
        plan = plan_remove_lifecycle(request)

    assert plan["blocked"] is True
    assert "watcher_authority_uncertain" in plan["blockers"]
    assert "stop_watcher" not in {
        step["operation"] for step in plan["steps"]
    }
