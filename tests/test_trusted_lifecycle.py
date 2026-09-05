import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from rta_brain import db, trusted_lifecycle
from rta_brain.cli import lifecycle_authority_environment
from rta_brain.mcp_host_lifecycle import (
    apply_host_configuration,
    issue_fresh_session_challenge,
    plan_host_configuration,
)
from rta_brain.mcp_server import RtaBrainMcpServer
from rta_brain.onboarding import supervise_brain
from rta_brain.review_bundle import write_review_bundle
from rta_brain.sdk import BrainClient
from rta_brain.trusted_lifecycle import (
    LifecycleOperationInProgressError,
    StaleLifecyclePlanError,
    apply_lifecycle,
    attach_lifecycle_mcp_proof,
    inspect_lifecycle,
    lifecycle_review_bundle,
    plan_lifecycle,
    plan_remove_lifecycle,
    plan_repair_lifecycle,
    plan_stop_lifecycle,
    remove_lifecycle,
    repair_lifecycle,
    stop_lifecycle,
    verify_lifecycle,
)


class TrustedLifecycleTests(unittest.TestCase):
    def setUp(self):
        self._authority_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self._authority_directory.cleanup)
        authority_patch = patch(
            "rta_brain.mcp_host_lifecycle._host_authority_root",
            return_value=Path(self._authority_directory.name),
        )
        authority_patch.start()
        self.addCleanup(authority_patch.stop)

    def test_plan_binds_every_execution_authority_without_exposing_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            sessions = base / "sessions"
            sessions.mkdir()
            home = base / "home"
            home.mkdir()
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base / "tool",
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": sessions,
                "platform_name": "win32",
                "home": home,
                "environment": {
                    "APPDATA": str(home / "AppData" / "Roaming"),
                    "PRIVATE_SENTINEL": "must-not-leak",
                },
            }
            plan = plan_lifecycle(request, {"schema_policy": "inspect-only"})
            serialized = json.dumps(plan, sort_keys=True)

            self.assertEqual(len(plan["execution_context_digest"]), 64)
            for secret in (
                str(request["tool_root"]),
                str(database.parent),
                str(database),
                str(root),
                str(sessions),
                str(home),
                "must-not-leak",
            ):
                self.assertNotIn(secret, serialized)

            substitutions = {
                "tool_root": base / "other-tool",
                "brain_dir": base / "other-brains",
                "db_path": base / "other.sqlite",
                "root": base / "other-root",
                "sessions_root": base / "other-sessions",
                "home": base / "other-home",
                "platform_name": "linux",
                "environment": {"APPDATA": "elsewhere"},
            }
            for field, value in substitutions.items():
                with self.subTest(field=field):
                    substituted = trusted_lifecycle.LifecyclePlan(
                        dict(plan), request
                    )
                    substituted._request[field] = value
                    with self.assertRaisesRegex(
                        PermissionError, "execution context"
                    ):
                        apply_lifecycle(
                            substituted,
                            {
                                "approved": True,
                                "plan_digest": plan["plan_digest"],
                                "observed_state_digest": plan[
                                    "observed_state_digest"
                                ],
                            },
                        )

    def test_post_migration_service_failure_never_restores_committed_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
                conn.commit()
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(
                request,
                {
                    "watcher": True,
                    "capture": True,
                    "schema_policy": "migrate-with-backup",
                },
            )

            def start_writer(*_args, **_kwargs):
                connection = sqlite3.connect(database)
                try:
                    connection.execute("CREATE TABLE post_migration_write(value TEXT)")
                    connection.execute(
                        "INSERT INTO post_migration_write(value) VALUES ('durable')"
                    )
                    connection.commit()
                finally:
                    connection.close()
                return {"state": "running"}

            with (
                patch(
                    "rta_brain.trusted_lifecycle.start_watcher",
                    side_effect=start_writer,
                ),
                patch(
                    "rta_brain.trusted_lifecycle.start_capture",
                    side_effect=RuntimeError("capture failed"),
                ),
                patch(
                    "rta_brain.trusted_lifecycle.stop_watcher",
                    return_value={"state": "stopped"},
                ),
            ):
                result = apply_lifecycle(
                    plan,
                    {
                        "approved": True,
                        "plan_digest": plan["plan_digest"],
                        "observed_state_digest": plan["observed_state_digest"],
                    },
                )

            self.assertEqual(result["state"], "failed")
            self.assertEqual(result["migration_phase"], "committed")
            self.assertNotIn(
                "restore_database_backup",
                [item["operation"] for item in result["compensations"]],
            )
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    db.SCHEMA_VERSION,
                )
                self.assertEqual(
                    connection.execute(
                        "SELECT value FROM post_migration_write"
                    ).fetchone()[0],
                    "durable",
                )
            finally:
                connection.close()

    def test_backup_is_no_clobber_digest_verified_and_retryable_after_interruption(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            backup = base / "control" / "backup.sqlite"
            selected = {
                "db_path": database,
                "backup_path": backup,
                "project": "demo",
                "root": root,
            }

            with patch(
                "rta_brain.trusted_lifecycle.sqlite3.connect",
                side_effect=sqlite3.OperationalError("backup interrupted"),
            ), self.assertRaisesRegex(sqlite3.OperationalError, "backup interrupted"):
                trusted_lifecycle._run_service_operation(
                    "backup_database", selected
                )
            self.assertEqual(list(backup.parent.glob("*.partial-*")), [])

            with patch(
                "rta_brain.trusted_lifecycle.os.link",
                side_effect=OSError("publish interrupted"),
            ), self.assertRaisesRegex(OSError, "publish interrupted"):
                trusted_lifecycle._run_service_operation(
                    "backup_database", selected
                )
            self.assertFalse(backup.exists())
            self.assertEqual(list(backup.parent.glob("*.partial-*")), [])

            result = trusted_lifecycle._run_service_operation(
                "backup_database", selected
            )
            self.assertEqual(len(result["backup_digest"]), 64)
            original = backup.read_bytes()
            backup.write_bytes(original + b"tampered")
            selected["backup_digest"] = result["backup_digest"]
            with self.assertRaisesRegex(RuntimeError, "digest"):
                trusted_lifecycle._run_service_operation(
                    "restore_database_backup", selected
                )

    def test_publication_failure_remains_recovery_required_with_desired_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {})
            with patch(
                "rta_brain.trusted_lifecycle._write_once_json",
                side_effect=OSError("receipt publication failed"),
            ), self.assertRaisesRegex(OSError, "receipt publication failed"):
                apply_lifecycle(
                    plan,
                    {
                        "approved": True,
                        "plan_digest": plan["plan_digest"],
                        "observed_state_digest": plan["observed_state_digest"],
                    },
                )

            snapshot = inspect_lifecycle(request)
            self.assertEqual(snapshot["enrollment_state"], "recovery_required")
            self.assertIn("interrupted_operation_pending", snapshot["reason_codes"])
            recovery = trusted_lifecycle._recoverable_journal(
                trusted_lifecycle._control_root(request)
            )
            self.assertIsNotNone(recovery)
            self.assertEqual(recovery[1]["state"], "interrupted")
            self.assertEqual(recovery[1]["publication_phase"], "desired_written")

    def test_desired_state_publication_failure_preserves_recovery_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {})
            original_write = trusted_lifecycle.write_json

            def fail_desired(path, payload, *, label):
                if Path(path).name == "desired-state.json":
                    raise OSError("desired publication failed")
                return original_write(path, payload, label=label)

            with patch(
                "rta_brain.trusted_lifecycle.write_json",
                side_effect=fail_desired,
            ), self.assertRaisesRegex(OSError, "desired publication failed"):
                apply_lifecycle(
                    plan,
                    {
                        "approved": True,
                        "plan_digest": plan["plan_digest"],
                        "observed_state_digest": plan["observed_state_digest"],
                    },
                )

            snapshot = inspect_lifecycle(request)
            self.assertEqual(snapshot["enrollment_state"], "recovery_required")
            self.assertIn("interrupted_operation_pending", snapshot["reason_codes"])
            self.assertEqual(snapshot["desired_state"], plan["desired_state"])
            self.assertFalse(
                (
                    trusted_lifecycle._control_root(request)
                    / "desired-state.json"
                ).exists()
            )
            recovery = trusted_lifecycle._recoverable_journal(
                trusted_lifecycle._control_root(request)
            )
            self.assertIsNotNone(recovery)
            self.assertEqual(recovery[1]["state"], "interrupted")
            self.assertEqual(recovery[1]["publication_phase"], "pending")

    def test_stop_and_remove_require_exact_previewed_plan_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            initial = plan_lifecycle(request, {})
            applied = apply_lifecycle(
                initial,
                {
                    "approved": True,
                    "plan_digest": initial["plan_digest"],
                    "observed_state_digest": initial["observed_state_digest"],
                },
            )

            stop_plan = plan_stop_lifecycle(request)
            self.assertEqual(stop_plan["execution_kind"], "stop")
            with self.assertRaisesRegex(PermissionError, "plan digest"):
                stop_lifecycle(
                    stop_plan,
                    {
                        "approved": True,
                        "plan_digest": "0" * 64,
                        "observed_state_digest": stop_plan[
                            "observed_state_digest"
                        ],
                    },
                )
            stopped = stop_lifecycle(
                stop_plan,
                {
                    "approved": True,
                    "plan_digest": stop_plan["plan_digest"],
                    "observed_state_digest": stop_plan["observed_state_digest"],
                },
            )
            self.assertEqual(stopped["state"], "complete")

            remove_plan = plan_remove_lifecycle(request)
            self.assertEqual(remove_plan["execution_kind"], "remove")
            self.assertEqual(
                remove_plan["source_desired_state_digest"],
                stopped["desired_state_digest"],
            )
            removed = remove_lifecycle(
                remove_plan,
                {
                    "approved": True,
                    "plan_digest": remove_plan["plan_digest"],
                    "observed_state_digest": remove_plan[
                        "observed_state_digest"
                    ],
                },
            )
            self.assertEqual(removed["state"], "removed")
            self.assertFalse(
                (Path(applied["receipt_path"]).parents[1] / "desired-state.json").exists()
            )

    def test_inspection_uses_canonical_operational_readiness_for_every_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                db.save_checkpoint(conn, "demo", "Continue from verified evidence")
            finally:
                conn.close()

            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": base / "sessions",
            }
            healthy_integrity = {"operationally_ready": True}
            healthy_reconciliation = {"conflict_count": 0, "conflicts": []}
            healthy_temporal = {
                "ledger_intact": True,
                "high_impact_contradiction_count": 0,
                "failed_critical_validator_count": 0,
                "expired_accepted_claim_count": 0,
            }
            blockers = {
                "no_structured_checkpoint": {"checkpoint": None},
                "work_state_conflicts": {
                    "reconciliation": {
                        "conflict_count": 1,
                        "conflicts": [{"type": "accepted_file_missing"}],
                    }
                },
                "project_integrity": {
                    "integrity": {"operationally_ready": False}
                },
                "truth_ledger_integrity": {
                    "temporal": {**healthy_temporal, "ledger_intact": False}
                },
                "truth_contradictions": {
                    "temporal": {
                        **healthy_temporal,
                        "high_impact_contradiction_count": 1,
                    }
                },
                "truth_validator_failures": {
                    "temporal": {
                        **healthy_temporal,
                        "failed_critical_validator_count": 1,
                    }
                },
                "truth_expired_accepted_claims": {
                    "temporal": {
                        **healthy_temporal,
                        "expired_accepted_claim_count": 1,
                    }
                },
            }

            for reason, overrides in blockers.items():
                with self.subTest(reason=reason), ExitStack() as stack:
                    stack.enter_context(
                        patch(
                            "rta_brain.continuity.latest_checkpoint",
                            return_value=overrides.get("checkpoint", {"source": "operator"}),
                        )
                    )
                    stack.enter_context(
                        patch(
                            "rta_brain.continuity.reconcile_work_items",
                            return_value=overrides.get(
                                "reconciliation", healthy_reconciliation
                            ),
                        )
                    )
                    stack.enter_context(
                        patch(
                            "rta_brain.continuity.integrity_diagnostics",
                            return_value=overrides.get("integrity", healthy_integrity),
                        )
                    )
                    stack.enter_context(
                        patch(
                            "rta_brain.continuity.temporal_readiness",
                            return_value=overrides.get("temporal", healthy_temporal),
                        )
                    )

                    snapshot = inspect_lifecycle(request)

                continuation = snapshot["health_axes"]["continuation_health"]
                self.assertFalse(continuation["manual_continuation_ready"])
                self.assertIn(reason, continuation["readiness_reason_codes"])

            active_request = {
                **request,
                "active_external_work": {"state": "running", "count": 1},
            }
            with patch(
                "rta_brain.continuity.latest_checkpoint",
                return_value={"source": "operator"},
            ), patch(
                "rta_brain.continuity.reconcile_work_items",
                return_value=healthy_reconciliation,
            ), patch(
                "rta_brain.continuity.integrity_diagnostics",
                return_value=healthy_integrity,
            ), patch(
                "rta_brain.continuity.temporal_readiness",
                return_value=healthy_temporal,
            ):
                active_snapshot = inspect_lifecycle(active_request)

            active_continuation = active_snapshot["health_axes"][
                "continuation_health"
            ]
            self.assertFalse(active_continuation["manual_continuation_ready"])
            self.assertIn(
                "active_external_work",
                active_continuation["readiness_reason_codes"],
            )

    def test_inspection_and_plan_are_read_only_deterministic_and_axis_based(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                db.save_checkpoint(conn, "demo", "Continue from verified evidence")
            finally:
                conn.close()

            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": base / "sessions",
            }
            desired = {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "inspect-only",
            }
            before = sorted(str(path.relative_to(base)) for path in base.rglob("*"))

            first_snapshot = inspect_lifecycle(request)
            first_plan = plan_lifecycle(request, desired)
            second_snapshot = inspect_lifecycle(request)
            second_plan = plan_lifecycle(request, desired)
            after = sorted(str(path.relative_to(base)) for path in base.rglob("*"))

            self.assertEqual(before, after)
            self.assertEqual(first_snapshot["observed_state_digest"], second_snapshot["observed_state_digest"])
            self.assertEqual(first_plan["plan_digest"], second_plan["plan_digest"])
            self.assertEqual(first_plan["observed_state_digest"], first_snapshot["observed_state_digest"])
            self.assertEqual(
                set(first_snapshot["health_axes"]),
                {
                    "database_health",
                    "project_integrity",
                    "capture_health",
                    "continuation_health",
                    "mcp_health",
                    "federation_health",
                },
            )
            self.assertEqual(first_snapshot["health_axes"]["database_health"]["state"], "healthy")
            self.assertTrue(
                first_snapshot["health_axes"]["continuation_health"][
                    "manual_continuation_ready"
                ]
            )
            self.assertEqual(first_snapshot["health_axes"]["federation_health"]["state"], "not_configured")
            self.assertEqual(first_plan["steps"], [])
            self.assertTrue(first_plan["read_only"])

    def test_apply_rejects_a_stale_plan_before_writing_a_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            rebound = base / "rebound"
            root.mkdir()
            rebound.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": base / "sessions",
            }
            plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "inspect-only",
            })
            conn = db.connect(database)
            try:
                conn.execute(
                    "UPDATE projects SET root_path = ? WHERE name = ?",
                    (str(rebound), "demo"),
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(StaleLifecyclePlanError, "observed state changed"):
                apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })

            self.assertFalse((database.parent / ".rta-smriti-lifecycle").exists())

    def test_apply_writes_private_receipt_and_replays_without_duplicate_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            sessions = base / "sessions"
            root.mkdir()
            sessions.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": sessions,
            }
            plan = plan_lifecycle(request, {
                "watcher": True,
                "capture": True,
                "continuity": True,
                "console": True,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })
            confirmation = {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            }

            running = {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
            }

            def start(service):
                running[service] = True
                return {"state": "running"}

            with (
                patch("rta_brain.trusted_lifecycle.watcher_status", side_effect=lambda *_args: {"state": "running" if running["watcher"] else "stopped"}),
                patch("rta_brain.trusted_lifecycle.capture_status", side_effect=lambda *_args: {"state": "running" if running["capture"] else "stopped"}),
                patch("rta_brain.trusted_lifecycle.continuity_status", side_effect=lambda *_args: {"state": "running" if running["continuity"] else "stopped"}),
                patch("rta_brain.trusted_lifecycle.console_status", side_effect=lambda *_args: {"state": "running" if running["console"] else "stopped"}),
                patch("rta_brain.trusted_lifecycle.start_watcher", side_effect=lambda *_args, **_kwargs: start("watcher")) as watcher,
                patch("rta_brain.trusted_lifecycle.start_capture", side_effect=lambda *_args, **_kwargs: start("capture")) as capture,
                patch("rta_brain.trusted_lifecycle.start_continuity", side_effect=lambda *_args, **_kwargs: start("continuity")) as continuity,
                patch("rta_brain.trusted_lifecycle.start_console", side_effect=lambda *_args, **_kwargs: start("console")) as console,
            ):
                first = apply_lifecycle(plan, confirmation)
                second = apply_lifecycle(plan, confirmation)

            self.assertEqual(first["state"], "complete")
            self.assertTrue(second["idempotent_replay"])
            self.assertEqual(first["operation_id"], second["operation_id"])
            watcher.assert_called_once()
            capture.assert_called_once()
            continuity.assert_called_once()
            console.assert_called_once()
            receipt_path = Path(first["receipt_path"])
            self.assertTrue(receipt_path.is_file())
            self.assertTrue((receipt_path.parents[1] / "desired-state.json").is_file())
            self.assertNotIn(str(root), str(first))
            self.assertNotIn(str(database), str(first))
            observed = inspect_lifecycle(request)
            self.assertEqual(observed["desired_state"], plan["desired_state"])
            self.assertEqual(
                observed["desired_state_digest"], first["desired_state_digest"]
            )

    def test_lifecycle_rejects_unknown_mcp_host_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            with self.assertRaisesRegex(ValueError, "unsupported MCP host profile"):
                plan_lifecycle(
                    {
                        "tool_root": base,
                        "brain_dir": database.parent,
                        "db_path": database,
                        "project": "demo",
                        "root": root,
                    },
                    {"mcp_hosts": ["invented-host"]},
                )

    def test_fresh_session_mcp_proof_satisfies_configured_host_axis(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "atlas-demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "atlas-demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {"mcp_hosts": ["zed"]})
            applied = apply_lifecycle(plan, {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            })
            target = base / ".config" / "zed" / "settings.json"
            host_plan = plan_host_configuration(
                "zed",
                target,
                "rta-smriti",
                {"command": "python", "args": ["-m", "rta_brain.mcp_server"]},
            )
            host_receipt = apply_host_configuration(
                host_plan,
                {"approved": True, "plan_digest": host_plan["plan_digest"]},
            )
            confirmation = {
                "approved": True,
                "configuration_plan_digest": host_plan["plan_digest"],
            }
            challenge = issue_fresh_session_challenge(
                Path(host_receipt["receipt_path"]), confirmation
            )
            server = RtaBrainMcpServer(
                database,
                "atlas-demo",
                expected_root=root,
                host_proof_receipt=Path(host_receipt["receipt_path"]),
                host_proof_challenge_token=challenge["challenge_token"],
            )
            server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "clientInfo": {"name": "zed", "version": "2026.09"},
                    },
                }
            )
            server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "brain_capabilities", "arguments": {}},
                }
            )
            server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "brain_search",
                        "arguments": {"query": "Atlas architecture"},
                    },
                }
            )

            proof = attach_lifecycle_mcp_proof(
                request,
                Path(host_receipt["receipt_path"]),
                {"challenge_token": challenge["challenge_token"]},
                {
                    "approved": True,
                    "desired_state_digest": applied["desired_state_digest"],
                    "configuration_plan_digest": host_plan["plan_digest"],
                },
            )
            snapshot = inspect_lifecycle(request)
            verified = verify_lifecycle(request, "fresh-session")

            self.assertEqual(proof["state"], "protocol_verified")
            self.assertEqual(
                snapshot["health_axes"]["mcp_health"]["state"],
                "protocol_verified",
            )
            self.assertEqual(
                snapshot["health_axes"]["mcp_health"]["verified_host_count"], 0
            )
            self.assertEqual(
                snapshot["health_axes"]["mcp_health"][
                    "protocol_verified_host_count"
                ],
                1,
            )
            self.assertFalse(verified["ready"])
            self.assertIn(
                "mcp_host_verification_unproven", verified["reason_codes"]
            )
            self.assertNotIn(challenge["challenge_token"], json.dumps(proof))

            payload = json.loads(target.read_text(encoding="utf-8"))
            payload["context_servers"]["rta-smriti"]["args"].append("--drifted")
            target.write_text(json.dumps(payload), encoding="utf-8")

            drifted = verify_lifecycle(request, "fresh-session")
            self.assertFalse(drifted["ready"])
            self.assertEqual(
                drifted["health_axes"]["mcp_health"]["state"],
                "configuration_drifted",
            )
            self.assertIn("mcp_configuration_drifted", drifted["reason_codes"])

    def test_repair_restarts_drifted_service_instead_of_replaying_old_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            desired = {
                "watcher": True,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            }
            plan = plan_lifecycle(request, desired)
            with patch(
                "rta_brain.trusted_lifecycle.start_watcher",
                return_value={"state": "running"},
            ) as start_watcher:
                applied = apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })
                observed = inspect_lifecycle(request)
                self.assertEqual(observed["status"], "attention_required")
                self.assertEqual(observed["enrollment_state"], "configured")
                self.assertIn(
                    "watcher_state_mismatch", observed["reason_codes"]
                )
                repair_plan = plan_repair_lifecycle(request)
                repaired = repair_lifecycle(request, {
                    "approved": True,
                    "plan_digest": repair_plan["plan_digest"],
                    "desired_state_digest": applied["desired_state_digest"],
                    "observed_state_digest": repair_plan["observed_state_digest"],
                })

            self.assertEqual(repaired["state"], "complete")
            self.assertFalse(repaired["idempotent_replay"])
            self.assertNotEqual(applied["operation_id"], repaired["operation_id"])
            self.assertEqual(start_watcher.call_count, 2)

    def test_apply_compensates_completed_steps_and_records_partial_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {
                "watcher": True,
                "capture": True,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })
            confirmation = {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            }

            with (
                patch("rta_brain.trusted_lifecycle.start_watcher", return_value={"state": "running"}),
                patch("rta_brain.trusted_lifecycle.start_capture", side_effect=RuntimeError("capture failed")),
                patch("rta_brain.trusted_lifecycle.stop_capture", return_value={"state": "stopped"}),
                patch("rta_brain.trusted_lifecycle.stop_watcher", return_value={"state": "stopped"}) as stop_watcher,
            ):
                receipt = apply_lifecycle(plan, confirmation)

            self.assertEqual(receipt["status"], "error")
            self.assertEqual(receipt["state"], "failed")
            self.assertEqual(receipt["error_class"], "RuntimeError")
            self.assertEqual(receipt["rollback_state"], "complete")
            self.assertEqual(receipt["compensations"], [
                {
                    "operation": "stop_capture",
                    "state": "complete",
                    "observed_service_state": "stopped",
                },
                {
                    "operation": "stop_watcher",
                    "state": "complete",
                    "observed_service_state": "stopped",
                },
            ])
            stop_watcher.assert_called_once()
            self.assertTrue(Path(receipt["receipt_path"]).is_file())
            self.assertFalse((Path(receipt["receipt_path"]).parents[1] / "desired-state.json").exists())

    def test_operation_claim_blocks_concurrent_lifecycle_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {"watcher": True})
            control = trusted_lifecycle._control_root(request)
            trusted_lifecycle._write_operation_claim(
                control / "operation.lock",
                {"operation_id": "other-operation", "pid": os.getpid()},
            )

            with self.assertRaisesRegex(
                LifecycleOperationInProgressError, "already in progress"
            ):
                apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })

    def test_reused_pid_does_not_preserve_a_stale_operation_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {})
            control = trusted_lifecycle._control_root(request)
            trusted_lifecycle._write_operation_claim(
                control / "operation.lock",
                {
                    "operation_id": "stale-operation",
                    "pid": os.getpid(),
                    "process_identity": "stale-process-birth",
                },
            )

            result = apply_lifecycle(
                plan,
                {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                },
            )

            self.assertEqual(result["state"], "complete")
            self.assertFalse((control / "operation.lock").exists())

    def test_review_bundle_and_sdk_expose_path_free_lifecycle_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {})
            apply_lifecycle(plan, {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            })

            bundle = lifecycle_review_bundle(request)
            client = BrainClient(database, "demo", root)
            sdk_snapshot = client.lifecycle_inspect()
            sdk_plan = client.lifecycle_plan({})

            self.assertEqual(bundle["status"], "ok")
            self.assertEqual(bundle["receipt_count"], 1)
            self.assertEqual(len(bundle["bundle_digest"]), 64)
            self.assertEqual(sdk_snapshot["contract_version"], "1.0")
            self.assertTrue(sdk_plan["read_only"])
            serialized = json.dumps({"bundle": bundle, "sdk": sdk_snapshot})
            self.assertNotIn(str(root), serialized)
            self.assertNotIn(str(database), serialized)

    def test_review_bundle_exports_versioned_json_and_markdown_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                db.save_checkpoint(conn, "demo", "Continue from verified evidence")
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            bundle = lifecycle_review_bundle(
                request,
                audience="release-reviewer",
                privacy_ceiling="internal",
                evidence_references=[
                    {
                        "kind": "qualification",
                        "reference": "receipt:operator-proof",
                        "digest": "a" * 64,
                    }
                ],
                redaction_manifest=[
                    {"field": "local_paths", "action": "fingerprinted"}
                ],
            )
            output = write_review_bundle(
                bundle,
                base / "review" / "v1-1a",
                formats=("json", "markdown"),
            )

            json_path = Path(output["files"]["json"])
            markdown_path = Path(output["files"]["markdown"])
            exported = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertEqual(
                exported["summary_authority"], "non_authoritative"
            )
            self.assertEqual(exported["audience"], "release-reviewer")
            self.assertEqual(exported["privacy_ceiling"], "internal")
            self.assertEqual(len(exported["bundle_digest"]), 64)
            self.assertEqual(
                exported["evidence_reference_manifest"][0]["reference"],
                "receipt:operator-proof",
            )
            self.assertIn("Non-authoritative operational summary", markdown)
            self.assertIn("receipt:operator-proof", markdown)
            serialized = json_path.read_text(encoding="utf-8") + markdown
            self.assertNotIn(str(root), serialized)
            self.assertNotIn(str(database), serialized)

            stable = base / "stable"
            stable.mkdir()
            stable_json = stable / "review.json"
            stable_json.write_text("stable\n", encoding="utf-8")
            with patch(
                "rta_brain.review_bundle.os.replace",
                side_effect=OSError("replace interrupted"),
            ), self.assertRaisesRegex(OSError, "replace interrupted"):
                write_review_bundle(
                    bundle,
                    stable / "review",
                    formats=("json",),
                )
            self.assertEqual(stable_json.read_text(encoding="utf-8"), "stable\n")
            self.assertEqual(list(stable.glob(".review.*.tmp")), [])

    def test_review_bundle_rejects_unsafe_references_and_oversized_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            with self.assertRaisesRegex(ValueError, "path-safe"):
                lifecycle_review_bundle(
                    request,
                    evidence_references=[
                        {
                            "kind": "unsafe",
                            "reference": str(root / "private.txt"),
                            "digest": "b" * 64,
                        }
                    ],
                )

            bundle = lifecycle_review_bundle(request)
            destination = base / "bounded" / "review"
            with self.assertRaisesRegex(ValueError, "size limit"):
                write_review_bundle(
                    bundle,
                    destination,
                    formats=("json", "markdown"),
                    max_output_bytes=128,
                )
            self.assertFalse(destination.with_suffix(".json").exists())
            self.assertFalse(destination.with_suffix(".md").exists())

    def test_sdk_lifecycle_can_bind_an_explicit_continuity_sessions_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            sessions = base / "codex-sessions"
            root.mkdir()
            sessions.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()

            client = BrainClient(
                database,
                "demo",
                root,
                sessions_root=sessions,
            )

            self.assertEqual(
                client._lifecycle_request()["sessions_root"],
                sessions.resolve(),
            )

    def test_sdk_stop_and_remove_use_previewed_plan_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            client = BrainClient(database, "demo", root)
            initial = client.lifecycle_plan({})
            client.lifecycle_apply(
                {},
                plan_digest=initial["plan_digest"],
                observed_state_digest=initial["observed_state_digest"],
            )

            stop_plan = client.lifecycle_plan_stop()
            stopped = client.lifecycle_stop(
                plan_digest=stop_plan["plan_digest"],
                observed_state_digest=stop_plan["observed_state_digest"],
            )
            self.assertEqual(stopped["state"], "complete")

            remove_plan = client.lifecycle_plan_remove()
            removed = client.lifecycle_remove(
                plan_digest=remove_plan["plan_digest"],
                observed_state_digest=remove_plan["observed_state_digest"],
            )
            self.assertEqual(removed["state"], "removed")

    def test_interrupted_operation_is_visible_and_repairable_from_private_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            desired = {"watcher": True, "capture": True}
            plan = plan_lifecycle(request, desired)
            with (
                patch(
                    "rta_brain.trusted_lifecycle.start_watcher",
                    return_value={"state": "running"},
                ),
                patch(
                    "rta_brain.trusted_lifecycle.start_capture",
                    side_effect=KeyboardInterrupt(),
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })

            snapshot = inspect_lifecycle(request)
            self.assertEqual(snapshot["enrollment_state"], "recovery_required")
            self.assertIn("interrupted_operation_pending", snapshot["reason_codes"])
            self.assertIsNotNone(snapshot["desired_state_digest"])
            with (
                patch(
                    "rta_brain.trusted_lifecycle.start_watcher",
                    return_value={"state": "running"},
                ),
                patch(
                    "rta_brain.trusted_lifecycle.start_capture",
                    return_value={"state": "running"},
                ),
            ):
                repair_plan = plan_repair_lifecycle(request)
                repaired = repair_lifecycle(request, {
                    "approved": True,
                    "plan_digest": repair_plan["plan_digest"],
                    "desired_state_digest": snapshot["desired_state_digest"],
                    "observed_state_digest": repair_plan["observed_state_digest"],
                })

            self.assertEqual(repaired["state"], "complete")
            journals = list(
                (trusted_lifecycle._control_root(request) / "inflight").glob("*.json")
            )
            self.assertEqual(len(journals), 2)
            journal = next(
                json.loads(path.read_text(encoding="utf-8"))
                for path in journals
                if json.loads(path.read_text(encoding="utf-8"))["state"]
                == "recovered"
            )
            self.assertEqual(journal["state"], "recovered")
            self.assertEqual(journal["recovery_operation_id"], repaired["operation_id"])

    def test_repair_seals_interrupted_journal_when_state_already_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            desired = trusted_lifecycle._normalize_desired_state({})
            control = trusted_lifecycle._control_root(request)
            journal_path = control / "inflight" / "interrupted.json"
            trusted_lifecycle.write_json(
                journal_path,
                {
                    "schema": trusted_lifecycle.LIFECYCLE_SCHEMA,
                    "state": "interrupted",
                    "operation_id": "interrupted-operation",
                    "desired_state": desired,
                    "steps": [],
                },
                label="lifecycle inflight journal",
            )

            snapshot = inspect_lifecycle(request)
            repair_plan = plan_repair_lifecycle(request)
            repaired = repair_lifecycle(request, {
                "approved": True,
                "plan_digest": repair_plan["plan_digest"],
                "desired_state_digest": snapshot["desired_state_digest"],
                "observed_state_digest": repair_plan["observed_state_digest"],
            })

            sealed = json.loads(journal_path.read_text(encoding="utf-8"))
            self.assertEqual(repaired["state"], "complete")
            self.assertFalse(repaired["idempotent_replay"])
            self.assertEqual(sealed["state"], "recovered")
            self.assertEqual(
                sealed["recovery_operation_id"], repaired["operation_id"]
            )
            self.assertEqual(inspect_lifecycle(request)["enrollment_state"], "configured")

    def test_newer_database_is_inspectable_but_cannot_produce_an_executable_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            database.parent.mkdir()
            conn = sqlite3.connect(database)
            try:
                conn.execute("CREATE TABLE projects(name TEXT, root_path TEXT)")
                conn.execute(
                    "INSERT INTO projects(name, root_path) VALUES (?, ?)",
                    ("demo", str(root)),
                )
                conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION + 1}")
                conn.commit()
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }

            snapshot = inspect_lifecycle(request)
            plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })

            self.assertEqual(
                snapshot["health_axes"]["database_health"]["schema_state"],
                "newer_unsupported",
            )
            self.assertTrue(plan["blocked"])
            self.assertIn("schema_newer_unsupported", plan["blockers"])
            with self.assertRaisesRegex(PermissionError, "blocked"):
                apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })
            self.assertFalse((database.parent / ".rta-smriti-lifecycle").exists())

    def test_malformed_database_is_reported_without_crashing_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            database.parent.mkdir()
            database.write_bytes(b"not-a-sqlite-database")
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }

            snapshot = inspect_lifecycle(request)
            plan = plan_lifecycle(request, {})

            self.assertEqual(
                snapshot["health_axes"]["database_health"]["state"], "invalid"
            )
            self.assertEqual(
                snapshot["health_axes"]["database_health"]["schema_state"],
                "invalid",
            )
            self.assertTrue(plan["blocked"])
            self.assertIn("schema_invalid_or_unavailable", plan["blockers"])

    def test_linked_sqlite_sidecar_fails_closed_before_database_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            victim = base / "foreign-wal"
            victim.write_bytes(b"foreign")
            os.link(victim, database.with_name(f"{database.name}-wal"))
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }

            snapshot = inspect_lifecycle(request)

            self.assertEqual(
                snapshot["health_axes"]["database_health"]["state"], "unsafe"
            )
            self.assertEqual(
                snapshot["health_axes"]["database_health"]["schema_state"],
                "unavailable",
            )

    def test_supported_schema_upgrade_is_backed_up_migrated_and_validated_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
                conn.commit()
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "migrate-with-backup",
            })
            self.assertEqual(
                [step["operation"] for step in plan["steps"][:3]],
                ["backup_database", "migrate_database", "validate_database"],
            )

            receipt = apply_lifecycle(plan, {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            })

            self.assertEqual(receipt["state"], "complete")
            conn = sqlite3.connect(database)
            try:
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
                self.assertEqual(conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
            finally:
                conn.close()
            backups = list((Path(receipt["receipt_path"]).parents[1] / "backups").glob("*.sqlite"))
            self.assertEqual(len(backups), 1)
            backup = sqlite3.connect(backups[0])
            try:
                self.assertEqual(backup.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION - 1)
            finally:
                backup.close()

    def test_failed_post_migration_validation_preserves_backup_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
                conn.commit()
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "migrate-with-backup",
            })
            confirmation = {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            }
            original_run = trusted_lifecycle._run_service_operation

            def fail_validation(operation, selected):
                if operation == "validate_database":
                    raise RuntimeError("validation failed")
                return original_run(operation, selected)

            with patch(
                "rta_brain.trusted_lifecycle._run_service_operation",
                side_effect=fail_validation,
            ):
                receipt = apply_lifecycle(plan, confirmation)

            self.assertEqual(receipt["state"], "failed")
            self.assertEqual(receipt["rollback_state"], "partial")
            self.assertNotIn(
                "restore_database_backup",
                [item["operation"] for item in receipt["compensations"]],
            )
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("PRAGMA user_version").fetchone()[0],
                    db.SCHEMA_VERSION,
                )
                self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            finally:
                connection.close()

    def test_failed_migration_validation_never_overwrites_a_post_backup_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
                conn.execute(f"PRAGMA user_version = {db.SCHEMA_VERSION - 1}")
                conn.commit()
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {"schema_policy": "migrate-with-backup"})
            confirmation = {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            }
            original_run = trusted_lifecycle._run_service_operation

            def write_then_fail(operation, selected):
                if operation == "validate_database":
                    connection = sqlite3.connect(database)
                    try:
                        connection.execute("CREATE TABLE post_backup_write(value TEXT)")
                        connection.execute(
                            "INSERT INTO post_backup_write(value) VALUES ('durable')"
                        )
                        connection.commit()
                    finally:
                        connection.close()
                    raise RuntimeError("validation failed")
                return original_run(operation, selected)

            with patch(
                "rta_brain.trusted_lifecycle._run_service_operation",
                side_effect=write_then_fail,
            ):
                receipt = apply_lifecycle(plan, confirmation)

            self.assertEqual(receipt["state"], "failed")
            self.assertEqual(receipt["rollback_state"], "partial")
            self.assertNotIn(
                "restore_database_backup",
                [item["operation"] for item in receipt["compensations"]],
            )
            connection = sqlite3.connect(database)
            try:
                self.assertEqual(
                    connection.execute("SELECT value FROM post_backup_write").fetchone()[0],
                    "durable",
                )
            finally:
                connection.close()

    def test_login_restoration_is_planned_applied_and_removed_reversibly(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            home = base / "home"
            appdata = home / "AppData" / "Roaming"
            root.mkdir()
            home.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "platform_name": "win32",
                "home": home,
                "environment": {"APPDATA": str(appdata)},
            }
            enabled_plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": True,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })
            self.assertIn(
                "enable_login_restoration",
                [step["operation"] for step in enabled_plan["steps"]],
            )
            enabled = apply_lifecycle(enabled_plan, {
                "approved": True,
                "plan_digest": enabled_plan["plan_digest"],
                "observed_state_digest": enabled_plan["observed_state_digest"],
            })
            self.assertEqual(enabled["state"], "complete")
            startup_entries = list(appdata.rglob("Rta-Smriti-*.vbs"))
            self.assertEqual(len(startup_entries), 1)
            self.assertNotIn("WScript.Shell", startup_entries[0].read_text(encoding="utf-8"))

            disabled_plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })
            self.assertIn(
                "disable_login_restoration",
                [step["operation"] for step in disabled_plan["steps"]],
            )

    def test_verify_and_remove_preserve_receipt_history_without_active_desired_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })
            applied = apply_lifecycle(plan, {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            })

            verified = verify_lifecycle(request, "process")
            remove_plan = plan_remove_lifecycle(request)
            removed = remove_lifecycle(remove_plan, {
                "approved": True,
                "plan_digest": remove_plan["plan_digest"],
                "observed_state_digest": remove_plan["observed_state_digest"],
            })

            self.assertEqual(verified["state"], "verified")
            self.assertTrue(verified["ready"])
            self.assertEqual(removed["state"], "removed")
            receipt = Path(applied["receipt_path"])
            self.assertTrue(receipt.is_file())
            self.assertFalse((receipt.parents[1] / "desired-state.json").exists())
            self.assertGreaterEqual(len(list(receipt.parent.glob("*.json"))), 2)

    def test_remove_preserves_enrollment_when_service_stop_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            running = False

            def watcher_state(*_args):
                return {"state": "running" if running else "stopped"}

            def start(*_args, **_kwargs):
                nonlocal running
                running = True
                return {"state": "running"}

            with (
                patch(
                    "rta_brain.trusted_lifecycle.watcher_status",
                    side_effect=watcher_state,
                ),
                patch(
                    "rta_brain.trusted_lifecycle.start_watcher",
                    side_effect=start,
                ),
            ):
                plan = plan_lifecycle(request, {"watcher": True})
                applied = apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })
                remove_plan = plan_remove_lifecycle(request)
            desired_path = Path(applied["receipt_path"]).parents[1] / "desired-state.json"

            with (
                patch(
                    "rta_brain.trusted_lifecycle.watcher_status",
                    side_effect=watcher_state,
                ),
                patch(
                    "rta_brain.trusted_lifecycle.stop_watcher",
                    side_effect=RuntimeError("stop failed"),
                ),
                patch(
                    "rta_brain.trusted_lifecycle.start_watcher",
                    return_value={"state": "running"},
                ),
            ):
                result = remove_lifecycle(remove_plan, {
                    "approved": True,
                    "plan_digest": remove_plan["plan_digest"],
                    "observed_state_digest": remove_plan[
                        "observed_state_digest"
                    ],
                })

            self.assertEqual(result["state"], "failed")
            self.assertTrue(desired_path.is_file())

    def test_completed_receipt_replay_rejects_current_state_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {})
            confirmation = {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            }
            apply_lifecycle(plan, confirmation)
            desired_path = trusted_lifecycle._control_root(request) / "desired-state.json"
            payload = json.loads(desired_path.read_text(encoding="utf-8"))
            payload["desired_state"]["watcher"] = True
            trusted_lifecycle.write_json(
                desired_path, payload, label="lifecycle desired state"
            )

            with self.assertRaisesRegex(StaleLifecyclePlanError, "completed receipt"):
                apply_lifecycle(plan, confirmation)

    def test_remove_preserves_newer_enrollment_created_during_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            running = False

            def watcher_state(*_args):
                return {"state": "running" if running else "stopped"}

            def start(*_args, **_kwargs):
                nonlocal running
                running = True
                return {"state": "running"}

            with (
                patch(
                    "rta_brain.trusted_lifecycle.watcher_status",
                    side_effect=watcher_state,
                ),
                patch(
                    "rta_brain.trusted_lifecycle.start_watcher",
                    side_effect=start,
                ),
            ):
                plan = plan_lifecycle(request, {"watcher": True})
                apply_lifecycle(plan, {
                    "approved": True,
                    "plan_digest": plan["plan_digest"],
                    "observed_state_digest": plan["observed_state_digest"],
                })
                remove_plan = plan_remove_lifecycle(request)
            desired_path = trusted_lifecycle._control_root(request) / "desired-state.json"

            def replace_enrollment(*_args, **_kwargs):
                payload = json.loads(desired_path.read_text(encoding="utf-8"))
                payload["desired_state"]["capture"] = True
                trusted_lifecycle.write_json(
                    desired_path, payload, label="lifecycle desired state"
                )
                return {"state": "stopped"}

            with (
                patch(
                    "rta_brain.trusted_lifecycle.watcher_status",
                    side_effect=watcher_state,
                ),
                patch(
                    "rta_brain.trusted_lifecycle.stop_watcher",
                    side_effect=replace_enrollment,
                ),
                self.assertRaisesRegex(PermissionError, "changed before removal"),
            ):
                remove_lifecycle(remove_plan, {
                    "approved": True,
                    "plan_digest": remove_plan["plan_digest"],
                    "observed_state_digest": remove_plan[
                        "observed_state_digest"
                    ],
                })

            self.assertTrue(desired_path.is_file())
            self.assertTrue(
                json.loads(desired_path.read_text(encoding="utf-8"))[
                    "desired_state"
                ]["capture"]
            )

    def test_cli_inspect_and_plan_use_the_same_path_free_lifecycle_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            cli = Path(__file__).resolve().parents[1] / "rta-brain.py"
            common = [
                sys.executable,
                str(cli),
                "lifecycle",
                "--db",
                str(database),
                "--project",
                "demo",
                "--root",
                str(root),
                "--brain-dir",
                str(database.parent),
                "--json",
            ]

            inspected = subprocess.run(
                [*common, "inspect"],
                text=True,
                capture_output=True,
                cwd=cli.parent,
                check=False,
            )
            planned = subprocess.run(
                [*common, "plan", "--schema-policy", "inspect-only"],
                text=True,
                capture_output=True,
                cwd=cli.parent,
                check=False,
            )

            self.assertEqual(inspected.returncode, 0, inspected.stderr)
            self.assertEqual(planned.returncode, 0, planned.stderr)
            snapshot = json.loads(inspected.stdout)
            plan = json.loads(planned.stdout)
            self.assertEqual(plan["observed_state_digest"], snapshot["observed_state_digest"])
            self.assertNotIn(str(root), inspected.stdout)
            self.assertNotIn(str(database), planned.stdout)

    def test_cli_stop_requires_the_exact_plan_stop_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": Path(__file__).resolve().parents[1],
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": Path.home() / ".codex" / "sessions",
            }
            initial = plan_lifecycle(request, {})
            apply_lifecycle(
                initial,
                {
                    "approved": True,
                    "plan_digest": initial["plan_digest"],
                    "observed_state_digest": initial["observed_state_digest"],
                },
            )
            cli = Path(__file__).resolve().parents[1] / "rta-brain.py"
            common = [
                sys.executable,
                str(cli),
                "lifecycle",
                "--db",
                str(database),
                "--project",
                "demo",
                "--root",
                str(root),
                "--brain-dir",
                str(database.parent),
                "--json",
            ]
            preview = subprocess.run(
                [*common, "plan-stop"],
                text=True,
                capture_output=True,
                cwd=cli.parent,
                check=False,
            )
            self.assertEqual(preview.returncode, 0, preview.stderr)
            stop_plan = json.loads(preview.stdout)

            stopped = subprocess.run(
                [
                    *common,
                    "stop",
                    "--confirm-plan-digest",
                    stop_plan["plan_digest"],
                    "--confirm-observed-state-digest",
                    stop_plan["observed_state_digest"],
                ],
                text=True,
                capture_output=True,
                cwd=cli.parent,
                check=False,
            )
            self.assertEqual(stopped.returncode, 0, stopped.stderr)
            self.assertEqual(json.loads(stopped.stdout)["state"], "complete")

    def test_cli_repair_requires_and_accepts_current_state_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            database = base / "brains" / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": Path(__file__).resolve().parents[1],
                "brain_dir": database.parent,
                "db_path": database,
                "project": "demo",
                "root": root,
                "sessions_root": Path.home() / ".codex" / "sessions",
                "environment": lifecycle_authority_environment(),
            }
            desired = {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            }
            plan = plan_lifecycle(request, desired)
            applied = apply_lifecycle(plan, {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            })
            observed = inspect_lifecycle(request)
            repair_plan = plan_repair_lifecycle(request)
            cli = Path(__file__).resolve().parents[1] / "rta-brain.py"
            repaired = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "lifecycle",
                    "repair",
                    "--db",
                    str(database),
                    "--project",
                    "demo",
                    "--root",
                    str(root),
                    "--brain-dir",
                    str(database.parent),
                    "--confirm-plan-digest",
                    repair_plan["plan_digest"],
                    "--confirm-desired-state-digest",
                    applied["desired_state_digest"],
                    "--confirm-observed-state-digest",
                    repair_plan["observed_state_digest"],
                    "--json",
                ],
                text=True,
                capture_output=True,
                cwd=cli.parent,
                check=False,
            )

            self.assertEqual(repaired.returncode, 0, repaired.stderr)
            self.assertEqual(json.loads(repaired.stdout)["state"], "verified")

    def test_login_supervisor_prefers_trusted_desired_state_without_forcing_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "project"
            root.mkdir()
            brain_dir = base / "brains"
            database = brain_dir / "demo.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", root)
            finally:
                conn.close()
            request = {
                "tool_root": base,
                "brain_dir": brain_dir,
                "db_path": database,
                "project": "demo",
                "root": root,
            }
            plan = plan_lifecycle(request, {
                "watcher": False,
                "capture": False,
                "continuity": False,
                "console": False,
                "login_restoration": False,
                "mcp_hosts": [],
                "schema_policy": "current-only",
            })
            apply_lifecycle(plan, {
                "approved": True,
                "plan_digest": plan["plan_digest"],
                "observed_state_digest": plan["observed_state_digest"],
            })

            with patch("rta_brain.console_daemon.start_console") as start_console:
                result = supervise_brain(base, brain_dir, open_browser=False)

            self.assertEqual(result["mode"], "trusted_lifecycle")
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["projects"][0]["state"], "verified")
            self.assertEqual(result["console"]["state"], "not_configured")
            start_console.assert_not_called()


if __name__ == "__main__":
    unittest.main()
