import concurrent.futures
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from rta_brain import db


class TemporalResilienceTests(unittest.TestCase):
    def test_claim_append_rolls_back_on_keyboard_interrupt(self):
        from rta_brain.temporal import append_claim

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                with (
                    mock.patch(
                        "rta_brain.temporal._project_for_write",
                        side_effect=KeyboardInterrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        claim_id="interrupted-claim",
                        subject="release",
                        predicate="status",
                        value="candidate",
                        idempotency_key="interrupted:1",
                        expected_stream_version=0,
                    )

                self.assertFalse(conn.in_transaction)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    0,
                )
            finally:
                if conn.in_transaction:
                    conn.rollback()
                conn.close()

    def test_concurrent_writers_serialize_and_one_stale_version_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            database = Path(tmp) / "brain.sqlite"
            conn = db.connect(database)
            try:
                db.init_project(conn, "demo", str(root))
            finally:
                conn.close()
            barrier = threading.Barrier(2)

            def write(value):
                from rta_brain.temporal import StreamVersionConflict, append_claim

                worker = db.connect(database)
                try:
                    db.init_schema(worker)
                    barrier.wait(timeout=5)
                    try:
                        result = append_claim(
                            worker,
                            project="demo",
                            active_root=root,
                            claim_id="release-status",
                            subject="release:v0.7",
                            predicate="status",
                            value=value,
                            idempotency_key=f"concurrent:{value}",
                            expected_stream_version=0,
                        )
                        return ("ok", result["event"]["event_id"])
                    except StreamVersionConflict as exc:
                        return ("conflict", exc.actual)
                finally:
                    worker.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(write, ("candidate-a", "candidate-b")))

            self.assertEqual(sorted(item[0] for item in outcomes), ["conflict", "ok"])
            check = db.connect(database)
            try:
                self.assertEqual(
                    check.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0], 1
                )
                self.assertEqual(
                    check.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0], 1
                )
            finally:
                check.close()

    def test_schema_migration_failure_rolls_back_legacy_data_and_event_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            legacy = sqlite3.connect(database)
            try:
                legacy.executescript(
                    """
                    CREATE TABLE projects (
                        id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                        root_path TEXT, repository_identity TEXT,
                        checkout_identity TEXT, created_at TEXT NOT NULL
                    );
                    CREATE TABLE memories (
                        id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL,
                        type TEXT NOT NULL, pramana TEXT NOT NULL, text TEXT NOT NULL,
                        confidence REAL NOT NULL, priority INTEGER NOT NULL,
                        status TEXT NOT NULL, metadata_json TEXT NOT NULL,
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    CREATE TABLE memory_provenance (
                        memory_id INTEGER PRIMARY KEY, source_path TEXT,
                        source_hash TEXT, command TEXT, timestamp TEXT NOT NULL,
                        verification_status TEXT NOT NULL, metadata_json TEXT NOT NULL
                    );
                    INSERT INTO projects VALUES (
                        1, 'demo', NULL, NULL, NULL, '2026-01-01T00:00:00+00:00'
                    );
                    INSERT INTO memories VALUES (
                        7, 1, 'decision', 'pratyaksha', 'original legacy memory',
                        0.9, 8, 'active', '{}',
                        '2026-01-02T00:00:00+00:00', '2026-01-03T00:00:00+00:00'
                    );
                    PRAGMA user_version = 7;
                    """
                )
                legacy.commit()
            finally:
                legacy.close()

            def fail_after_write(conn):
                conn.execute(
                    "UPDATE memories SET text = 'partial migration' WHERE id = 7"
                )
                raise RuntimeError("injected migration failure")

            conn = db.connect(database)
            try:
                with mock.patch(
                    "rta_brain.temporal.migrate_legacy_memories",
                    side_effect=fail_after_write,
                ):
                    with self.assertRaisesRegex(RuntimeError, "injected migration failure"):
                        db.init_schema(conn, allow_migration=True)
            finally:
                conn.close()

            verify = sqlite3.connect(database)
            try:
                self.assertEqual(verify.execute("PRAGMA user_version").fetchone()[0], 7)
                self.assertEqual(
                    verify.execute("SELECT text FROM memories WHERE id = 7").fetchone()[0],
                    "original legacy memory",
                )
                self.assertIsNone(
                    verify.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'truth_events'"
                    ).fetchone()
                )
            finally:
                verify.close()

    def test_replay_unknown_event_rolls_back_without_destroying_live_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    _event_envelope_from_row,
                    _event_hash,
                    append_claim,
                    rebuild_projections,
                )

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="release-status",
                    subject="release:v0.7",
                    predicate="status",
                    value="candidate",
                    idempotency_key="unknown-event:1",
                    expected_stream_version=0,
                )
                event = conn.execute("SELECT * FROM truth_events").fetchone()
                envelope = _event_envelope_from_row(event)
                envelope["event_type"] = "future_event.v99"
                conn.execute("DROP TRIGGER truth_events_no_update")
                conn.execute(
                    "UPDATE truth_events SET event_type = ?, event_hash = ? WHERE event_id = ?",
                    ("future_event.v99", _event_hash(envelope), event["event_id"]),
                )
                conn.commit()

                with self.assertRaisesRegex(ValueError, "unsupported truth event"):
                    rebuild_projections(conn, project="demo", active_root=root)

                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_event_payload_rejects_oversized_and_excessively_nested_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim

                nested = "leaf"
                for _ in range(40):
                    nested = {"next": nested}
                cases = (
                    ("large", "x" * (300 * 1024), "256 KiB"),
                    ("deep", nested, "nesting"),
                )
                for suffix, value, message in cases:
                    with self.subTest(suffix=suffix):
                        with self.assertRaisesRegex(ValueError, message):
                            append_claim(
                                conn,
                                project="demo",
                                active_root=root,
                                claim_id=f"claim-{suffix}",
                                subject=f"payload:{suffix}",
                                predicate="value",
                                value=value,
                                idempotency_key=f"payload:{suffix}:1",
                                expected_stream_version=0,
                            )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0], 0
                )
            finally:
                conn.close()

    def test_overview_is_bounded_and_redacts_sensitive_event_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim, truth_overview

                for index in range(3):
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        claim_id=f"claim-{index}",
                        subject=f"subject:{index}",
                        predicate="value",
                        value=f"private-{index}",
                        privacy_class="sensitive" if index == 2 else "internal",
                        idempotency_key=f"overview:{index}",
                        expected_stream_version=0,
                    )
                overview = truth_overview(conn, project="demo", limit=2)

                self.assertEqual(overview["counts"]["events"], 3)
                self.assertEqual(len(overview["events"]), 2)
                self.assertEqual(len(overview["claims"]), 2)
                self.assertEqual(
                    overview["events"][0]["payload_summary"],
                    {"redacted": True, "privacy_class": "sensitive"},
                )
                self.assertEqual(
                    overview["claims"][0]["object"],
                    {"redacted": True, "privacy_class": "sensitive"},
                )
                self.assertTrue(overview["claims"][0]["redacted"])
                self.assertNotIn("subject", overview["claims"][0])
            finally:
                conn.close()

    def test_temporal_validators_reject_hard_linked_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            outside = Path(tmp) / "outside.json"
            outside.write_text('{"secret": true}', encoding="utf-8")
            linked = root / "linked.json"
            try:
                os.link(outside, linked)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            from rta_brain.temporal_validators import (
                evaluate_validator,
                stable_file_bytes,
                stable_file_sha256,
            )

            with self.assertRaisesRegex(ValueError, "hard linked"):
                stable_file_sha256(linked)
            with self.assertRaisesRegex(ValueError, "hard linked"):
                stable_file_bytes(linked, maximum_bytes=1024)
            outcome, details = evaluate_validator(
                "file_exists", {"path": "linked.json"}, active_root=root,
                allow_command=False, trusted_executables=(),
            )
            self.assertEqual((outcome, details["exists"]), ("fail", False))

    def test_git_anchor_uses_hardened_repository_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            head = mock.Mock(returncode=0, stdout="a" * 40 + "\n")
            status = mock.Mock(returncode=0, stdout=" M state.txt\0")
            with (
                mock.patch(
                    "rta_brain.temporal_validators.run_git_inspection",
                    side_effect=(head, status),
                ) as inspect,
                mock.patch(
                    "rta_brain.temporal_validators.repository_state",
                    return_value={"branch": "main", "dirty_files": 1},
                ),
            ):
                from rta_brain.temporal_validators import git_anchor_state

                result = git_anchor_state(root)
            self.assertEqual(result["commit"], "a" * 40)
            self.assertEqual(result["dirty_files"], 1)
            self.assertEqual(inspect.call_count, 2)
            self.assertEqual(inspect.call_args_list[0].args[1:], ("rev-parse", "--verify", "HEAD"))
            self.assertEqual(inspect.call_args_list[1].args[1], "status")

    def test_truth_explanation_bounds_large_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    append_claim,
                    attach_evidence,
                    truth_explain,
                )

                append_claim(
                    conn, project="demo", active_root=root, claim_id="claim-a",
                    subject="release", predicate="status", value="candidate",
                    idempotency_key="explain:claim:1", expected_stream_version=0,
                )
                for index in range(6):
                    attach_evidence(
                        conn, project="demo", active_root=root, claim_id="claim-a",
                        evidence_id=f"evidence-{index}", source_identifier=f"proof-{index}",
                        method="bounded-test", polarity="supporting",
                        authority_class="operator", confidence=1.0,
                        provenance={"blob": "x" * (40 * 1024)},
                        idempotency_key=f"explain:evidence:{index}",
                        expected_stream_version=0,
                    )
                result = truth_explain(conn, project="demo", claim_id="claim-a")
                self.assertEqual(len(result["evidence"]), 6)
                self.assertTrue(all(
                    item["provenance"]["value_omitted"] for item in result["evidence"]
                ))
                self.assertLess(len(json.dumps(result).encode("utf-8")), 128 * 1024)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
