import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import db


class TemporalTruthSchemaTests(unittest.TestCase):
    def test_init_schema_creates_immutable_temporal_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_schema(conn)

                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], db.SCHEMA_VERSION)
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
                self.assertTrue(
                    {
                        "truth_events",
                        "truth_claim_versions",
                        "truth_relations",
                        "truth_evidence",
                        "truth_projection_state",
                    }.issubset(tables)
                )
                triggers = {
                    row["name"]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                self.assertIn("truth_events_no_update", triggers)
                self.assertIn("truth_events_no_delete", triggers)
            finally:
                conn.close()

    def test_schema_seven_memory_migrates_once_without_fabricated_recorded_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "brain.sqlite"
            legacy = sqlite3.connect(database)
            try:
                legacy.executescript(
                    """
                    CREATE TABLE projects (
                        id INTEGER PRIMARY KEY,
                        name TEXT NOT NULL UNIQUE,
                        root_path TEXT,
                        repository_identity TEXT,
                        checkout_identity TEXT,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE memories (
                        id INTEGER PRIMARY KEY,
                        project_id INTEGER NOT NULL REFERENCES projects(id),
                        type TEXT NOT NULL,
                        pramana TEXT NOT NULL,
                        text TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        priority INTEGER NOT NULL,
                        status TEXT NOT NULL,
                        metadata_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );
                    CREATE TABLE memory_provenance (
                        memory_id INTEGER PRIMARY KEY REFERENCES memories(id),
                        source_path TEXT,
                        source_hash TEXT,
                        command TEXT,
                        timestamp TEXT NOT NULL,
                        verification_status TEXT NOT NULL,
                        metadata_json TEXT NOT NULL
                    );
                    INSERT INTO projects VALUES (
                        1, 'demo', NULL, NULL, NULL, '2026-01-01T00:00:00+00:00'
                    );
                    INSERT INTO memories VALUES (
                        7, 1, 'decision', 'pratyaksha', 'Use SQLite locally.',
                        0.9, 8, 'active', '{}',
                        '2026-01-02T00:00:00+00:00',
                        '2026-01-03T00:00:00+00:00'
                    );
                    INSERT INTO memory_provenance VALUES (
                        7, 'ARCHITECTURE.md', 'abc123', 'pytest',
                        '2026-01-03T00:00:00+00:00', 'verified', '{}'
                    );
                    PRAGMA user_version = 7;
                    """
                )
                legacy.execute(
                    """
                    INSERT INTO memories VALUES (
                        8, 1, 'fact', 'smriti', 'Legacy metadata stays bounded.',
                        0.7, 5, 'active', ?,
                        '2026-01-04T00:00:00+00:00',
                        '2026-01-04T00:00:00+00:00'
                    )
                    """,
                    (json.dumps({"oversized": "x" * (300 * 1024)}),),
                )
                legacy.commit()
            finally:
                legacy.close()

            conn = db.connect(database)
            try:
                db.init_schema(conn, allow_migration=True)
                db.init_schema(conn, allow_migration=True)

                event = conn.execute(
                    "SELECT * FROM truth_events WHERE project_id = 1"
                ).fetchone()
                self.assertIsNotNone(event)
                self.assertEqual(event["event_type"], "legacy_memory_registered.v1")
                self.assertNotEqual(
                    event["recorded_at"], "2026-01-02T00:00:00+00:00"
                )
                payload = __import__("json").loads(event["payload_json"])
                self.assertEqual(
                    payload["legacy_created_at"], "2026-01-02T00:00:00+00:00"
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    2,
                )
                claim = conn.execute(
                    "SELECT * FROM truth_claim_versions WHERE legacy_memory_id = 7"
                ).fetchone()
                self.assertIsNotNone(claim)
                self.assertNotEqual(claim["epistemic_state"], "accepted")
                self.assertEqual(
                    __import__("json").loads(claim["object_json"]),
                    "Use SQLite locally.",
                )
                oversized = conn.execute(
                    "SELECT payload_json FROM truth_events WHERE stream_id = 'claim:legacy-memory:8'"
                ).fetchone()
                marker = json.loads(oversized["payload_json"])["legacy_metadata"]
                self.assertTrue(marker["legacy_value_omitted"])
                self.assertEqual(len(marker["sha256"]), 64)
            finally:
                conn.close()


class TemporalTruthAppendTests(unittest.TestCase):
    def test_append_claim_creates_event_and_current_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import append_claim
                except ModuleNotFoundError:
                    self.fail("rta_brain.temporal is not implemented")

                result = append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="candidate",
                    idempotency_key="test:claim:release-status:1",
                    expected_stream_version=0,
                    valid_from="2026-08-22T00:00:00+00:00",
                )

                self.assertEqual(result["status"], "ok")
                self.assertFalse(result["idempotent_replay"])
                self.assertEqual(result["event"]["project_sequence"], 1)
                self.assertEqual(result["event"]["stream_version"], 1)
                self.assertEqual(result["claim"]["object"], "candidate")
                self.assertEqual(result["claim"]["recorded_from_sequence"], 1)
                self.assertIsNone(result["claim"]["recorded_to_sequence"])
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_verify_ledger_is_read_only_and_reports_chain_and_projection_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim, verify_ledger

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="claim-verify",
                    subject="ledger",
                    predicate="integrity",
                    value="intact",
                    idempotency_key="verify:claim:1",
                    expected_stream_version=0,
                )
                before = conn.total_changes
                result = verify_ledger(conn, project="demo")

                self.assertEqual(result["status"], "ok")
                self.assertTrue(result["chain_valid"])
                self.assertEqual(result["events_verified"], 1)
                self.assertEqual(len(result["event_chain_hash"]), 64)
                self.assertEqual(len(result["projection_digest"]), 64)
                self.assertEqual(conn.total_changes, before)
            finally:
                conn.close()


class TemporalTruthQueryTests(unittest.TestCase):
    def test_retroactive_revision_preserves_prior_recorded_belief(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        revise_claim,
                        truth_as_of,
                    )
                except ImportError:
                    self.fail("bitemporal revision and as-of queries are not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="candidate",
                    claim_id="release-status",
                    idempotency_key="test:release-status:1",
                    expected_stream_version=0,
                    valid_from="2026-01-01T00:00:00+00:00",
                )
                revise_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="release-status",
                    value="ready",
                    idempotency_key="test:release-status:2",
                    expected_stream_version=1,
                    valid_from="2026-01-01T00:00:00+00:00",
                    reason="Later verification corrected the earlier status.",
                )

                earlier = truth_as_of(
                    conn,
                    project="demo",
                    claim_id="release-status",
                    valid_at="2026-06-01T00:00:00+00:00",
                    recorded_sequence=1,
                )
                later = truth_as_of(
                    conn,
                    project="demo",
                    claim_id="release-status",
                    valid_at="2026-06-01T00:00:00+00:00",
                    recorded_sequence=2,
                )

                self.assertEqual(earlier["claim"]["object"], "candidate")
                self.assertEqual(later["claim"]["object"], "ready")
                versions = conn.execute(
                    """
                    SELECT object_json, recorded_from_sequence, recorded_to_sequence
                    FROM truth_claim_versions
                    ORDER BY recorded_from_sequence
                    """
                ).fetchall()
                self.assertEqual(len(versions), 2)
                self.assertEqual(versions[0]["recorded_to_sequence"], 2)
                self.assertIsNone(versions[1]["recorded_to_sequence"])
            finally:
                conn.close()

    def test_commit_query_requires_an_explicit_observed_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Temporal Test"],
                cwd=root,
                check=True,
            )
            (root / "state.txt").write_text("ready\n", encoding="utf-8")
            subprocess.run(["git", "add", "state.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=root, check=True)
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        observe_repository_anchor,
                        projection_digest,
                        rebuild_projections,
                        truth_at_commit,
                    )
                except ImportError:
                    self.fail("explicit repository anchors are not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="ready",
                    claim_id="release-status",
                    valid_from="2026-08-22T00:00:00+00:00",
                    idempotency_key="test:release-status:1",
                    expected_stream_version=0,
                )
                observe_repository_anchor(
                    conn,
                    project="demo",
                    active_root=root,
                    anchor_id="initial-head",
                    idempotency_key="test:anchor:initial-head:1",
                    expected_stream_version=0,
                )

                anchored = truth_at_commit(
                    conn,
                    project="demo",
                    claim_id="release-status",
                    commit=head,
                    valid_at="2026-08-22T00:00:00+00:00",
                )
                unknown = truth_at_commit(
                    conn,
                    project="demo",
                    claim_id="release-status",
                    commit="0" * 40,
                    valid_at="2026-08-22T00:00:00+00:00",
                )
                before = projection_digest(conn, project="demo")
                conn.execute("DELETE FROM truth_repository_anchors")
                conn.commit()
                rebuilt = rebuild_projections(
                    conn, project="demo", active_root=root
                )
                restored = truth_at_commit(
                    conn,
                    project="demo",
                    claim_id="release-status",
                    commit=head,
                    valid_at="2026-08-22T00:00:00+00:00",
                )

                self.assertEqual(anchored["status"], "ok")
                self.assertEqual(anchored["claim"]["object"], "ready")
                self.assertEqual(anchored["anchor"]["commit"], head)
                self.assertEqual(unknown["status"], "abstain")
                self.assertIn("explicit anchor", unknown["reason"])
                self.assertEqual(rebuilt["projection_digest"], before)
                self.assertEqual(restored["anchor"]["commit"], head)
            finally:
                conn.close()

    def test_history_and_diff_explain_what_changed_between_sequences(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        revise_claim,
                        truth_diff,
                        truth_history,
                    )
                except ImportError:
                    self.fail("temporal history and diff queries are not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="candidate",
                    claim_id="release-status",
                    idempotency_key="test:release-status:1",
                    expected_stream_version=0,
                    valid_from="2026-01-01T00:00:00+00:00",
                )
                revise_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="release-status",
                    value="ready",
                    reason="Qualification passed.",
                    idempotency_key="test:release-status:2",
                    expected_stream_version=1,
                    valid_from="2026-01-01T00:00:00+00:00",
                )

                history = truth_history(
                    conn, project="demo", claim_id="release-status"
                )
                difference = truth_diff(
                    conn,
                    project="demo",
                    from_sequence=1,
                    to_sequence=2,
                    valid_at="2026-06-01T00:00:00+00:00",
                )

                self.assertEqual(
                    [version["object"] for version in history["versions"]],
                    ["candidate", "ready"],
                )
                self.assertEqual(len(difference["changes"]), 1)
                self.assertEqual(difference["changes"][0]["before"]["object"], "candidate")
                self.assertEqual(difference["changes"][0]["after"]["object"], "ready")
            finally:
                conn.close()


class TemporalTruthGovernanceTests(unittest.TestCase):
    def test_agent_cannot_forge_claim_authority_or_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim

                with self.assertRaisesRegex(
                    PermissionError, "agents must use an agent authority class"
                ):
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        subject="release:v0.8",
                        predicate="status",
                        value="ready",
                        authority_class="operator",
                        actor_type="agent",
                        actor_id="codex",
                        idempotency_key="agent-forgery:authority:1",
                        expected_stream_version=0,
                    )
                with self.assertRaisesRegex(
                    PermissionError, "agents cannot self-verify claims"
                ):
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        subject="release:v0.8",
                        predicate="status",
                        value="ready",
                        authority_class="agent-proposal",
                        verification_status="verified",
                        actor_type="agent",
                        actor_id="codex",
                        idempotency_key="agent-forgery:verification:1",
                        expected_stream_version=0,
                    )

                proposed = append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.8",
                    predicate="status",
                    value="candidate",
                    authority_class="agent-proposal",
                    verification_status="unverified",
                    actor_type="agent",
                    actor_id="codex",
                    idempotency_key="agent-proposal:valid:1",
                    expected_stream_version=0,
                )

                projection = conn.execute(
                    """
                    SELECT authority_class, verification_status
                    FROM truth_claim_versions
                    WHERE claim_id = ? AND recorded_to_sequence IS NULL
                    """,
                    (proposed["claim"]["claim_id"],),
                ).fetchone()
                self.assertEqual(projection["authority_class"], "agent-proposal")
                self.assertEqual(projection["verification_status"], "unverified")
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0], 1
                )
            finally:
                conn.close()

    def test_agent_cannot_self_promote_but_operator_can_accept(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import append_claim, change_claim_state
                except ImportError:
                    self.fail("epistemic state transitions are not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="verified",
                    claim_id="release-status",
                    idempotency_key="test:release-status:1",
                    expected_stream_version=0,
                    epistemic_state="observed",
                )
                with self.assertRaisesRegex(
                    PermissionError, "agents cannot promote claims to accepted"
                ):
                    change_claim_state(
                        conn,
                        project="demo",
                        active_root=root,
                        claim_id="release-status",
                        new_state="accepted",
                        reason="I decided my own result is correct.",
                        idempotency_key="test:release-status:agent-accept",
                        expected_stream_version=1,
                        actor_type="agent",
                        actor_id="codex",
                    )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    1,
                )

                accepted = change_claim_state(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="release-status",
                    new_state="accepted",
                    reason="Owner reviewed the verified evidence.",
                    idempotency_key="test:release-status:operator-accept",
                    expected_stream_version=1,
                    actor_type="operator",
                    actor_id="owner",
                )

                self.assertEqual(accepted["claim"]["epistemic_state"], "accepted")
                self.assertEqual(accepted["event"]["stream_version"], 2)
                current = conn.execute(
                    """
                    SELECT epistemic_state FROM truth_claim_versions
                    WHERE claim_id = 'release-status'
                      AND recorded_to_sequence IS NULL
                    """
                ).fetchone()
                self.assertEqual(current["epistemic_state"], "accepted")
            finally:
                conn.close()

    def test_command_validator_requires_explicit_capability_and_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    append_claim,
                    define_validator,
                    run_validator,
                )

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="check:local",
                    predicate="status",
                    value="pending",
                    claim_id="local-check",
                    idempotency_key="test:local-check:1",
                    expected_stream_version=0,
                )
                define_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="safe-command",
                    validator_type="command_exit",
                    claim_id="local-check",
                    config={
                        "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                        "timeout_seconds": 2,
                    },
                    failure_effect="disputed",
                    idempotency_key="test:safe-command:1",
                    expected_stream_version=0,
                )
                disabled = run_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="safe-command",
                    idempotency_key="test:safe-command:run:disabled",
                    expected_stream_version=1,
                )
                enabled = run_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="safe-command",
                    idempotency_key="test:safe-command:run:enabled",
                    expected_stream_version=2,
                    allow_command=True,
                    trusted_executables=[sys.executable],
                )

                self.assertEqual(disabled["evaluation"]["outcome"], "unavailable")
                self.assertEqual(enabled["evaluation"]["outcome"], "pass")
                self.assertEqual(enabled["evaluation"]["details"]["exit_code"], 0)
            finally:
                conn.close()

    def test_built_in_deterministic_validator_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Temporal Test"],
                cwd=root,
                check=True,
            )
            (root / "state.json").write_text('{"status":"ready"}\n', encoding="utf-8")
            sample_db = sqlite3.connect(root / "sample.sqlite")
            sample_db.execute("CREATE TABLE proof(value TEXT)")
            sample_db.commit()
            sample_db.close()
            subprocess.run(["git", "add", "state.json", "sample.sqlite"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "fixtures"], cwd=root, check=True)
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    append_claim,
                    define_validator,
                    run_validator,
                )

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="registry:validators",
                    predicate="status",
                    value="configured",
                    claim_id="validators-configured",
                    idempotency_key="test:validators-configured:1",
                    expected_stream_version=0,
                )
                cases = (
                    (
                        "json-ready",
                        "json_pointer_equals",
                        {"path": "state.json", "pointer": "/status", "equals": "ready"},
                    ),
                    (
                        "sqlite-ok",
                        "sqlite_integrity",
                        {"path": "sample.sqlite"},
                    ),
                    (
                        "git-head",
                        "git_head_equals",
                        {"commit": head},
                    ),
                    (
                        "git-clean",
                        "git_clean_state",
                        {"clean": True},
                    ),
                )
                for validator_id, validator_type, config in cases:
                    define_validator(
                        conn,
                        project="demo",
                        active_root=root,
                        validator_id=validator_id,
                        validator_type=validator_type,
                        claim_id="validators-configured",
                        config=config,
                        failure_effect="stale",
                        idempotency_key=f"test:{validator_id}:1",
                        expected_stream_version=0,
                    )
                    result = run_validator(
                        conn,
                        project="demo",
                        active_root=root,
                        validator_id=validator_id,
                        idempotency_key=f"test:{validator_id}:run:1",
                        expected_stream_version=1,
                    )
                    self.assertEqual(
                        result["evaluation"]["outcome"], "pass", validator_id
                    )
            finally:
                conn.close()

    def test_expiry_changes_effective_state_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim, truth_current

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="dependency:catalog",
                    predicate="status",
                    value="current",
                    claim_id="catalog-current",
                    idempotency_key="test:catalog-current:1",
                    expected_stream_version=0,
                    valid_from="2026-01-01T00:00:00+00:00",
                    expires_at="2026-02-01T00:00:00+00:00",
                )

                before = truth_current(
                    conn,
                    project="demo",
                    claim_id="catalog-current",
                    valid_at="2026-01-15T00:00:00+00:00",
                )
                after = truth_current(
                    conn,
                    project="demo",
                    claim_id="catalog-current",
                    valid_at="2026-03-01T00:00:00+00:00",
                )

                self.assertEqual(before["claim"]["effective_state"], "observed")
                self.assertEqual(after["claim"]["effective_state"], "stale")
                self.assertEqual(after["claim"]["epistemic_state"], "observed")
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_failed_bounded_validator_makes_claim_effectively_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            artifact = root / "artifact.txt"
            artifact.write_text("verified\n", encoding="utf-8")
            expected_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        define_validator,
                        run_validator,
                        truth_current,
                    )
                except ImportError:
                    self.fail("bounded temporal validators are not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="artifact:release",
                    predicate="sha256_verified",
                    value=True,
                    claim_id="artifact-verified",
                    idempotency_key="test:artifact-verified:1",
                    expected_stream_version=0,
                )
                define_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="artifact-sha",
                    validator_type="file_sha256",
                    claim_id="artifact-verified",
                    config={"path": "artifact.txt", "sha256": expected_hash},
                    failure_effect="stale",
                    idempotency_key="test:validator:artifact-sha:1",
                    expected_stream_version=0,
                )
                passed = run_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="artifact-sha",
                    idempotency_key="test:validator:artifact-sha:run:1",
                    expected_stream_version=1,
                )
                self.assertEqual(passed["evaluation"]["outcome"], "pass")

                artifact.write_text("changed\n", encoding="utf-8")
                failed = run_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="artifact-sha",
                    idempotency_key="test:validator:artifact-sha:run:2",
                    expected_stream_version=2,
                )

                self.assertEqual(failed["evaluation"]["outcome"], "fail")
                current = truth_current(
                    conn, project="demo", claim_id="artifact-verified"
                )
                self.assertEqual(current["claim"]["epistemic_state"], "observed")
                self.assertEqual(current["claim"]["effective_state"], "stale")
                self.assertEqual(
                    current["claim"]["validator_failures"], ["artifact-sha"]
                )
            finally:
                conn.close()

    def test_evidence_is_provenance_bearing_and_explainable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        attach_evidence,
                        truth_explain,
                    )
                except ImportError:
                    self.fail("proof-carrying temporal evidence is not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="test:suite",
                    predicate="status",
                    value="green",
                    claim_id="suite-green",
                    idempotency_key="test:suite-green:1",
                    expected_stream_version=0,
                )
                attached = attach_evidence(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="suite-green",
                    evidence_id="pytest-receipt",
                    source_identifier="tests/test_temporal_truth.py",
                    source_hash="a" * 64,
                    method="pytest",
                    polarity="supporting",
                    authority_class="direct-test",
                    confidence=0.98,
                    provenance={"command": "python -m pytest", "exit_code": 0},
                    idempotency_key="test:evidence:pytest-receipt:1",
                    expected_stream_version=0,
                    verification_status="verified",
                )

                self.assertEqual(attached["evidence"]["polarity"], "supporting")
                explained = truth_explain(
                    conn, project="demo", claim_id="suite-green"
                )
                self.assertEqual(explained["claim"]["object"], "green")
                self.assertEqual(len(explained["evidence"]), 1)
                self.assertEqual(
                    explained["evidence"][0]["source_hash"], "a" * 64
                )
                self.assertEqual(
                    explained["evidence"][0]["provenance"]["exit_code"], 0
                )
            finally:
                conn.close()

    def test_abstention_records_missing_proof_without_creating_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import record_abstention
                except ImportError:
                    self.fail("temporal abstention events are not implemented")

                result = record_abstention(
                    conn,
                    project="demo",
                    active_root=root,
                    query_scope="Is v0.7 ready to publish?",
                    missing_evidence=["macOS clean install", "Linux clean install"],
                    unresolved_conflicts=["CI has not run"],
                    minimum_revalidation_action="Run hosted cross-platform CI.",
                    idempotency_key="test:abstention:release-ready:1",
                    expected_stream_version=0,
                )

                self.assertEqual(result["status"], "abstain")
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0],
                    0,
                )
                event = conn.execute("SELECT event_type FROM truth_events").fetchone()
                self.assertEqual(event["event_type"], "abstention_recorded.v1")
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_abstentions").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_contradiction_relation_keeps_both_claims_and_disputes_current_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        relate_claims,
                        truth_current,
                    )
                except ImportError:
                    self.fail("contradiction branches are not implemented")

                common = {
                    "conn": conn,
                    "project": "demo",
                    "active_root": root,
                    "subject": "feature:temporal-truth",
                    "predicate": "enabled",
                    "expected_stream_version": 0,
                }
                append_claim(
                    **common,
                    value=True,
                    claim_id="feature-enabled",
                    idempotency_key="test:feature-enabled",
                )
                append_claim(
                    **common,
                    value=False,
                    claim_id="feature-disabled",
                    idempotency_key="test:feature-disabled",
                )
                relation = relate_claims(
                    conn,
                    project="demo",
                    active_root=root,
                    from_claim_id="feature-enabled",
                    relation_type="contradicts",
                    to_claim_id="feature-disabled",
                    relation_id="feature-conflict",
                    idempotency_key="test:feature-conflict",
                    expected_stream_version=0,
                    actor_type="operator",
                    actor_id="local-operator",
                )

                self.assertEqual(relation["relation"]["type"], "contradicts")
                enabled = truth_current(
                    conn, project="demo", claim_id="feature-enabled"
                )
                disabled = truth_current(
                    conn, project="demo", claim_id="feature-disabled"
                )
                self.assertEqual(enabled["claim"]["effective_state"], "disputed")
                self.assertEqual(disabled["claim"]["effective_state"], "disputed")
                self.assertEqual(
                    enabled["claim"]["contradictions"], ["feature-disabled"]
                )
                self.assertEqual(
                    disabled["claim"]["contradictions"], ["feature-enabled"]
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0],
                    2,
                )
            finally:
                conn.close()

    def test_projection_rebuild_replays_events_to_identical_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import (
                        append_claim,
                        projection_digest,
                        rebuild_projections,
                        revise_claim,
                        truth_as_of,
                    )
                except ImportError:
                    self.fail("deterministic projection replay is not implemented")

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="candidate",
                    claim_id="release-status",
                    idempotency_key="test:release-status:1",
                    expected_stream_version=0,
                    valid_from="2026-01-01T00:00:00+00:00",
                )
                revise_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="release-status",
                    value="ready",
                    idempotency_key="test:release-status:2",
                    expected_stream_version=1,
                    valid_from="2026-01-01T00:00:00+00:00",
                    reason="Verification completed.",
                )
                before = projection_digest(conn, project="demo")
                conn.execute("DELETE FROM truth_claim_versions")
                conn.commit()

                rebuilt = rebuild_projections(
                    conn, project="demo", active_root=root
                )

                self.assertEqual(rebuilt["projection_digest"], before)
                self.assertEqual(rebuilt["events_replayed"], 2)
                self.assertEqual(rebuilt["claims_rebuilt"], 2)
                restored = truth_as_of(
                    conn,
                    project="demo",
                    claim_id="release-status",
                    valid_at="2026-06-01T00:00:00+00:00",
                    recorded_sequence=1,
                )
                self.assertEqual(restored["claim"]["object"], "candidate")
            finally:
                conn.close()

    def test_projection_rebuild_restores_state_and_relation_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    append_claim,
                    change_claim_state,
                    projection_digest,
                    rebuild_projections,
                    relate_claims,
                    truth_current,
                )

                for claim_id, value in (("claim-a", "A"), ("claim-b", "B")):
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        subject=f"component:{claim_id}",
                        predicate="status",
                        value=value,
                        claim_id=claim_id,
                        idempotency_key=f"test:{claim_id}:1",
                        expected_stream_version=0,
                    )
                change_claim_state(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="claim-a",
                    new_state="corroborated",
                    reason="Two independent checks agree.",
                    idempotency_key="test:claim-a:state:2",
                    expected_stream_version=1,
                )
                relate_claims(
                    conn,
                    project="demo",
                    active_root=root,
                    from_claim_id="claim-a",
                    relation_type="supports",
                    to_claim_id="claim-b",
                    relation_id="support-a-b",
                    idempotency_key="test:support-a-b:1",
                    expected_stream_version=0,
                )
                before = projection_digest(conn, project="demo")
                conn.execute("DELETE FROM truth_claim_versions")
                conn.execute("DELETE FROM truth_relations")
                conn.commit()

                rebuilt = rebuild_projections(
                    conn, project="demo", active_root=root
                )

                self.assertEqual(rebuilt["projection_digest"], before)
                self.assertEqual(
                    truth_current(conn, project="demo", claim_id="claim-a")["claim"]
                    ["epistemic_state"],
                    "corroborated",
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_relations").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_projection_rebuild_restores_evidence_abstention_and_validators(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            artifact = root / "artifact.txt"
            artifact.write_text("stable\n", encoding="utf-8")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    append_claim,
                    attach_evidence,
                    define_validator,
                    projection_digest,
                    rebuild_projections,
                    record_abstention,
                    run_validator,
                )

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="artifact:release",
                    predicate="status",
                    value="stable",
                    claim_id="artifact-stable",
                    idempotency_key="test:artifact-stable:1",
                    expected_stream_version=0,
                )
                attach_evidence(
                    conn,
                    project="demo",
                    active_root=root,
                    claim_id="artifact-stable",
                    evidence_id="artifact-proof",
                    source_identifier="artifact.txt",
                    source_hash=digest,
                    method="sha256",
                    polarity="supporting",
                    authority_class="direct-file",
                    confidence=1.0,
                    provenance={"path": "artifact.txt"},
                    idempotency_key="test:artifact-proof:1",
                    expected_stream_version=0,
                )
                record_abstention(
                    conn,
                    project="demo",
                    active_root=root,
                    query_scope="Is every operating system qualified?",
                    missing_evidence=["macOS"],
                    unresolved_conflicts=[],
                    minimum_revalidation_action="Run macOS CI.",
                    abstention_id="cross-platform-gap",
                    idempotency_key="test:cross-platform-gap:1",
                    expected_stream_version=0,
                )
                define_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="artifact-sha",
                    validator_type="file_sha256",
                    claim_id="artifact-stable",
                    config={"path": "artifact.txt", "sha256": digest},
                    failure_effect="stale",
                    idempotency_key="test:artifact-sha:1",
                    expected_stream_version=0,
                )
                run_validator(
                    conn,
                    project="demo",
                    active_root=root,
                    validator_id="artifact-sha",
                    idempotency_key="test:artifact-sha:run:1",
                    expected_stream_version=1,
                )
                before = projection_digest(conn, project="demo")
                for table in (
                    "truth_evidence",
                    "truth_abstentions",
                    "truth_validator_results",
                    "truth_validators",
                    "truth_claim_versions",
                ):
                    conn.execute(f"DELETE FROM {table}")
                conn.commit()

                rebuilt = rebuild_projections(
                    conn, project="demo", active_root=root
                )

                self.assertEqual(rebuilt["projection_digest"], before)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_evidence").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_abstentions").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_validators").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_validator_results").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_duplicate_idempotency_key_returns_original_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim

                arguments = {
                    "project": "demo",
                    "active_root": root,
                    "subject": "release:v0.7",
                    "predicate": "status",
                    "value": "candidate",
                    "claim_id": "release-status",
                    "idempotency_key": "test:claim:release-status:1",
                    "expected_stream_version": 0,
                    "valid_from": "2026-08-22T00:00:00+00:00",
                }
                original = append_claim(conn, **arguments)
                duplicate = append_claim(conn, **arguments)

                self.assertTrue(duplicate["idempotent_replay"])
                self.assertEqual(
                    duplicate["event"]["event_id"], original["event"]["event_id"]
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_truth_events_reject_direct_update_and_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim

                append_claim(
                    conn,
                    project="demo",
                    active_root=root,
                    subject="release:v0.7",
                    predicate="status",
                    value="candidate",
                    claim_id="release-status",
                    idempotency_key="test:claim:release-status:1",
                    expected_stream_version=0,
                )
                event_id = conn.execute(
                    "SELECT event_id FROM truth_events LIMIT 1"
                ).fetchone()[0]

                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "truth events are immutable"
                ):
                    conn.execute(
                        "UPDATE truth_events SET actor_id = 'other' WHERE event_id = ?",
                        (event_id,),
                    )
                conn.rollback()
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "truth events are immutable"
                ):
                    conn.execute(
                        "DELETE FROM truth_events WHERE event_id = ?", (event_id,)
                    )
                conn.rollback()
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_wrong_expected_stream_version_fails_without_partial_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                try:
                    from rta_brain.temporal import StreamVersionConflict, append_claim
                except ImportError:
                    self.fail("typed stream-version conflicts are not implemented")

                with self.assertRaises(StreamVersionConflict) as raised:
                    append_claim(
                        conn,
                        project="demo",
                        active_root=root,
                        subject="release:v0.7",
                        predicate="status",
                        value="candidate",
                        claim_id="release-status",
                        idempotency_key="test:claim:release-status:stale",
                        expected_stream_version=1,
                    )

                self.assertEqual(raised.exception.expected, 1)
                self.assertEqual(raised.exception.actual, 0)
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0],
                    0,
                )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_claim_versions").fetchone()[0],
                    0,
                )
            finally:
                conn.close()

    def test_agent_cannot_mutate_or_downgrade_operator_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import (
                    append_claim,
                    define_validator,
                    relate_claims,
                    revise_claim,
                )

                append_claim(
                    conn, project="demo", active_root=root, claim_id="owner-claim",
                    subject="release", predicate="status", value="approved",
                    epistemic_state="accepted", idempotency_key="authority:owner:1",
                    expected_stream_version=0,
                )
                append_claim(
                    conn, project="demo", active_root=root, claim_id="agent-claim",
                    subject="release", predicate="status", value="questioned",
                    authority_class="agent-proposal", actor_type="agent", actor_id="codex",
                    idempotency_key="authority:agent:1", expected_stream_version=0,
                )
                with self.assertRaises(PermissionError):
                    revise_claim(
                        conn, project="demo", active_root=root, claim_id="owner-claim",
                        value="replaced", reason="agent rewrite",
                        idempotency_key="authority:rewrite:2", expected_stream_version=1,
                        actor_type="agent", actor_id="codex",
                    )
                with self.assertRaises(PermissionError):
                    relate_claims(
                        conn, project="demo", active_root=root,
                        from_claim_id="agent-claim", relation_type="contradicts",
                        to_claim_id="owner-claim", relation_id="authority-conflict",
                        idempotency_key="authority:relation:1", expected_stream_version=0,
                        actor_type="agent", actor_id="codex",
                    )
                with self.assertRaises(PermissionError):
                    define_validator(
                        conn, project="demo", active_root=root,
                        validator_id="agent-refute", validator_type="file_exists",
                        claim_id="owner-claim", config={"path": "missing.txt"},
                        failure_effect="refuted", idempotency_key="authority:validator:1",
                        expected_stream_version=0, actor_type="agent", actor_id="codex",
                    )
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0], 2
                )
            finally:
                conn.close()

    def test_idempotency_key_is_bound_to_request_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            conn = db.connect(Path(tmp) / "brain.sqlite")
            try:
                db.init_project(conn, "demo", str(root))
                from rta_brain.temporal import append_claim

                request = {
                    "conn": conn,
                    "project": "demo",
                    "active_root": root,
                    "claim_id": "claim-a",
                    "subject": "a",
                    "predicate": "value",
                    "value": 1,
                    "idempotency_key": "shared-key",
                    "expected_stream_version": 0,
                }
                with patch(
                    "rta_brain.temporal.db.now_iso",
                    side_effect=[
                        "2026-08-23T10:00:00+00:00",
                        "2026-08-23T10:00:01+00:00",
                        "2026-08-23T10:00:02+00:00",
                    ],
                ):
                    append_claim(**request)
                    replay = append_claim(**request)
                    self.assertTrue(replay["idempotent_replay"])
                    with self.assertRaisesRegex(ValueError, "different truth request"):
                        append_claim(**{**request, "claim_id": "claim-b", "subject": "b"})
                self.assertEqual(
                    conn.execute("SELECT COUNT(*) FROM truth_events").fetchone()[0], 1
                )
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
