import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from rta_brain import capture as capture_module
from rta_brain import db
from rta_brain.capture import (
    append_event,
    bind_session,
    close_session_binding,
    delete_capture_content,
    read_capture_replay,
    rebuild_projections,
    register_policy,
    register_source,
    verify_journal,
)
from rta_brain.capture_control import capture_diagnostics, capture_replay
from rta_brain.capture_types import CapturePolicy, CaptureSource, NormalizedEvent


class CaptureJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        self.database = self.base / "brain.sqlite"
        self.conn = db.connect(self.database)
        db.init_project(self.conn, "demo", str(self.root))
        self.policy = CapturePolicy.continuity()
        register_policy(
            self.conn,
            project="demo",
            active_root=self.root,
            policy_id="continuity",
            policy_version=1,
            policy=self.policy,
        )
        self.source = CaptureSource(
            source_id="codex-local",
            adapter="codex-jsonl",
            adapter_version="1",
            installation_scope="transcript",
            config_fingerprint=hashlib.sha256(b"capture-test-source").hexdigest(),
        )
        register_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source=self.source,
            policy_digest=self.policy.digest,
        )

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def event(
        self,
        cursor: str,
        name: str = "turn.started.v1",
        *,
        session: str = "session-a",
        occurred_at: str | None = "2026-08-22T09:00:00+00:00",
        observed_at: str = "2026-08-22T09:00:01+00:00",
        attributes: dict | None = None,
        external_event_id: str | None = None,
        causation_event_id: str | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        parent_span_id: str | None = None,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            event_name=name,
            session_id=session,
            source_cursor=cursor,
            observed_at=observed_at,
            occurred_at=occurred_at,
            attributes=attributes or {},
            external_event_id=external_event_id,
            causation_event_id=causation_event_id,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            actor_type="agent",
            actor_id="actor-opaque",
        )

    def append(self, event: NormalizedEvent, key: str, **kwargs):
        return append_event(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=self.source.source_id,
            event=event,
            idempotency_key=key,
            cursor_kind="sequence",
            original_bytes=100,
            redaction_count=0,
            truncation_count=0,
            **kwargs,
        )

    def test_register_policy_is_immutable_and_source_is_policy_bound(self):
        duplicate = register_policy(
            self.conn,
            project="demo",
            active_root=self.root,
            policy_id="continuity",
            policy_version=1,
            policy=self.policy,
        )
        self.assertTrue(duplicate["idempotent_replay"])

        with self.assertRaisesRegex(ValueError, "policy version"):
            register_policy(
                self.conn,
                project="demo",
                active_root=self.root,
                policy_id="continuity",
                policy_version=1,
                policy=CapturePolicy.metadata_only(),
            )

        row = self.conn.execute(
            "SELECT policy_digest, repository_identity, checkout_identity FROM capture_sources"
        ).fetchone()
        project = self.conn.execute(
            "SELECT repository_identity, checkout_identity FROM projects WHERE name = 'demo'"
        ).fetchone()
        self.assertEqual(row["policy_digest"], self.policy.digest)
        self.assertEqual(row["repository_identity"], project["repository_identity"])
        self.assertEqual(row["checkout_identity"], project["checkout_identity"])

    def test_append_is_sequenced_idempotent_and_conflicts_on_changed_request(self):
        first = self.append(self.event("1"), "event:1")
        duplicate = self.append(self.event("1"), "event:1")

        self.assertEqual(first["event_id"], duplicate["event_id"])
        self.assertEqual(first["project_sequence"], 1)
        self.assertTrue(duplicate["idempotent_replay"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0], 1)

        with self.assertRaisesRegex(ValueError, "idempotency key"):
            self.append(self.event("2", name="turn.completed.v1"), "event:1")

    def test_journal_rejects_attributes_outside_the_bound_policy(self):
        metadata = CapturePolicy.metadata_only()
        register_policy(
            self.conn,
            project="demo",
            active_root=self.root,
            policy_id="metadata",
            policy_version=1,
            policy=metadata,
        )
        source = CaptureSource(
            source_id="metadata-source",
            adapter="generic",
            adapter_version="1",
            installation_scope="api",
            config_fingerprint=hashlib.sha256(b"metadata-source").hexdigest(),
        )
        register_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source=source,
            policy_digest=metadata.digest,
        )
        with self.assertRaisesRegex(ValueError, "allowlist"):
            append_event(
                self.conn,
                project="demo",
                active_root=self.root,
                source_id=source.source_id,
                event=self.event(
                    "1",
                    name="agent.message.v1",
                    attributes={"text": "synthetic-secret-value"},
                ),
                idempotency_key="metadata:secret",
                cursor_kind="sequence",
                original_bytes=30,
            )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM capture_events WHERE source_id = 'metadata-source'"
            ).fetchone()[0],
            0,
        )

    def test_normalized_event_attributes_are_a_deep_immutable_snapshot(self):
        original = {"metadata": {"nested": ["safe"]}}
        event = self.event(
            "1",
            name="tool.completed.v1",
            attributes=original,
        )
        original["metadata"]["nested"][0] = "mutated outside"

        self.assertEqual(event.attributes["metadata"]["nested"], ["safe"])
        with self.assertRaisesRegex(TypeError, "immutable"):
            event.attributes["metadata"]["nested"].append("mutated inside")
        with self.assertRaisesRegex(TypeError, "immutable"):
            event.attributes["metadata"] = {"nested": []}

    def test_journal_rechecks_field_and_collection_budgets(self):
        bounded = CapturePolicy(
            profile="continuity",
            field_allowlist={"agent.message.v1": ("text", "metadata")},
            max_field_chars=256,
            max_collection_items=2,
        )
        register_policy(
            self.conn,
            project="demo",
            active_root=self.root,
            policy_id="bounded",
            policy_version=1,
            policy=bounded,
        )
        source = CaptureSource(
            source_id="bounded-source",
            adapter="generic",
            adapter_version="1",
            installation_scope="api",
            config_fingerprint=hashlib.sha256(b"bounded-source").hexdigest(),
        )
        register_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source=source,
            policy_digest=bounded.digest,
        )
        for cursor, attributes, message in (
            ("1", {"text": "x" * 257}, "character"),
            ("2", {"metadata": [1, 2, 3]}, "collection"),
            ("3", {"metadata": {"k" * 257: "value"}}, "character"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                append_event(
                    self.conn,
                    project="demo",
                    active_root=self.root,
                    source_id=source.source_id,
                    event=self.event(
                        cursor,
                        name="agent.message.v1",
                        attributes=attributes,
                    ),
                    idempotency_key=f"bounded:{cursor}",
                    cursor_kind="sequence",
                    original_bytes=100,
                )

    def test_journal_checks_the_complete_normalized_event_budget(self):
        bounded = CapturePolicy(
            profile="continuity",
            field_allowlist={"agent.message.v1": ("text",)},
            max_event_bytes=1_024,
        )
        register_policy(
            self.conn,
            project="demo",
            active_root=self.root,
            policy_id="whole-event-budget",
            policy_version=1,
            policy=bounded,
        )
        source = CaptureSource(
            source_id="whole-event-source",
            adapter="generic",
            adapter_version="1",
            installation_scope="api",
            config_fingerprint=hashlib.sha256(b"whole-event-source").hexdigest(),
        )
        register_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source=source,
            policy_digest=bounded.digest,
        )
        oversized = NormalizedEvent(
            event_name="agent.message.v1",
            session_id="s" * 500,
            source_cursor="9" * 500,
            observed_at="2026-08-22T09:00:01+00:00",
            occurred_at="2026-08-22T09:00:00+00:00",
            attributes={"text": "x" * 200},
        )
        with self.assertRaisesRegex(ValueError, "normalized capture event"):
            append_event(
                self.conn,
                project="demo",
                active_root=self.root,
                source_id=source.source_id,
                event=oversized,
                idempotency_key="whole-event:oversized",
                cursor_kind="opaque",
                original_bytes=10,
            )

    def test_numeric_source_cursor_must_advance(self):
        self.append(self.event("10"), "event:10")
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.append(self.event("9"), "event:9")
        with self.assertRaisesRegex(ValueError, "cursor"):
            self.append(self.event("10"), "event:10-other")

    def test_late_and_time_skew_flags_are_derived_without_changing_event_time(self):
        self.append(
            self.event(
                "1",
                occurred_at="2026-08-22T09:10:00+00:00",
                observed_at="2026-08-22T09:10:01+00:00",
            ),
            "event:late-base",
        )
        late = self.append(
            self.event(
                "2",
                occurred_at="2026-08-22T09:00:00+00:00",
                observed_at="2026-08-22T09:11:00+00:00",
            ),
            "event:late",
        )
        skewed = self.append(
            self.event(
                "3",
                occurred_at="2026-08-22T11:00:00+00:00",
                observed_at="2026-08-22T09:12:00+00:00",
            ),
            "event:skew",
        )

        self.assertTrue(late["flags"]["late"])
        self.assertTrue(skewed["flags"]["time_skew"])
        row = self.conn.execute(
            "SELECT occurred_at, attributes_json FROM capture_events WHERE event_id = ?",
            (late["event_id"],),
        ).fetchone()
        self.assertEqual(row["occurred_at"], "2026-08-22T09:00:00+00:00")
        self.assertTrue(json.loads(row["attributes_json"])["_capture"]["late"])

    def test_causal_links_and_repository_anchors_are_preserved(self):
        first = self.append(
            self.event(
                "1",
                external_event_id="external-a",
                trace_id="1" * 32,
                span_id="2" * 16,
            ),
            "event:causal-a",
            repository_ref="feature/test",
            repository_commit="a" * 40,
            dirty_digest="b" * 64,
        )
        second = self.append(
            self.event(
                "2",
                name="turn.completed.v1",
                causation_event_id="external-a",
                trace_id="1" * 32,
                span_id="3" * 16,
            ),
            "event:causal-b",
        )

        row = self.conn.execute(
            "SELECT repository_ref, repository_commit, dirty_digest FROM capture_events WHERE event_id = ?",
            (first["event_id"],),
        ).fetchone()
        self.assertEqual(dict(row), {
            "repository_ref": "feature/test",
            "repository_commit": "a" * 40,
            "dirty_digest": "b" * 64,
        })
        projection = rebuild_projections(
            self.conn, project="demo", active_root=self.root,
        )
        self.assertEqual(projection["causal_links"][0]["event_id"], second["event_id"])
        self.assertEqual(projection["causal_links"][0]["caused_by"], first["event_id"])

    def test_projection_does_not_join_reused_external_ids_across_sources(self):
        second_source = CaptureSource(
            source_id="cursor-local",
            adapter="cursor-hooks",
            adapter_version="1",
            installation_scope="project",
            config_fingerprint=hashlib.sha256(b"second-capture-source").hexdigest(),
        )
        register_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source=second_source,
            policy_digest=self.policy.digest,
        )
        self.append(
            self.event("1", external_event_id="shared-external-id"),
            "event:source-one",
        )
        append_event(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=second_source.source_id,
            event=self.event(
                "1",
                name="turn.completed.v1",
                causation_event_id="shared-external-id",
            ),
            idempotency_key="event:source-two",
            cursor_kind="sequence",
            original_bytes=10,
        )

        projection = rebuild_projections(
            self.conn, project="demo", active_root=self.root,
        )
        self.assertEqual(projection["causal_links"], [])
        self.assertEqual(projection["unresolved_causes"], 1)
        self.assertEqual(
            set(projection["sessions"]),
            {'["codex-local","session-a"]', '["cursor-local","session-a"]'},
        )

    def test_late_detection_is_scoped_to_source_and_session(self):
        second_source = CaptureSource(
            source_id="late-source-two",
            adapter="generic",
            adapter_version="1",
            installation_scope="api",
            config_fingerprint=hashlib.sha256(b"late-source-two").hexdigest(),
        )
        register_source(
            self.conn,
            project="demo",
            active_root=self.root,
            source=second_source,
            policy_digest=self.policy.digest,
        )
        self.append(
            self.event(
                "1",
                occurred_at="2026-08-22T10:00:00+00:00",
                observed_at="2026-08-22T10:00:01+00:00",
            ),
            "late-scope:first-source",
        )
        result = append_event(
            self.conn,
            project="demo",
            active_root=self.root,
            source_id=second_source.source_id,
            event=self.event(
                "1",
                occurred_at="2026-08-22T09:00:00+00:00",
                observed_at="2026-08-22T09:00:01+00:00",
            ),
            idempotency_key="late-scope:second-source",
            cursor_kind="sequence",
            original_bytes=10,
        )
        self.assertFalse(result["flags"]["late"])

    def test_projection_session_key_is_collision_free(self):
        for source_id in ("a:b", "a"):
            source = CaptureSource(
                source_id=source_id,
                adapter="generic",
                adapter_version="1",
                installation_scope="api",
                config_fingerprint=hashlib.sha256(source_id.encode()).hexdigest(),
            )
            register_source(
                self.conn,
                project="demo",
                active_root=self.root,
                source=source,
                policy_digest=self.policy.digest,
            )
        for source_id, session_id, key in (
            ("a:b", "c", "collision:a"),
            ("a", "b:c", "collision:b"),
        ):
            append_event(
                self.conn,
                project="demo",
                active_root=self.root,
                source_id=source_id,
                event=self.event("1", session=session_id),
                idempotency_key=key,
                cursor_kind="sequence",
                original_bytes=10,
            )
        projection = rebuild_projections(
            self.conn, project="demo", active_root=self.root,
        )
        self.assertEqual(
            set(projection["sessions"]),
            {'["a","b:c"]', '["a:b","c"]'},
        )

    def test_hash_chain_verification_and_immutability(self):
        first = self.append(self.event("1"), "event:hash-1")
        second = self.append(self.event("2"), "event:hash-2")
        self.assertEqual(second["previous_event_hash"], first["event_hash"])
        verified = verify_journal(self.conn, project="demo")
        self.assertTrue(verified["chain_valid"])
        self.assertEqual(verified["events_verified"], 2)

        bounded = verify_journal(self.conn, project="demo", max_events=1)
        self.assertTrue(bounded["chain_valid"])
        self.assertEqual(bounded["events_verified"], 1)
        self.assertFalse(bounded["verification_complete"])
        self.assertEqual(bounded["verification_scope"], "prefix")
        self.assertEqual(bounded["next_sequence"], 1)

        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.conn.execute(
                "UPDATE capture_events SET event_name = 'turn.completed.v1' WHERE event_id = ?",
                (first["event_id"],),
            )

    def test_replay_reads_content_and_tombstones_in_one_snapshot(self):
        self.append(self.event("1"), "event:transactional-replay")
        transaction_states = []

        def trace(statement):
            if "FROM capture_tombstones" in statement:
                transaction_states.append(self.conn.in_transaction)

        self.conn.set_trace_callback(trace)
        try:
            replay = read_capture_replay(self.conn, project="demo", limit=10)
        finally:
            self.conn.set_trace_callback(None)

        self.assertEqual(len(replay["events"]), 1)
        self.assertEqual(transaction_states, [True, True, True, True])
        self.assertFalse(self.conn.in_transaction)

    def test_default_capture_diagnostics_bounds_journal_verification(self):
        self.append(self.event("1"), "event:bounded-diagnostics")

        with patch(
            "rta_brain.capture_control.verify_journal",
            wraps=verify_journal,
        ) as verifier:
            result = capture_diagnostics(
                self.conn,
                database=self.database,
                project="demo",
                active_root=self.root,
            )

        verifier.assert_called_once_with(
            self.conn,
            project="demo",
            max_events=1_000,
        )
        self.assertTrue(result["journal"]["verification_complete"])

    def test_explicit_binding_accepts_only_current_cursor_forward(self):
        receipt = bind_session(
            self.conn,
            database=self.database,
            project="demo",
            active_root=self.root,
            source_id=self.source.source_id,
            external_session_id="outside-session",
            cursor_kind="sequence",
            start_cursor="50",
            operator_id="operator-local",
        )
        with self.assertRaisesRegex(ValueError, "predates"):
            self.append(
                self.event("49", session="outside-session"),
                "event:pre-bind",
                binding_id=receipt["binding_id"],
            )
        accepted = self.append(
            self.event("50", session="outside-session"),
            "event:at-bind",
            binding_id=receipt["binding_id"],
        )
        self.assertEqual(accepted["project_sequence"], 1)
        exact = self.append(
            self.event("50", session="outside-session"),
            "event:at-bind",
            binding_id=receipt["binding_id"],
        )
        self.assertTrue(exact["idempotent_replay"])
        for label, overrides in (
            ("binding", {"binding_id": None}),
            ("cursor kind", {"binding_id": receipt["binding_id"], "cursor_kind": "byte-offset"}),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "idempotency key"):
                append_event(
                    self.conn,
                    project="demo",
                    active_root=self.root,
                    source_id=self.source.source_id,
                    event=self.event("50", session="outside-session"),
                    idempotency_key="event:at-bind",
                    cursor_kind=overrides.get("cursor_kind", "sequence"),
                    original_bytes=100,
                    binding_id=overrides["binding_id"],
                )

    def test_idempotent_replay_requires_identical_repository_anchors(self):
        self.append(
            self.event("1"),
            "event:anchored",
            repository_ref="feature/one",
            repository_commit="a" * 40,
            dirty_digest="b" * 64,
        )
        with self.assertRaisesRegex(ValueError, "idempotency key"):
            self.append(self.event("1"), "event:anchored")

    def test_explicit_binding_rejects_unordered_opaque_cursor(self):
        with self.assertRaisesRegex(ValueError, "ordered"):
            bind_session(
                self.conn,
                database=self.database,
                project="demo",
                active_root=self.root,
                source_id=self.source.source_id,
                external_session_id="outside-session",
                cursor_kind="opaque",
                start_cursor="cursor-now",
                operator_id="operator-local",
            )

    def test_closed_and_stale_bindings_fail_without_foreign_paths(self):
        receipt = bind_session(
            self.conn,
            database=self.database,
            project="demo",
            active_root=self.root,
            source_id=self.source.source_id,
            external_session_id="outside-session",
            cursor_kind="sequence",
            start_cursor="1",
            operator_id="operator-local",
        )
        close_session_binding(
            self.conn,
            database=self.database,
            project="demo",
            active_root=self.root,
            binding_id=receipt["binding_id"],
            operator_id="operator-local",
        )
        with self.assertRaisesRegex(ValueError, "not active") as closed:
            self.append(
                self.event("1", session="outside-session"),
                "event:closed",
                binding_id=receipt["binding_id"],
            )
        self.assertNotIn(str(self.root), str(closed.exception))

        project = self.conn.execute(
            "SELECT * FROM projects WHERE name = 'demo'"
        ).fetchone()
        stale_id = "stale-binding-receipt"
        self.conn.execute(
            """
            INSERT INTO capture_session_bindings(
                project_id, binding_id, source_id, external_session_id,
                cursor_kind, start_cursor, root_fingerprint,
                repository_identity, checkout_identity, status,
                created_by_type, created_by_id, created_at
            ) VALUES (?, ?, ?, 'stale-session', 'sequence', '1', ?, ?,
                      'stale-checkout', 'active', 'operator', 'operator-local', ?)
            """,
            (
                int(project["id"]), stale_id, self.source.source_id,
                hashlib.sha256(str(self.root.resolve()).lower().encode()).hexdigest(),
                project["repository_identity"], db.now_iso(),
            ),
        )
        self.conn.commit()
        with self.assertRaisesRegex(ValueError, "binding drifted") as drifted:
            self.append(
                self.event("1", session="stale-session"),
                "event:stale",
                binding_id=stale_id,
            )
        self.assertNotIn(str(self.root), str(drifted.exception))

    def test_session_binding_receipt_identity_is_immutable(self):
        receipt = bind_session(
            self.conn,
            database=self.database,
            project="demo",
            active_root=self.root,
            source_id=self.source.source_id,
            external_session_id="immutable-session",
            cursor_kind="sequence",
            start_cursor="1",
            operator_id="operator-local",
        )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.conn.execute(
                "UPDATE capture_session_bindings SET start_cursor = '0' WHERE binding_id = ?",
                (receipt["binding_id"],),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
            self.conn.execute(
                "DELETE FROM capture_session_bindings WHERE binding_id = ?",
                (receipt["binding_id"],),
            )

    def test_wrong_and_ambiguous_roots_fail_closed(self):
        other = self.base / "other"
        other.mkdir()
        with self.assertRaisesRegex(ValueError, "canonical") as mismatch:
            register_policy(
                self.conn,
                project="demo",
                active_root=other,
                policy_id="other",
                policy_version=1,
                policy=CapturePolicy.metadata_only(),
            )
        self.assertNotIn(str(self.root), str(mismatch.exception))
        self.assertNotIn(str(other), str(mismatch.exception))

        db.init_project(self.conn, "duplicate", str(self.root))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.append(self.event("1"), "event:ambiguous")

    def test_capture_reads_reject_a_replaced_checkout_at_the_same_path(self):
        self.append(self.event("1"), "event:before-replacement")
        displaced = self.base / "repo-displaced"
        self.root.rename(displaced)
        self.root.mkdir()

        with self.assertRaisesRegex(ValueError, "canonical project binding|binding drifted"):
            capture_replay(
                self.conn,
                project="demo",
                active_root=self.root,
            )
        with self.assertRaisesRegex(ValueError, "canonical project binding|binding drifted"):
            capture_diagnostics(
                self.conn,
                database=self.database,
                project="demo",
                active_root=self.root,
            )

    def test_session_binding_rejects_credential_shaped_external_session_id(self):
        with self.assertRaisesRegex(ValueError, "external_session_id contains sensitive"):
            bind_session(
                self.conn,
                database=self.database,
                project="demo",
                active_root=self.root,
                source_id=self.source.source_id,
                external_session_id="Authorization: Bearer synthetic-session-secret-123456",
                cursor_kind="sequence",
                start_cursor="1",
                operator_id="operator-local",
            )

        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM capture_session_bindings").fetchone()[0],
            0,
        )

    def test_binding_cannot_close_another_projects_receipt(self):
        other_root = self.base / "other-project"
        other_root.mkdir()
        db.init_project(self.conn, "other-project", str(other_root))
        register_policy(
            self.conn,
            project="other-project",
            active_root=other_root,
            policy_id="continuity",
            policy_version=1,
            policy=self.policy,
        )
        register_source(
            self.conn,
            project="other-project",
            active_root=other_root,
            source=self.source,
            policy_digest=self.policy.digest,
        )
        foreign = bind_session(
            self.conn,
            database=self.database,
            project="other-project",
            active_root=other_root,
            source_id=self.source.source_id,
            external_session_id="shared-session",
            cursor_kind="sequence",
            start_cursor="10",
            operator_id="operator-local",
        )
        with self.assertRaisesRegex(ValueError, "another project"):
            bind_session(
                self.conn,
                database=self.database,
                project="demo",
                active_root=self.root,
                source_id=self.source.source_id,
                external_session_id="shared-session",
                cursor_kind="sequence",
                start_cursor="10",
                operator_id="operator-local",
            )
        status = self.conn.execute(
            "SELECT status FROM capture_session_bindings WHERE binding_id = ?",
            (foreign["binding_id"],),
        ).fetchone()["status"]
        self.assertEqual(status, "active")

    def test_projection_rebuild_is_deterministic_and_tracks_recovery_state(self):
        self.append(
            self.event("1", name="session.started.v1"),
            "event:session",
        )
        self.append(
            self.event("2", name="tool.started.v1", span_id="1" * 16),
            "event:tool-start",
        )
        self.append(
            self.event(
                "3",
                name="turn.interrupted.v1",
                attributes={"summary": "retained projection content"},
            ),
            "event:interrupt",
        )
        self.append(self.event("4", name="capture.gap.v1"), "event:gap", gap_state="detected")
        checkpoint = self.append(
            self.event("5", name="checkpoint.created.v1"), "event:checkpoint",
        )

        first = rebuild_projections(self.conn, project="demo", active_root=self.root)
        second = rebuild_projections(self.conn, project="demo", active_root=self.root)

        self.assertEqual(first["projection_digest"], second["projection_digest"])
        session = first["sessions"]['["codex-local","session-a"]']
        self.assertTrue(session["interrupted"])
        self.assertEqual(session["latest_checkpoint_sequence"], checkpoint["project_sequence"])
        self.assertEqual(session["gaps"], 1)
        self.assertEqual(session["incomplete_spans"], ["1" * 16])

    def test_replay_is_chronological_causal_and_surfaces_recovery_markers(self):
        started = self.append(
            self.event(
                "1", name="tool.started.v1", external_event_id="tool-start",
                trace_id="1" * 32, span_id="2" * 16,
            ),
            "event:tool-start",
        )
        self.append(
            self.event(
                "2", name="turn.interrupted.v1",
                attributes={"reason": "operator pause", "summary": "resume validation"},
                causation_event_id=started["event_id"], trace_id="1" * 32,
                parent_span_id="2" * 16,
            ),
            "event:interrupt",
        )
        self.append(
            self.event(
                "3", name="capture.gap.v1",
                attributes={"reason": "bounded tail", "from_cursor": "3", "to_cursor": "8"},
            ),
            "event:gap",
            gap_state="detected",
        )

        chronological = read_capture_replay(
            self.conn, project="demo", mode="chronological", limit=10,
        )
        causal = read_capture_replay(
            self.conn, project="demo", mode="causal", limit=10,
        )

        self.assertEqual(
            [event["project_sequence"] for event in chronological["events"]],
            [1, 2, 3],
        )
        self.assertEqual(
            causal["causal_edges"],
            [{"from": started["event_id"], "to": causal["events"][1]["event_id"]}],
        )
        self.assertEqual(causal["coverage"]["gap_events"], 1)
        self.assertEqual(causal["coverage"]["incomplete_spans"], 1)
        self.assertEqual(causal["coverage"]["interrupted_sessions"], 1)
        self.assertEqual(causal["interruption_snapshot"]["status"], "interrupted")
        self.assertFalse(causal["executes_actions"])

    def test_replay_is_bounded_and_deterministic(self):
        for index in range(12):
            self.append(
                self.event(str(index + 1), name="turn.started.v1"),
                f"event:{index}",
            )

        first = read_capture_replay(
            self.conn, project="demo", mode="chronological", limit=5, max_bytes=16_384,
        )
        second = read_capture_replay(
            self.conn, project="demo", mode="chronological", limit=5, max_bytes=16_384,
        )

        self.assertEqual(first, second)
        self.assertEqual(len(first["events"]), 5)
        self.assertFalse(first["complete"])
        self.assertEqual(first["truncated_by"], "row-limit")
        self.assertRegex(first["replay_digest"], r"^[0-9a-f]{64}$")

    def test_replay_integrity_decodes_each_selected_content_record_once(self):
        for index in range(3):
            self.append(
                self.event(
                    str(index + 1),
                    name="agent.message.v1",
                    attributes={"text": f"verified observation {index}"},
                ),
                f"event:decode:{index}",
            )

        with patch.object(
            capture_module,
            "_event_content",
            wraps=capture_module._event_content,
        ) as decode:
            replay = read_capture_replay(self.conn, project="demo", limit=10)

        self.assertEqual(len(replay["events"]), 3)
        self.assertEqual(decode.call_count, 3)

    def test_replay_privacy_filter_preserves_chain_verification_across_hidden_rows(self):
        self.append(
            self.event("1", name="turn.started.v1"),
            "event:sensitive",
            privacy_class="internal",
        )
        self.append(
            self.event("2", name="turn.completed.v1"),
            "event:public",
            privacy_class="public",
        )

        replay = read_capture_replay(
            self.conn, project="demo", privacy_ceiling="public", limit=10,
        )

        self.assertEqual(len(replay["events"]), 1)
        self.assertEqual(replay["events"][0]["project_sequence"], 1)
        self.assertEqual(replay["next_cursor"], 1)
        self.assertNotIn("source_cursor", replay["events"][0])

    def test_public_replay_skips_hidden_content_but_internal_replay_verifies_it(self):
        self.append(
            self.event(
                "1",
                name="agent.message.v1",
                attributes={"text": "hidden original"},
            ),
            "event:hidden-tamper",
            privacy_class="internal",
        )
        self.append(
            self.event("2", name="turn.completed.v1"),
            "event:visible-after-tamper",
            privacy_class="public",
        )
        tampered = '{"text":"hidden tampered"}'
        self.conn.execute(
            "UPDATE capture_event_content SET content_json = ?, content_sha256 = ? "
            "WHERE event_row_id = (SELECT id FROM capture_events WHERE project_sequence = 1)",
            (tampered, hashlib.sha256(tampered.encode("utf-8")).hexdigest()),
        )
        self.conn.commit()

        public_replay = read_capture_replay(
            self.conn,
            project="demo",
            privacy_ceiling="public",
            limit=10,
        )
        self.assertEqual(len(public_replay["events"]), 1)
        self.assertEqual(
            public_replay["coverage"]["journal_verification_scope"],
            "privacy-projected-visible-events-with-predecessor-links",
        )

        with self.assertRaisesRegex(ValueError, "normalized hash"):
            read_capture_replay(
                self.conn,
                project="demo",
                privacy_ceiling="internal",
                limit=10,
            )

    def test_replay_verifies_the_paginated_anchor_before_resuming(self):
        self.append(
            self.event(
                "1",
                name="agent.message.v1",
                attributes={"text": "anchor original"},
            ),
            "event:anchor-tamper",
        )
        self.append(
            self.event("2", name="turn.completed.v1"),
            "event:after-anchor",
        )
        tampered = '{"text":"anchor tampered"}'
        self.conn.execute(
            "UPDATE capture_event_content SET content_json = ?, content_sha256 = ? "
            "WHERE event_row_id = (SELECT id FROM capture_events WHERE project_sequence = 1)",
            (tampered, hashlib.sha256(tampered.encode("utf-8")).hexdigest()),
        )
        self.conn.commit()

        with self.assertRaisesRegex(ValueError, "normalized hash"):
            read_capture_replay(
                self.conn,
                project="demo",
                after_sequence=1,
                limit=10,
            )

    def test_logically_deleted_capture_content_never_reappears_in_replay(self):
        created = self.append(
            self.event(
                "1", name="agent.message.v1",
                attributes={"text": "private deleted observation"},
            ),
            "event:deleted",
        )
        preview = delete_capture_content(
            self.conn,
            project="demo",
            active_root=self.root,
            scope="event-content",
            scope_token=created["event_id"],
            reason_class="operator-request",
            actor_id="operator-local",
            policy_digest=self.policy.digest,
        )
        delete_capture_content(
            self.conn,
            project="demo",
            active_root=self.root,
            scope="event-content",
            scope_token=created["event_id"],
            reason_class="operator-request",
            actor_id="operator-local",
            policy_digest=self.policy.digest,
            confirm=True,
            confirmation_token=preview["confirmation_token"],
        )

        replay = read_capture_replay(self.conn, project="demo", limit=10)

        self.assertNotIn("private deleted observation", repr(replay))
        self.assertEqual(replay["events"][0]["attributes"], {})
        self.assertEqual(replay["events"][0]["content_state"], "logically-deleted")

    def test_concurrent_append_assigns_unique_project_sequences(self):
        errors: list[BaseException] = []

        def worker(index: int) -> None:
            conn = db.connect(self.database)
            try:
                append_event(
                    conn,
                    project="demo",
                    active_root=self.root,
                    source_id=self.source.source_id,
                    event=self.event(str(index + 1), session=f"session-{index}"),
                    idempotency_key=f"concurrent:{index}",
                    cursor_kind="sequence",
                    original_bytes=10,
                )
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                errors.append(exc)
            finally:
                conn.close()

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        sequences = [
            row[0]
            for row in self.conn.execute(
                "SELECT project_sequence FROM capture_events ORDER BY project_sequence"
            )
        ]
        self.assertEqual(sequences, list(range(1, 9)))


if __name__ == "__main__":
    unittest.main()
