import hashlib
import json
from pathlib import Path

import pytest

from rta_brain import db
from rta_brain.capture import (
    append_event,
    export_capture_events,
    read_capture_replay,
    register_policy,
    register_source,
)
from rta_brain.capture_types import CapturePolicy, CaptureSource, NormalizedEvent
from rta_brain.cognition import cognition_snapshot
from rta_brain.context import build_context_pack
from rta_brain.progressive_retrieval import ProgressiveRetriever
from rta_brain.temporal import (
    append_claim,
    attach_evidence,
    relate_claims,
    search_truth,
)


def _project(tmp_path: Path, name: str = "demo"):
    root = tmp_path / "LOCAL-ROOT-MARKER-7F19"
    root.mkdir(parents=True)
    database = tmp_path / "brain.sqlite"
    conn = db.connect(database)
    db.init_project(conn, name, root)
    return conn, root


def _public_retrieval_report(tmp_path: Path, hidden_count: int) -> dict:
    conn, _ = _project(tmp_path)
    try:
        db.remember(
            conn,
            "shared privacy phrase public result",
            project="demo",
            metadata={"privacy_class": "public"},
        )
        for index in range(hidden_count):
            db.remember(
                conn,
                f"shared privacy phrase hidden result {index}",
                project="demo",
                metadata={"privacy_class": "restricted"},
            )
        return ProgressiveRetriever(b"privacy-test-secret").retrieve(
            conn,
            project="demo",
            stage="index",
            query="shared privacy phrase",
            limit=20,
            privacy_ceiling="public",
        )["report"]
    finally:
        conn.close()


def test_public_retrieval_does_not_reveal_hidden_result_cardinality(tmp_path):
    one_hidden = _public_retrieval_report(tmp_path / "one", 1)
    many_hidden = _public_retrieval_report(tmp_path / "many", 7)

    assert one_hidden["privacy_filtered_count"] == 1
    assert many_hidden["privacy_filtered_count"] == 1
    assert one_hidden["privacy_filtered_count"] == many_hidden["privacy_filtered_count"]


def test_public_context_pack_omits_local_and_operational_metadata(tmp_path):
    conn, root = _project(tmp_path)
    try:
        db.remember(
            conn,
            "PUBLIC-CONTEXT-MARKER-52BC",
            project="demo",
            metadata={"privacy_class": "public"},
            provenance={
                "source_path": str(root / "PRIVATE-PROVENANCE-MARKER.txt"),
                "source_hash": "a" * 64,
                "verification_status": "verified",
            },
        )
        db.save_checkpoint(
            conn,
            "demo",
            "PRIVATE-CHECKPOINT-MARKER-184D",
            verified_evidence="PRIVATE-VERIFICATION-MARKER-942A",
            next_action="PRIVATE-NEXT-ACTION-MARKER-11C0",
            source="PRIVATE-SOURCE-MARKER-7A2F",
            trigger="PRIVATE-TRIGGER-MARKER-980E",
        )

        pack = build_context_pack(
            conn,
            "PUBLIC-CONTEXT-MARKER-52BC",
            project="demo",
            privacy_ceiling="public",
        )

        assert "PUBLIC-CONTEXT-MARKER-52BC" in pack
        assert str(root) not in pack
        assert "Canonical repository root" not in pack
        assert "Repository identity" not in pack
        assert "Git snapshot" not in pack
        assert "Index state" not in pack
        assert "stale status" not in pack
        assert "Freshness And Policy" not in pack
        assert "PRIVATE-CHECKPOINT-MARKER-184D" not in pack
        assert "PRIVATE-VERIFICATION-MARKER-942A" not in pack
        assert "PRIVATE-NEXT-ACTION-MARKER-11C0" not in pack
        assert "PRIVATE-SOURCE-MARKER-7A2F" not in pack
        assert "PRIVATE-TRIGGER-MARKER-980E" not in pack
        assert "PRIVATE-PROVENANCE-MARKER" not in pack
        assert "a" * 64 not in pack
    finally:
        conn.close()


def _capture_project(tmp_path: Path):
    conn, root = _project(tmp_path)
    policy = CapturePolicy.continuity()
    register_policy(
        conn,
        project="demo",
        active_root=root,
        policy_id="continuity",
        policy_version=1,
        policy=policy,
    )
    source = CaptureSource(
        source_id="codex-local",
        adapter="codex-jsonl",
        adapter_version="1",
        installation_scope="transcript",
        config_fingerprint=hashlib.sha256(b"privacy-capture-source").hexdigest(),
    )
    register_source(
        conn,
        project="demo",
        active_root=root,
        source=source,
        policy_digest=policy.digest,
    )
    return conn, root, source


def _append_capture(
    conn,
    root,
    source,
    cursor: str,
    privacy_class: str,
    *,
    attributes: dict | None = None,
):
    event = NormalizedEvent(
        event_name="turn.started.v1",
        session_id="session-a",
        source_cursor=cursor,
        observed_at="2026-09-06T00:00:01+00:00",
        occurred_at="2026-09-06T00:00:00+00:00",
        attributes=attributes or {},
        actor_type="agent",
        actor_id="opaque-agent",
    )
    return append_event(
        conn,
        project="demo",
        active_root=root,
        source_id=source.source_id,
        event=event,
        idempotency_key=f"privacy-event:{cursor}",
        cursor_kind="sequence",
        original_bytes=100,
        redaction_count=0,
        truncation_count=0,
        privacy_class=privacy_class,
    )


def test_public_capture_views_do_not_expose_chain_hashes_or_hidden_stream_counters(tmp_path):
    conn, root, source = _capture_project(tmp_path)
    try:
        hidden = _append_capture(conn, root, source, "1", "internal")
        _append_capture(conn, root, source, "2", "public")

        replay = read_capture_replay(
            conn, project="demo", privacy_ceiling="public", limit=20
        )
        exported = export_capture_events(
            conn,
            project="demo",
            active_root=root,
            privacy_ceiling="public",
            limit=20,
        )
        rendered = json.dumps((replay, exported), sort_keys=True)

        assert hidden["event_hash"] not in rendered
        assert hidden["event_id"] not in rendered
        assert "latest_event_hash" not in rendered
        assert "verified_through_sequence" not in rendered
        assert "previous_event_hash" not in rendered
        assert "normalized_sha256" not in rendered
        assert "event_hash" not in replay["events"][0]
        assert "event_hash" not in exported["events"][0]
        assert "source_cursor" not in replay["events"][0]
        assert "source_cursor" not in exported["events"][0]
        assert replay["events"][0]["project_sequence"] == 1
        assert exported["events"][0]["project_sequence"] == 1
        assert replay["next_cursor"] == 1
        assert exported["next_cursor"] == 1
        assert "replay_digest" not in replay
        assert replay["coverage"]["selected_events"] == 1
        assert replay["interruption_snapshot"]["interrupted_sessions"] == 0
    finally:
        conn.close()


def test_public_capture_pagination_uses_only_visible_event_ordinals(tmp_path):
    conn, root, source = _capture_project(tmp_path)
    try:
        for cursor in range(1, 8):
            _append_capture(conn, root, source, str(cursor), "internal")
        _append_capture(conn, root, source, "8", "public")
        for cursor in range(9, 15):
            _append_capture(conn, root, source, str(cursor), "internal")
        _append_capture(conn, root, source, "15", "public")

        first = read_capture_replay(
            conn,
            project="demo",
            privacy_ceiling="public",
            limit=1,
        )
        second = read_capture_replay(
            conn,
            project="demo",
            privacy_ceiling="public",
            after_sequence=first["next_cursor"],
            limit=1,
        )

        assert first["events"][0]["project_sequence"] == 1
        assert first["next_cursor"] == 1
        assert second["events"][0]["project_sequence"] == 2
        assert second["next_cursor"] == 2
        assert second["complete"] is True
    finally:
        conn.close()


def test_hidden_capture_gap_cannot_stall_public_export_or_replay(tmp_path):
    conn, root, source = _capture_project(tmp_path)
    try:
        _append_capture(conn, root, source, "1", "public")
        padding = {"status": "x" * 700}
        _append_capture(
            conn, root, source, "2", "internal", attributes=padding
        )
        _append_capture(
            conn, root, source, "3", "internal", attributes=padding
        )
        _append_capture(conn, root, source, "4", "public")

        readers = (
            lambda cursor: export_capture_events(
                conn,
                project="demo",
                active_root=root,
                privacy_ceiling="public",
                after_sequence=cursor,
                limit=1,
                max_bytes=2_000,
            ),
            lambda cursor: read_capture_replay(
                conn,
                project="demo",
                privacy_ceiling="public",
                after_sequence=cursor,
                limit=1,
                max_bytes=2_000,
            ),
        )
        for read_page in readers:
            first = read_page(0)
            second = read_page(first["next_cursor"])

            assert first["next_cursor"] == 1
            assert len(second["events"]) == 1
            assert second["events"][0]["project_sequence"] == 2
            assert second["next_cursor"] == 2
            assert second["complete"] is True
            verification_scope = second.get(
                "journal_verification_scope",
                second.get("coverage", {}).get("journal_verification_scope"),
            )
            assert verification_scope == (
                "privacy-projected-visible-events-with-predecessor-links"
            )
    finally:
        conn.close()


def test_out_of_range_public_cursor_is_rejected_before_offset_lookup(tmp_path):
    conn, root, source = _capture_project(tmp_path)
    try:
        _append_capture(conn, root, source, "1", "public")
        statements: list[str] = []
        conn.set_trace_callback(statements.append)

        with pytest.raises(ValueError, match="outside the visible stream"):
            export_capture_events(
                conn,
                project="demo",
                active_root=root,
                privacy_ceiling="public",
                after_sequence=1_000_000_000,
            )

        assert not any(" OFFSET " in statement.upper() for statement in statements)
    finally:
        conn.set_trace_callback(None)
        conn.close()


def test_public_capture_page_rejects_a_tampered_predecessor_link(tmp_path):
    conn, root, source = _capture_project(tmp_path)
    try:
        hidden = _append_capture(conn, root, source, "1", "internal")
        _append_capture(conn, root, source, "2", "public")
        conn.execute("DROP TRIGGER capture_events_no_update")
        conn.execute(
            "UPDATE capture_events SET event_hash = ? WHERE event_id = ?",
            ("0" * 64, hidden["event_id"]),
        )
        conn.execute(
            """
            CREATE TRIGGER capture_events_no_update
            BEFORE UPDATE ON capture_events
            BEGIN SELECT RAISE(ABORT, 'capture events are immutable'); END
            """
        )
        conn.commit()

        with pytest.raises(ValueError, match="capture event chain mismatch"):
            export_capture_events(
                conn,
                project="demo",
                active_root=root,
                privacy_ceiling="public",
            )
    finally:
        conn.close()


def test_truth_privacy_reverse_relation_lookup_has_a_bounded_index(tmp_path):
    conn, _ = _project(tmp_path)
    try:
        indexes = {
            row["name"]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            )
        }
        assert "idx_truth_relations_to_claim_active" in indexes

        plan = " ".join(
            str(value)
            for row in conn.execute(
                """
                EXPLAIN QUERY PLAN
                SELECT from_claim_id
                FROM truth_relations
                WHERE project_id = ? AND to_claim_id = ?
                  AND recorded_to_sequence IS NULL
                """,
                (1, "claim"),
            )
            for value in row
        )
        assert "idx_truth_relations_to_claim_active" in plan
    finally:
        conn.close()


def test_visible_truth_inherits_restricted_child_privacy_before_retrieval(tmp_path):
    conn, root = _project(tmp_path)
    try:
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="PUBLIC-PARENT-ID-2D7A",
            subject="PUBLIC-PARENT-MARKER-9C3B",
            predicate="status",
            value="accepted",
            epistemic_state="accepted",
            privacy_class="public",
            idempotency_key="parent:1",
            expected_stream_version=0,
        )
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="RESTRICTED-CHILD-ID-8EE1",
            subject="RESTRICTED-CHILD-MARKER-44FA",
            predicate="status",
            value="blocked",
            privacy_class="restricted",
            idempotency_key="child:1",
            expected_stream_version=0,
        )
        attach_evidence(
            conn,
            project="demo",
            active_root=root,
            claim_id="PUBLIC-PARENT-ID-2D7A",
            evidence_id="RESTRICTED-EVIDENCE-ID-370C",
            source_identifier="RESTRICTED-SOURCE-MARKER-6AB4",
            method="operator-review",
            polarity="supporting",
            authority_class="operator",
            confidence=0.9,
            provenance={"marker": "RESTRICTED-PROVENANCE-MARKER-63DD"},
            privacy_class="restricted",
            idempotency_key="evidence:1",
            expected_stream_version=0,
        )
        relate_claims(
            conn,
            project="demo",
            active_root=root,
            from_claim_id="PUBLIC-PARENT-ID-2D7A",
            relation_type="contradicts",
            to_claim_id="RESTRICTED-CHILD-ID-8EE1",
            idempotency_key="relation:1",
            expected_stream_version=0,
        )

        truth = search_truth(
            conn, "PUBLIC-PARENT-MARKER-9C3B", project="demo", limit=10
        )
        assert truth[0]["privacy_class"] == "restricted"

        pack = build_context_pack(
            conn,
            "PUBLIC-PARENT-MARKER-9C3B",
            project="demo",
            privacy_ceiling="public",
        )
        progressive = ProgressiveRetriever(b"privacy-test-secret").retrieve(
            conn,
            project="demo",
            stage="index",
            query="PUBLIC-PARENT-MARKER-9C3B",
            privacy_ceiling="public",
        )
        cognition = cognition_snapshot(
            conn,
            project="demo",
            active_root=root,
            include_change_impact=False,
        )
        parent_debt = next(
            item
            for item in cognition["decision_debt"]["items"]
            if item.get("claim_id") == "PUBLIC-PARENT-ID-2D7A"
        )

        assert "PUBLIC-PARENT-ID-2D7A" not in pack
        assert "RESTRICTED-CHILD-ID-8EE1" not in pack
        assert progressive["items"] == []
        assert "RESTRICTED-CHILD-ID-8EE1" not in json.dumps(progressive)
        assert "RESTRICTED-EVIDENCE-ID-370C" not in json.dumps(progressive)
        assert parent_debt["privacy_class"] == "restricted"
    finally:
        conn.close()


def test_restricted_truth_event_does_not_invalidate_public_timeline_handle(tmp_path):
    conn, root = _project(tmp_path)
    try:
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="public-timeline-claim",
            subject="public timeline marker",
            predicate="status",
            value="visible",
            privacy_class="public",
            idempotency_key="public-timeline:1",
            expected_stream_version=0,
        )
        retriever = ProgressiveRetriever(b"privacy-test-secret")
        index = retriever.retrieve(
            conn,
            project="demo",
            stage="index",
            query="public timeline marker",
            privacy_ceiling="public",
        )
        append_claim(
            conn,
            project="demo",
            active_root=root,
            claim_id="restricted-unrelated-claim",
            subject="restricted unrelated marker",
            predicate="status",
            value="hidden",
            privacy_class="restricted",
            idempotency_key="restricted-unrelated:1",
            expected_stream_version=0,
        )

        timeline = retriever.retrieve(
            conn,
            project="demo",
            stage="timeline",
            expansion_handle=index["expansion_handle"],
            privacy_ceiling="public",
        )

        assert timeline["stage"] == "timeline"
        assert "restricted-unrelated-claim" not in json.dumps(timeline)
    finally:
        conn.close()
