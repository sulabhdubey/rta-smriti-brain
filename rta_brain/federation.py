"""Immutable federation event storage and deterministic reconciliation order."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from heapq import heappop, heappush
from typing import Any

from .federation_types import FederationEventEnvelope

MAX_EVENTS_PER_SPACE = 10_000
MAX_EVENT_BYTES_PER_SPACE = 256 * 1024 * 1024


class FederationEventCollision(ValueError):
    """An immutable event identity conflicts with different bytes or sequence."""


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _event_identity(row: sqlite3.Row) -> tuple[Any, ...]:
    return (
        str(row["space_id"]),
        str(row["scope_id"]),
        int(row["epoch"]),
        str(row["event_id"]),
        str(row["author_peer_id"]),
        int(row["author_sequence"]),
        str(row["capability_event_id"]),
        str(row["parents_json"]),
        bytes(row["nonce"]),
        bytes(row["ciphertext"]),
        str(row["ciphertext_sha256"]),
        bytes(row["signature"]),
    )


def _envelope_identity(envelope: FederationEventEnvelope) -> tuple[Any, ...]:
    return (
        envelope.space_id,
        envelope.scope_id,
        envelope.epoch,
        envelope.event_id,
        envelope.author_peer_id,
        envelope.author_sequence,
        envelope.capability_event_id,
        json.dumps(list(envelope.parents), separators=(",", ":")),
        envelope.nonce,
        envelope.ciphertext,
        envelope.ciphertext_sha256,
        envelope.signature,
    )


def _record_quarantine(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    envelope: FederationEventEnvelope,
    reason_code: str,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO federation_quarantine(
            project_id, space_id, claimed_event_id, reason_code,
            envelope_sha256, encoded_bytes, state, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """,
        (
            project_id,
            envelope.space_id,
            envelope.event_id,
            reason_code,
            envelope.envelope_sha256,
            len(envelope.encoded),
            _now_iso(),
        ),
    )


def _missing_parents(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    envelope: FederationEventEnvelope,
) -> list[str]:
    if not envelope.parents:
        return []
    placeholders = ",".join("?" for _ in envelope.parents)
    query = f"""
        SELECT event_id FROM federation_events
        WHERE project_id = ? AND space_id = ? AND event_id IN ({placeholders})
        """  # nosec B608 - placeholder count only; every parent remains parameterized
    rows = conn.execute(
        query,
        (project_id, envelope.space_id, *envelope.parents),
    )
    present = {str(row["event_id"]) for row in rows}
    return sorted(set(envelope.parents) - present)


def store_event(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    envelope: FederationEventEnvelope,
    commit: bool = True,
) -> dict[str, Any]:
    existing = conn.execute(
        """
        SELECT * FROM federation_events
        WHERE project_id = ? AND space_id = ? AND event_id = ?
        """,
        (project_id, envelope.space_id, envelope.event_id),
    ).fetchone()
    if existing is not None:
        if _event_identity(existing) == _envelope_identity(envelope):
            validation = conn.execute(
                "SELECT validation_state FROM federation_event_validation WHERE event_row_id = ?",
                (int(existing["id"]),),
            ).fetchone()
            return {
                "state": "duplicate",
                "event_id": envelope.event_id,
                "validation_state": str(validation["validation_state"]),
                "missing_parent_count": len(
                    _missing_parents(conn, project_id=project_id, envelope=envelope)
                ),
            }
        _record_quarantine(
            conn,
            project_id=project_id,
            envelope=envelope,
            reason_code="event_id_collision",
        )
        if commit:
            conn.commit()
        raise FederationEventCollision("federation event id collision")

    sequence = conn.execute(
        """
        SELECT event_id FROM federation_events
        WHERE project_id = ? AND space_id = ?
          AND author_peer_id = ? AND author_sequence = ?
        """,
        (
            project_id,
            envelope.space_id,
            envelope.author_peer_id,
            envelope.author_sequence,
        ),
    ).fetchone()
    if sequence is not None:
        _record_quarantine(
            conn,
            project_id=project_id,
            envelope=envelope,
            reason_code="author_sequence_collision",
        )
        if commit:
            conn.commit()
        raise FederationEventCollision("federation author sequence collision")

    usage = conn.execute(
        "SELECT COUNT(*) AS event_count, COALESCE(SUM(LENGTH(ciphertext)), 0) AS bytes "
        "FROM federation_events WHERE project_id = ? AND space_id = ?",
        (project_id, envelope.space_id),
    ).fetchone()
    if int(usage["event_count"]) >= MAX_EVENTS_PER_SPACE:
        raise ValueError("federation space event count limit exceeded")
    if int(usage["bytes"]) + len(envelope.ciphertext) > MAX_EVENT_BYTES_PER_SPACE:
        raise ValueError("federation space ciphertext byte limit exceeded")

    missing = _missing_parents(conn, project_id=project_id, envelope=envelope)
    validation_state = "pending_parent" if missing else "received"
    cursor = conn.execute(
        """
        INSERT INTO federation_events(
            project_id, space_id, scope_id, epoch, event_id,
            author_peer_id, author_sequence, capability_event_id, parents_json, nonce,
            ciphertext, ciphertext_sha256, signature, received_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            envelope.space_id,
            envelope.scope_id,
            envelope.epoch,
            envelope.event_id,
            envelope.author_peer_id,
            envelope.author_sequence,
            envelope.capability_event_id,
            json.dumps(list(envelope.parents), separators=(",", ":")),
            envelope.nonce,
            envelope.ciphertext,
            envelope.ciphertext_sha256,
            envelope.signature,
            envelope.received_at,
        ),
    )
    conn.execute(
        """
        INSERT INTO federation_event_validation(
            event_row_id, project_id, validation_state, reason_code
        ) VALUES (?, ?, ?, ?)
        """,
        (
            int(cursor.lastrowid),
            project_id,
            validation_state,
            "missing_parent" if missing else None,
        ),
    )
    if commit:
        conn.commit()
    return {
        "state": "inserted",
        "event_id": envelope.event_id,
        "validation_state": validation_state,
        "missing_parent_count": len(missing),
    }


def deterministic_event_order(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
) -> list[dict[str, Any]]:
    rows = list(
        conn.execute(
            """
            SELECT id, event_id, author_peer_id, author_sequence, parents_json,
                   scope_id, epoch, ciphertext_sha256
            FROM federation_events
            WHERE project_id = ? AND space_id = ?
            """,
            (project_id, space_id),
        )
    )
    by_id = {str(row["event_id"]): row for row in rows}
    parents = {
        event_id: tuple(str(item) for item in json.loads(str(row["parents_json"])))
        for event_id, row in by_id.items()
    }
    eligible = {
        event_id
        for event_id, event_parents in parents.items()
        if all(parent in by_id for parent in event_parents)
    }
    indegree = {
        event_id: sum(parent in eligible for parent in parents[event_id])
        for event_id in eligible
    }
    children: dict[str, list[str]] = defaultdict(list)
    for event_id in eligible:
        for parent in parents[event_id]:
            if parent in eligible:
                children[parent].append(event_id)
    depth: dict[str, int] = {}
    ordered: list[dict[str, Any]] = []
    ready: list[tuple[int, int, str, str]] = []
    for event_id in eligible:
        if indegree[event_id] == 0:
            row = by_id[event_id]
            heappush(
                ready,
                (0, int(row["author_sequence"]), str(row["author_peer_id"]), event_id),
            )
    while ready:
        event_depth, _, _, event_id = heappop(ready)
        row = by_id[event_id]
        depth[event_id] = event_depth
        ordered.append(
            {
                "row_id": int(row["id"]),
                "event_id": event_id,
                "author_peer_id": str(row["author_peer_id"]),
                "author_sequence": int(row["author_sequence"]),
                "parents": list(parents[event_id]),
                "causal_depth": event_depth,
                "scope_id": str(row["scope_id"]),
                "epoch": int(row["epoch"]),
                "ciphertext_sha256": str(row["ciphertext_sha256"]),
            }
        )
        for child in sorted(children[event_id]):
            indegree[child] -= 1
            if indegree[child] == 0:
                child_row = by_id[child]
                child_depth = max(depth[parent] for parent in parents[child]) + 1
                heappush(
                    ready,
                    (
                        child_depth,
                        int(child_row["author_sequence"]),
                        str(child_row["author_peer_id"]),
                        child,
                    ),
                )
    return ordered


def record_projection_state(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    projection_name: str,
    accepted_event_count: int,
    head_digest: str,
    state: str,
) -> dict[str, Any]:
    if state not in {"ready", "partial", "conflict", "blocked"}:
        raise ValueError("federation projection state is invalid")
    if not 0 <= accepted_event_count <= 10_000_000:
        raise ValueError("accepted event count is invalid")
    conn.execute(
        """
        INSERT INTO federation_projections(
            project_id, space_id, projection_name, schema_version,
            accepted_event_count, head_digest, state, rebuilt_at
        ) VALUES (?, ?, ?, 1, ?, ?, ?, ?)
        ON CONFLICT(project_id, space_id, projection_name) DO UPDATE SET
            schema_version = excluded.schema_version,
            accepted_event_count = excluded.accepted_event_count,
            head_digest = excluded.head_digest,
            state = excluded.state,
            rebuilt_at = excluded.rebuilt_at
        """,
        (
            project_id,
            space_id,
            projection_name,
            accepted_event_count,
            head_digest,
            state,
            _now_iso(),
        ),
    )
    conn.commit()
    return {
        "project_id": project_id,
        "space_id": space_id,
        "projection_name": projection_name,
        "accepted_event_count": accepted_event_count,
        "head_digest": head_digest,
        "state": state,
    }
