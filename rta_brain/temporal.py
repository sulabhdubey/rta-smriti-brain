"""Immutable temporal truth events and rebuildable bitemporal projections."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import db
from .repository import (
    canonical_root,
    checkout_identity,
    repository_identity,
    repository_state,
    same_root,
)
from .temporal_validators import evaluate_validator, git_anchor_state

MAX_EVENT_PAYLOAD_BYTES = 256 * 1024
MAX_EVENT_JSON_DEPTH = 24
MAX_EVENT_COLLECTION_ITEMS = 4096
MAX_EVENT_STRING_CHARS = 128 * 1024
VALID_PRIVACY_CLASSES = {"public", "internal", "sensitive", "restricted"}
_PRIVACY_RANKS = {
    "public": 0,
    "internal": 1,
    "sensitive": 2,
    "restricted": 3,
}
VALID_EPISTEMIC_STATES = {
    "hypothesis",
    "observed",
    "corroborated",
    "accepted",
    "disputed",
    "stale",
    "refuted",
    "superseded",
    "retracted",
}


class StreamVersionConflict(ValueError):
    """Raised when a truth stream changed after the caller last observed it."""

    def __init__(self, *, stream_id: str, expected: int, actual: int) -> None:
        self.stream_id = stream_id
        self.expected = int(expected)
        self.actual = int(actual)
        super().__init__(
            f"stream version conflict for {stream_id}: "
            f"expected {self.expected}, actual {self.actual}"
        )


def _canonical_json(value: Any) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("truth event payload must be canonical JSON") from exc
    if len(encoded.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
        raise ValueError("truth event payload exceeds the 256 KiB limit")
    return encoded


def _row_as_dict(
    row: sqlite3.Row,
    *,
    exclude: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Detach a SQLite row without treating its iterable values as column names."""

    return {
        key: row[key]
        for key in row.keys()  # noqa: SIM118 - sqlite3.Row iteration yields values.
        if key not in exclude
    }


def _canonical_event_payload(value: Any) -> str:
    """Encode a bounded event payload without recursive parser exhaustion."""

    pending = [(value, 0)]
    collection_items = 0
    while pending:
        item, depth = pending.pop()
        if depth > MAX_EVENT_JSON_DEPTH:
            raise ValueError(
                f"truth event payload nesting exceeds {MAX_EVENT_JSON_DEPTH} levels"
            )
        if isinstance(item, str):
            if len(item) > MAX_EVENT_STRING_CHARS:
                raise ValueError("truth event payload string exceeds the character limit")
            continue
        if item is None or isinstance(item, (bool, int, float)):
            continue
        if isinstance(item, dict):
            collection_items += len(item)
            if collection_items > MAX_EVENT_COLLECTION_ITEMS:
                raise ValueError("truth event payload collection exceeds the item limit")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("truth event payload object keys must be strings")
                if len(key) > 512:
                    raise ValueError("truth event payload object key exceeds 512 characters")
                pending.append((child, depth + 1))
            continue
        if isinstance(item, list):
            collection_items += len(item)
            if collection_items > MAX_EVENT_COLLECTION_ITEMS:
                raise ValueError("truth event payload collection exceeds the item limit")
            pending.extend((child, depth + 1) for child in item)
            continue
        raise ValueError("truth event payload must be canonical JSON")
    return _canonical_json(value)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _event_hash(envelope: dict[str, Any]) -> str:
    return _sha256_text(_canonical_json(envelope))


def _required_text(name: str, value: Any, *, maximum: int = 512) -> str:
    selected = str(value).strip()
    if not selected:
        raise ValueError(f"{name} is required")
    if len(selected) > maximum:
        raise ValueError(f"{name} exceeds the {maximum} character limit")
    return selected


def _normalized_privacy_class(value: Any) -> str:
    selected = str(value or "").strip().casefold()
    if selected == "private":
        selected = "restricted"
    return selected if selected in _PRIVACY_RANKS else "restricted"


def _more_restrictive_privacy_class(left: Any, right: Any) -> str:
    return max(
        (_normalized_privacy_class(left), _normalized_privacy_class(right)),
        key=_PRIVACY_RANKS.__getitem__,
    )


def _claim_effective_privacy_class(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    claim_id: str,
    claim_privacy_class: Any,
) -> str:
    """Make a claim inherit every active evidence and related-claim ceiling."""

    selected = _normalized_privacy_class(claim_privacy_class)
    child = conn.execute(
        """
        SELECT MAX(privacy_rank) AS privacy_rank
        FROM (
            SELECT CASE e.privacy_class
                WHEN 'public' THEN 0
                WHEN 'internal' THEN 1
                WHEN 'sensitive' THEN 2
                ELSE 3
            END AS privacy_rank
            FROM truth_evidence e
            WHERE e.project_id = ? AND e.claim_id = ?
              AND e.recorded_to_sequence IS NULL
            UNION ALL
            SELECT CASE related.privacy_class
                WHEN 'public' THEN 0
                WHEN 'internal' THEN 1
                WHEN 'sensitive' THEN 2
                ELSE 3
            END AS privacy_rank
            FROM (
                SELECT r.to_claim_id AS other_claim_id
                FROM truth_relations r
                WHERE r.project_id = ? AND r.from_claim_id = ?
                  AND r.recorded_to_sequence IS NULL
                UNION ALL
                SELECT r.from_claim_id AS other_claim_id
                FROM truth_relations r
                WHERE r.project_id = ? AND r.to_claim_id = ?
                  AND r.recorded_to_sequence IS NULL
            ) relation
            LEFT JOIN truth_claim_versions related
              ON related.project_id = ?
             AND related.claim_id = relation.other_claim_id
             AND related.recorded_to_sequence IS NULL
        ) inherited_privacy
        """,
        (
            project_id,
            claim_id,
            project_id,
            claim_id,
            project_id,
            claim_id,
            project_id,
        ),
    ).fetchone()
    inherited_rank = 0 if child is None or child["privacy_rank"] is None else int(
        child["privacy_rank"]
    )
    effective_rank = max(_PRIVACY_RANKS[selected], inherited_rank)
    return next(
        privacy_class
        for privacy_class, rank in _PRIVACY_RANKS.items()
        if rank == effective_rank
    )


def _project_for_write(
    conn: sqlite3.Connection,
    project: str,
    active_root: str | Path,
) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT id, root_path, repository_identity, checkout_identity
        FROM projects WHERE name = ?
        """,
        (project,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {project}")
    requested_root = canonical_root(active_root)
    if not row["root_path"] or not same_root(str(row["root_path"]), requested_root):
        raise ValueError("temporal truth write requires the exact canonical project root")
    current_repository = repository_identity(requested_root, create_marker=False)
    current_checkout = checkout_identity(requested_root, create_marker=False)
    if (
        current_repository != row["repository_identity"]
        or current_checkout != row["checkout_identity"]
    ):
        raise ValueError("temporal truth write rejected because the project binding drifted")
    return row


def _claim_result_from_event(
    conn: sqlite3.Connection,
    event: sqlite3.Row,
    *,
    idempotent_replay: bool,
) -> dict[str, Any]:
    payload = json.loads(str(event["payload_json"]))
    claim = conn.execute(
        """
        SELECT recorded_from_sequence, recorded_to_sequence
        FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ? AND opened_by_event_id = ?
        """,
        (int(event["project_id"]), payload["claim_id"], event["event_id"]),
    ).fetchone()
    if claim is None:
        raise RuntimeError("truth event exists without its claim projection")
    return {
        "status": "ok",
        "idempotent_replay": idempotent_replay,
        "event": {
            "event_id": event["event_id"],
            "event_type": event["event_type"],
            "project_sequence": int(event["project_sequence"]),
            "stream_id": event["stream_id"],
            "stream_version": int(event["stream_version"]),
            "event_hash": event["event_hash"],
        },
        "claim": {
            "claim_id": payload["claim_id"],
            "subject": payload["subject"],
            "predicate": payload["predicate"],
            "object": payload["object"],
            "privacy_class": payload["privacy_class"],
            "sharing_policy": payload.get("sharing_policy", "local-only"),
            "epistemic_state": payload["epistemic_state"],
            "recorded_from_sequence": int(claim["recorded_from_sequence"]),
            "recorded_to_sequence": claim["recorded_to_sequence"],
        },
    }


def _require_matching_idempotent_event(
    event: sqlite3.Row,
    *,
    stream_id: str,
    event_type: str,
    actor_type: str,
    actor_id: str,
    source: str,
    payload_sha256: str | None = None,
    payload_fields: dict[str, Any] | None = None,
) -> None:
    """Bind an idempotency key to one exact actor, stream, type, and request."""

    matches = (
        str(event["stream_id"]) == stream_id
        and str(event["event_type"]) == event_type
        and str(event["actor_type"]) == str(actor_type).strip()
        and str(event["actor_id"]) == str(actor_id).strip()
        and str(event["source"]) == str(source).strip()
    )
    if payload_sha256 is not None:
        matches = matches and hmac.compare_digest(
            str(event["payload_sha256"]), payload_sha256
        )
    if payload_fields:
        existing_payload = json.loads(str(event["payload_json"]))
        matches = matches and all(
            key in existing_payload
            and _canonical_json(existing_payload[key]) == _canonical_json(value)
            for key, value in payload_fields.items()
        )
    if not matches:
        raise ValueError("idempotency key is already bound to a different truth request")


def _append_project_event(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    stream_id: str,
    expected_stream_version: int,
    event_type: str,
    idempotency_key: str,
    payload: dict[str, Any],
    projector: Callable[[sqlite3.Connection, int, int, str, dict[str, Any]], None],
    actor_type: str,
    actor_id: str,
    source: str,
    verification_status: str,
    privacy_class: str,
    occurred_at: str | None = None,
) -> tuple[sqlite3.Row, bool]:
    """Append a non-claim event and apply its projection in one transaction."""

    db.init_schema(conn)
    project_name = _required_text("project", project, maximum=128)
    selected_stream = _required_text("stream_id", stream_id, maximum=256)
    selected_key = _required_text("idempotency_key", idempotency_key, maximum=512)
    selected_event_type = _required_text("event_type", event_type, maximum=128)
    selected_expected = int(expected_stream_version)
    if selected_expected < 0:
        raise ValueError("expected_stream_version must not be negative")
    selected_privacy = str(privacy_class).strip().lower()
    if selected_privacy not in VALID_PRIVACY_CLASSES:
        raise ValueError(f"unsupported privacy class: {privacy_class}")
    payload_json = _canonical_event_payload(payload)
    payload_sha256 = _sha256_text(payload_json)
    recorded_at = db.now_iso()
    event_id = uuid.uuid4().hex

    try:
        conn.execute("BEGIN IMMEDIATE")
        project_row = _project_for_write(conn, project_name, active_root)
        project_id = int(project_row["id"])
        duplicate = conn.execute(
            "SELECT * FROM truth_events WHERE project_id = ? AND idempotency_key = ?",
            (project_id, selected_key),
        ).fetchone()
        if duplicate is not None:
            _require_matching_idempotent_event(
                duplicate,
                stream_id=selected_stream,
                event_type=selected_event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                source=source,
                payload_sha256=payload_sha256,
            )
            conn.commit()
            return duplicate, True
        current_version = int(
            conn.execute(
                """
                SELECT COALESCE(MAX(stream_version), 0) FROM truth_events
                WHERE project_id = ? AND stream_id = ?
                """,
                (project_id, selected_stream),
            ).fetchone()[0]
        )
        if current_version != selected_expected:
            raise StreamVersionConflict(
                stream_id=selected_stream,
                expected=selected_expected,
                actual=current_version,
            )
        previous = conn.execute(
            """
            SELECT project_sequence, event_hash FROM truth_events
            WHERE project_id = ? ORDER BY project_sequence DESC LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        project_sequence = int(previous["project_sequence"]) + 1 if previous else 1
        previous_event_hash = str(previous["event_hash"]) if previous else None
        stream_version = current_version + 1
        state = repository_state(active_root)
        envelope = {
            "actor_id": _required_text("actor_id", actor_id),
            "actor_type": _required_text("actor_type", actor_type),
            "checkout_identity": project_row["checkout_identity"],
            "dirty_digest": None,
            "event_id": event_id,
            "event_schema": 1,
            "event_type": selected_event_type,
            "idempotency_key": selected_key,
            "occurred_at": occurred_at,
            "payload_sha256": payload_sha256,
            "previous_event_hash": previous_event_hash,
            "privacy_class": selected_privacy,
            "project_id": project_id,
            "project_sequence": project_sequence,
            "recorded_at": recorded_at,
            "repository_commit": state.get("head"),
            "repository_identity": project_row["repository_identity"],
            "repository_ref": state.get("branch"),
            "source": _required_text("source", source),
            "stream_id": selected_stream,
            "stream_version": stream_version,
            "verification_status": _required_text(
                "verification_status", verification_status
            ),
        }
        event_hash = _event_hash(envelope)
        conn.execute(
            """
            INSERT INTO truth_events(
                project_id, project_sequence, event_id, stream_id, stream_version,
                event_type, event_schema, idempotency_key, payload_json,
                payload_sha256, previous_event_hash, event_hash, actor_type,
                actor_id, source, verification_status, repository_identity,
                checkout_identity, repository_ref, repository_commit,
                dirty_digest, occurred_at, recorded_at, privacy_class
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
            """,
            (
                project_id,
                project_sequence,
                event_id,
                selected_stream,
                stream_version,
                selected_event_type,
                selected_key,
                payload_json,
                payload_sha256,
                previous_event_hash,
                event_hash,
                envelope["actor_type"],
                envelope["actor_id"],
                envelope["source"],
                envelope["verification_status"],
                project_row["repository_identity"],
                project_row["checkout_identity"],
                envelope["repository_ref"],
                envelope["repository_commit"],
                occurred_at,
                recorded_at,
                selected_privacy,
            ),
        )
        projector(conn, project_id, project_sequence, event_id, payload)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    event = conn.execute(
        "SELECT * FROM truth_events WHERE project_id = ? AND event_id = ?",
        (project_id, event_id),
    ).fetchone()
    return event, False


def append_claim(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    subject: str,
    predicate: str,
    value: Any,
    idempotency_key: str,
    expected_stream_version: int,
    claim_id: str | None = None,
    valid_from: str | None = None,
    valid_to: str | None = None,
    revalidate_at: str | None = None,
    expires_at: str | None = None,
    epistemic_state: str = "observed",
    state_reason: str = "",
    authority_class: str = "operator",
    confidence: float = 1.0,
    verification_status: str = "unverified",
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
    occurred_at: str | None = None,
    privacy_class: str = "internal",
    sharing_policy: str = "local-only",
) -> dict[str, Any]:
    """Append one claim assertion and its current bitemporal projection."""

    db.init_schema(conn)
    project_name = _required_text("project", project, maximum=128)
    subject_display = _required_text("subject", subject, maximum=1024)
    subject_key = subject_display.casefold()
    selected_predicate = _required_text("predicate", predicate, maximum=256)
    selected_key = _required_text("idempotency_key", idempotency_key, maximum=512)
    selected_claim_id = _required_text(
        "claim_id", claim_id or uuid.uuid4().hex, maximum=128
    )
    selected_state = str(epistemic_state).strip().lower()
    if selected_state not in VALID_EPISTEMIC_STATES:
        raise ValueError(f"unsupported epistemic state: {epistemic_state}")
    selected_actor_type = _required_text("actor_type", actor_type).casefold()
    selected_authority_class = _required_text(
        "authority_class", authority_class, maximum=128
    )
    selected_verification_status = _required_text(
        "verification_status", verification_status, maximum=64
    ).casefold()
    if selected_actor_type == "agent" and not (
        selected_authority_class.casefold().startswith("agent-")
        or selected_authority_class.casefold().startswith("agent:")
    ):
        raise PermissionError("agents must use an agent authority class")
    if selected_actor_type == "agent" and selected_verification_status != "unverified":
        raise PermissionError("agents cannot self-verify claims")
    if selected_state == "accepted" and selected_actor_type == "agent":
        raise PermissionError("agents cannot create accepted claims")
    selected_privacy = str(privacy_class).strip().lower()
    if selected_privacy not in VALID_PRIVACY_CLASSES:
        raise ValueError(f"unsupported privacy class: {privacy_class}")
    selected_confidence = float(confidence)
    if not 0.0 <= selected_confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    selected_expected_version = int(expected_stream_version)
    if selected_expected_version < 0:
        raise ValueError("expected_stream_version must not be negative")

    recorded_at = db.now_iso()
    selected_valid_from = valid_from or occurred_at or recorded_at
    object_json = _canonical_json(value)
    payload = {
        "authority_class": selected_authority_class,
        "claim_id": selected_claim_id,
        "confidence": selected_confidence,
        "epistemic_state": selected_state,
        "object": value,
        "polarity": "for",
        "predicate": selected_predicate,
        "privacy_class": selected_privacy,
        "revalidate_at": revalidate_at,
        "expires_at": expires_at,
        "sharing_policy": _required_text(
            "sharing_policy", sharing_policy, maximum=128
        ),
        "state_reason": str(state_reason).strip(),
        "subject": subject_display,
        "subject_key": subject_key,
        "valid_from": selected_valid_from,
        "valid_to": valid_to,
        "verification_status": selected_verification_status,
    }
    idempotency_payload_fields = dict(payload)
    if not claim_id:
        idempotency_payload_fields.pop("claim_id")
    if not valid_from and not occurred_at:
        idempotency_payload_fields.pop("valid_from")
    payload_json = _canonical_event_payload(payload)
    payload_sha256 = _sha256_text(payload_json)
    event_id = uuid.uuid4().hex
    stream_id = f"claim:{selected_claim_id}"

    try:
        conn.execute("BEGIN IMMEDIATE")
        project_row = _project_for_write(conn, project_name, active_root)
        project_id = int(project_row["id"])
        duplicate = conn.execute(
            """
            SELECT * FROM truth_events
            WHERE project_id = ? AND idempotency_key = ?
            """,
            (project_id, selected_key),
        ).fetchone()
        if duplicate is not None:
            _require_matching_idempotent_event(
                duplicate,
                stream_id=stream_id if claim_id else str(duplicate["stream_id"]),
                event_type="claim_asserted.v1",
                actor_type=selected_actor_type,
                actor_id=actor_id,
                source=source,
                payload_fields=idempotency_payload_fields,
            )
            result = _claim_result_from_event(
                conn, duplicate, idempotent_replay=True
            )
            conn.commit()
            return result
        current_version = conn.execute(
            """
            SELECT COALESCE(MAX(stream_version), 0)
            FROM truth_events WHERE project_id = ? AND stream_id = ?
            """,
            (project_id, stream_id),
        ).fetchone()[0]
        if int(current_version) != selected_expected_version:
            raise StreamVersionConflict(
                stream_id=stream_id,
                expected=selected_expected_version,
                actual=int(current_version),
            )
        if int(current_version) != 0:
            raise ValueError("append_claim cannot append to an existing claim stream")
        previous = conn.execute(
            """
            SELECT project_sequence, event_hash FROM truth_events
            WHERE project_id = ? ORDER BY project_sequence DESC LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        project_sequence = int(previous["project_sequence"]) + 1 if previous else 1
        previous_event_hash = str(previous["event_hash"]) if previous else None
        state = repository_state(active_root)
        envelope = {
            "actor_id": _required_text("actor_id", actor_id),
            "actor_type": selected_actor_type,
            "checkout_identity": project_row["checkout_identity"],
            "dirty_digest": None,
            "event_id": event_id,
            "event_schema": 1,
            "event_type": "claim_asserted.v1",
            "idempotency_key": selected_key,
            "occurred_at": occurred_at,
            "payload_sha256": payload_sha256,
            "previous_event_hash": previous_event_hash,
            "privacy_class": selected_privacy,
            "project_id": project_id,
            "project_sequence": project_sequence,
            "recorded_at": recorded_at,
            "repository_commit": state.get("head"),
            "repository_identity": project_row["repository_identity"],
            "repository_ref": state.get("branch"),
            "source": _required_text("source", source),
            "stream_id": stream_id,
            "stream_version": 1,
            "verification_status": payload["verification_status"],
        }
        event_hash = _event_hash(envelope)
        conn.execute(
            """
            INSERT INTO truth_events(
                project_id, project_sequence, event_id, stream_id, stream_version,
                event_type, event_schema, idempotency_key, payload_json,
                payload_sha256, previous_event_hash, event_hash, actor_type,
                actor_id, source, verification_status, repository_identity,
                checkout_identity, repository_ref, repository_commit,
                dirty_digest, occurred_at, recorded_at, privacy_class
            ) VALUES (?, ?, ?, ?, 1, 'claim_asserted.v1', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                project_sequence,
                event_id,
                stream_id,
                selected_key,
                payload_json,
                payload_sha256,
                previous_event_hash,
                event_hash,
                envelope["actor_type"],
                envelope["actor_id"],
                envelope["source"],
                payload["verification_status"],
                project_row["repository_identity"],
                project_row["checkout_identity"],
                envelope["repository_ref"],
                envelope["repository_commit"],
                envelope["dirty_digest"],
                occurred_at,
                recorded_at,
                selected_privacy,
            ),
        )
        conn.execute(
            """
            INSERT INTO truth_claim_versions(
                project_id, claim_id, subject_key, subject_display, predicate,
                object_json, polarity, epistemic_state, state_reason,
                authority_class, confidence, verification_status, valid_from,
                valid_to, recorded_from_sequence, recorded_to_sequence,
                opened_by_event_id, revalidate_at, expires_at, privacy_class,
                sharing_policy
            ) VALUES (?, ?, ?, ?, ?, ?, 'for', ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                selected_claim_id,
                subject_key,
                subject_display,
                selected_predicate,
                object_json,
                selected_state,
                payload["state_reason"],
                payload["authority_class"],
                selected_confidence,
                payload["verification_status"],
                selected_valid_from,
                valid_to,
                project_sequence,
                event_id,
                revalidate_at,
                expires_at,
                selected_privacy,
                payload["sharing_policy"],
            ),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

    event = conn.execute(
        "SELECT * FROM truth_events WHERE project_id = ? AND event_id = ?",
        (project_id, event_id),
    ).fetchone()
    return _claim_result_from_event(conn, event, idempotent_replay=False)


def revise_claim(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    claim_id: str,
    value: Any,
    idempotency_key: str,
    expected_stream_version: int,
    valid_from: str | None = None,
    valid_to: str | None = None,
    reason: str = "",
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
    occurred_at: str | None = None,
    _event_type: str = "claim_asserted.v1",
    _epistemic_state: str | None = None,
    _state_reason: str | None = None,
) -> dict[str, Any]:
    """Append a corrected assertion while preserving prior recorded belief."""

    db.init_schema(conn)
    project_name = _required_text("project", project, maximum=128)
    selected_claim_id = _required_text("claim_id", claim_id, maximum=128)
    selected_key = _required_text("idempotency_key", idempotency_key, maximum=512)
    selected_expected_version = int(expected_stream_version)
    if selected_expected_version < 1:
        raise ValueError("a claim revision must expect an existing stream version")
    object_json = _canonical_json(value)
    stream_id = f"claim:{selected_claim_id}"
    recorded_at = db.now_iso()
    event_id = uuid.uuid4().hex

    try:
        conn.execute("BEGIN IMMEDIATE")
        project_row = _project_for_write(conn, project_name, active_root)
        project_id = int(project_row["id"])
        duplicate = conn.execute(
            "SELECT * FROM truth_events WHERE project_id = ? AND idempotency_key = ?",
            (project_id, selected_key),
        ).fetchone()
        if duplicate is not None:
            retry_fields = {
                "claim_id": selected_claim_id,
                "object": value,
                "revision_reason": str(reason).strip(),
            }
            if valid_from is not None:
                retry_fields["valid_from"] = valid_from
            if valid_to is not None:
                retry_fields["valid_to"] = valid_to
            if _epistemic_state is not None:
                retry_fields["epistemic_state"] = _epistemic_state
            if _state_reason is not None:
                retry_fields["state_reason"] = str(_state_reason).strip()
            _require_matching_idempotent_event(
                duplicate,
                stream_id=stream_id,
                event_type=_event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                source=source,
                payload_fields=retry_fields,
            )
            result = _claim_result_from_event(
                conn, duplicate, idempotent_replay=True
            )
            conn.commit()
            return result
        previous_claim = conn.execute(
            """
            SELECT * FROM truth_claim_versions
            WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
            """,
            (project_id, selected_claim_id),
        ).fetchone()
        if previous_claim is None:
            raise ValueError(f"claim does not exist: {selected_claim_id}")
        if (
            str(actor_type).strip().lower() == "agent"
            and not str(previous_claim["authority_class"]).startswith("agent-")
        ):
            raise PermissionError("agents cannot revise operator-authoritative claims")
        current_version = int(
            conn.execute(
                """
                SELECT COALESCE(MAX(stream_version), 0) FROM truth_events
                WHERE project_id = ? AND stream_id = ?
                """,
                (project_id, stream_id),
            ).fetchone()[0]
        )
        if current_version != selected_expected_version:
            raise StreamVersionConflict(
                stream_id=stream_id,
                expected=selected_expected_version,
                actual=current_version,
            )
        previous_event = conn.execute(
            """
            SELECT project_sequence, event_hash FROM truth_events
            WHERE project_id = ? ORDER BY project_sequence DESC LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        project_sequence = int(previous_event["project_sequence"]) + 1
        previous_event_hash = str(previous_event["event_hash"])
        selected_valid_from = valid_from or str(previous_claim["valid_from"])
        selected_valid_to = valid_to if valid_to is not None else previous_claim["valid_to"]
        payload = {
            "authority_class": previous_claim["authority_class"],
            "claim_id": selected_claim_id,
            "confidence": float(previous_claim["confidence"]),
            "epistemic_state": _epistemic_state or previous_claim["epistemic_state"],
            "object": value,
            "polarity": previous_claim["polarity"],
            "predicate": previous_claim["predicate"],
            "privacy_class": previous_claim["privacy_class"],
            "revalidate_at": previous_claim["revalidate_at"],
            "expires_at": previous_claim["expires_at"],
            "sharing_policy": previous_claim["sharing_policy"],
            "revision_reason": str(reason).strip(),
            "state_reason": (
                str(_state_reason).strip()
                if _state_reason is not None
                else previous_claim["state_reason"]
            ),
            "subject": previous_claim["subject_display"],
            "subject_key": previous_claim["subject_key"],
            "valid_from": selected_valid_from,
            "valid_to": selected_valid_to,
            "verification_status": previous_claim["verification_status"],
        }
        payload_json = _canonical_event_payload(payload)
        payload_sha256 = _sha256_text(payload_json)
        state = repository_state(active_root)
        stream_version = current_version + 1
        envelope = {
            "actor_id": _required_text("actor_id", actor_id),
            "actor_type": _required_text("actor_type", actor_type),
            "checkout_identity": project_row["checkout_identity"],
            "dirty_digest": None,
            "event_id": event_id,
            "event_schema": 1,
            "event_type": _event_type,
            "idempotency_key": selected_key,
            "occurred_at": occurred_at,
            "payload_sha256": payload_sha256,
            "previous_event_hash": previous_event_hash,
            "privacy_class": previous_claim["privacy_class"],
            "project_id": project_id,
            "project_sequence": project_sequence,
            "recorded_at": recorded_at,
            "repository_commit": state.get("head"),
            "repository_identity": project_row["repository_identity"],
            "repository_ref": state.get("branch"),
            "source": _required_text("source", source),
            "stream_id": stream_id,
            "stream_version": stream_version,
            "verification_status": previous_claim["verification_status"],
        }
        event_hash = _event_hash(envelope)
        conn.execute(
            """
            INSERT INTO truth_events(
                project_id, project_sequence, event_id, stream_id, stream_version,
                event_type, event_schema, idempotency_key, payload_json,
                payload_sha256, previous_event_hash, event_hash, actor_type,
                actor_id, source, verification_status, repository_identity,
                checkout_identity, repository_ref, repository_commit,
                dirty_digest, occurred_at, recorded_at, privacy_class
            ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                project_sequence,
                event_id,
                stream_id,
                stream_version,
                _event_type,
                selected_key,
                payload_json,
                payload_sha256,
                previous_event_hash,
                event_hash,
                envelope["actor_type"],
                envelope["actor_id"],
                envelope["source"],
                previous_claim["verification_status"],
                project_row["repository_identity"],
                project_row["checkout_identity"],
                envelope["repository_ref"],
                envelope["repository_commit"],
                None,
                occurred_at,
                recorded_at,
                previous_claim["privacy_class"],
            ),
        )
        conn.execute(
            """
            UPDATE truth_claim_versions
            SET recorded_to_sequence = ?, closed_by_event_id = ?
            WHERE id = ? AND recorded_to_sequence IS NULL
            """,
            (project_sequence, event_id, int(previous_claim["id"])),
        )
        conn.execute(
            """
            INSERT INTO truth_claim_versions(
                project_id, claim_id, subject_key, subject_display, predicate,
                object_json, polarity, epistemic_state, state_reason,
                authority_class, confidence, verification_status, valid_from,
                valid_to, recorded_from_sequence, recorded_to_sequence,
                opened_by_event_id, repository_anchor_event_id, provenance_json,
                revalidate_at, expires_at, privacy_class, sharing_policy,
                legacy_memory_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                selected_claim_id,
                previous_claim["subject_key"],
                previous_claim["subject_display"],
                previous_claim["predicate"],
                object_json,
                previous_claim["polarity"],
                payload["epistemic_state"],
                payload["state_reason"],
                previous_claim["authority_class"],
                float(previous_claim["confidence"]),
                previous_claim["verification_status"],
                selected_valid_from,
                selected_valid_to,
                project_sequence,
                event_id,
                previous_claim["repository_anchor_event_id"],
                previous_claim["provenance_json"],
                previous_claim["revalidate_at"],
                previous_claim["expires_at"],
                previous_claim["privacy_class"],
                previous_claim["sharing_policy"],
                previous_claim["legacy_memory_id"],
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    event = conn.execute(
        "SELECT * FROM truth_events WHERE project_id = ? AND event_id = ?",
        (project_id, event_id),
    ).fetchone()
    return _claim_result_from_event(conn, event, idempotent_replay=False)


_ALLOWED_STATE_TRANSITIONS = {
    "hypothesis": {"observed", "disputed", "stale", "refuted", "retracted"},
    "observed": {
        "corroborated", "accepted", "disputed", "stale", "refuted",
        "superseded", "retracted",
    },
    "corroborated": {
        "accepted", "disputed", "stale", "refuted", "superseded", "retracted",
    },
    "accepted": {"disputed", "stale", "refuted", "superseded", "retracted"},
    "disputed": {
        "observed", "corroborated", "accepted", "stale", "refuted",
        "superseded", "retracted",
    },
    "stale": {
        "observed", "corroborated", "disputed", "refuted", "superseded", "retracted",
    },
    "refuted": {"retracted"},
    "superseded": {"retracted"},
    "retracted": set(),
}


def change_claim_state(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    claim_id: str,
    new_state: str,
    reason: str,
    idempotency_key: str,
    expected_stream_version: int,
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
    occurred_at: str | None = None,
) -> dict[str, Any]:
    """Append a governed epistemic transition for an existing claim."""

    selected_state = str(new_state).strip().lower()
    if selected_state not in VALID_EPISTEMIC_STATES:
        raise ValueError(f"unsupported epistemic state: {new_state}")
    selected_actor_type = _required_text("actor_type", actor_type).lower()
    if selected_state == "accepted" and selected_actor_type == "agent":
        raise PermissionError("agents cannot promote claims to accepted")
    selected_reason = _required_text("reason", reason, maximum=2048)
    db.init_schema(conn)
    project_row = _project_row(conn, project)
    current = conn.execute(
        """
        SELECT * FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
        """,
        (int(project_row["id"]), str(claim_id).strip()),
    ).fetchone()
    if current is None:
        raise ValueError(f"claim does not exist: {claim_id}")
    current_state = str(current["epistemic_state"])
    if selected_state not in _ALLOWED_STATE_TRANSITIONS[current_state]:
        raise ValueError(
            f"invalid epistemic transition: {current_state} -> {selected_state}"
        )
    return revise_claim(
        conn,
        project=project,
        active_root=active_root,
        claim_id=claim_id,
        value=json.loads(str(current["object_json"])),
        idempotency_key=idempotency_key,
        expected_stream_version=expected_stream_version,
        valid_from=str(current["valid_from"]),
        valid_to=current["valid_to"],
        reason=selected_reason,
        actor_type=selected_actor_type,
        actor_id=actor_id,
        source=source,
        occurred_at=occurred_at,
        _event_type="claim_state_changed.v1",
        _epistemic_state=selected_state,
        _state_reason=selected_reason,
    )


VALID_RELATION_TYPES = {
    "supports",
    "contradicts",
    "supersedes",
    "retracts",
    "refutes",
    "derived_from",
    "alternate_of",
    "specialization_of",
}


def _project_relation(
    conn: sqlite3.Connection,
    project_id: int,
    project_sequence: int,
    event_id: str,
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO truth_relations(
            project_id, relation_id, from_claim_id, relation_type,
            to_claim_id, authority_class, confidence, valid_from, valid_to,
            recorded_from_sequence, recorded_to_sequence,
            opened_by_event_id, closed_by_event_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)
        """,
        (
            project_id,
            payload["relation_id"],
            payload["from_claim_id"],
            payload["relation_type"],
            payload["to_claim_id"],
            payload["authority_class"],
            float(payload["confidence"]),
            payload["valid_from"],
            payload["valid_to"],
            project_sequence,
            event_id,
        ),
    )


def relate_claims(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    from_claim_id: str,
    relation_type: str,
    to_claim_id: str,
    idempotency_key: str,
    expected_stream_version: int,
    relation_id: str | None = None,
    authority_class: str | None = None,
    confidence: float = 0.7,
    valid_from: str | None = None,
    valid_to: str | None = None,
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
) -> dict[str, Any]:
    """Append a typed relation without resolving competing truth branches."""

    db.init_schema(conn)
    project_row = _project_row(conn, project)
    project_id = int(project_row["id"])
    selected_from = _required_text("from_claim_id", from_claim_id, maximum=128)
    selected_to = _required_text("to_claim_id", to_claim_id, maximum=128)
    if selected_from == selected_to:
        raise ValueError("a claim relation requires two different claims")
    selected_type = str(relation_type).strip().lower()
    if selected_type not in VALID_RELATION_TYPES:
        raise ValueError(f"unsupported truth relation: {relation_type}")
    claims = conn.execute(
        """
        SELECT claim_id, authority_class, epistemic_state FROM truth_claim_versions
        WHERE project_id = ? AND claim_id IN (?, ?)
          AND recorded_to_sequence IS NULL
        """,
        (project_id, selected_from, selected_to),
    ).fetchall()
    if {row["claim_id"] for row in claims} != {selected_from, selected_to}:
        raise ValueError("both relation claims must exist and be current")
    selected_actor_type = _required_text("actor_type", actor_type).lower()
    if selected_actor_type == "agent" and selected_type == "contradicts" and any(
        not str(row["authority_class"]).startswith("agent-") for row in claims
    ):
        raise PermissionError(
            "agents cannot directly dispute operator-authoritative claims"
        )
    selected_authority = authority_class or (
        "agent-proposal" if selected_actor_type == "agent" else "operator"
    )
    selected_confidence = float(confidence)
    if not 0.0 <= selected_confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    selected_relation_id = _required_text(
        "relation_id", relation_id or uuid.uuid4().hex, maximum=128
    )
    selected_valid_from = valid_from or db.now_iso()
    payload = {
        "authority_class": _required_text(
            "authority_class", selected_authority, maximum=128
        ),
        "confidence": selected_confidence,
        "from_claim_id": selected_from,
        "relation_id": selected_relation_id,
        "relation_type": selected_type,
        "to_claim_id": selected_to,
        "valid_from": selected_valid_from,
        "valid_to": valid_to,
    }
    event, duplicate = _append_project_event(
        conn,
        project=project,
        active_root=active_root,
        stream_id=f"relation:{selected_relation_id}",
        expected_stream_version=expected_stream_version,
        event_type="claim_related.v1",
        idempotency_key=idempotency_key,
        payload=payload,
        projector=_project_relation,
        actor_type=selected_actor_type,
        actor_id=actor_id,
        source=source,
        verification_status="unverified",
        privacy_class="internal",
    )
    relation = conn.execute(
        """
        SELECT * FROM truth_relations
        WHERE project_id = ? AND opened_by_event_id = ?
        """,
        (project_id, event["event_id"]),
    ).fetchone()
    if relation is None:
        raise RuntimeError("truth relation event exists without its projection")
    return {
        "status": "ok",
        "idempotent_replay": duplicate,
        "event": {
            "event_id": event["event_id"],
            "project_sequence": int(event["project_sequence"]),
            "stream_version": int(event["stream_version"]),
        },
        "relation": {
            "relation_id": relation["relation_id"],
            "from_claim_id": relation["from_claim_id"],
            "type": relation["relation_type"],
            "to_claim_id": relation["to_claim_id"],
        },
    }


def truth_current(
    conn: sqlite3.Connection,
    *,
    project: str,
    claim_id: str,
    valid_at: str | None = None,
    _initialize: bool = True,
) -> dict[str, Any]:
    """Return the current recorded claim with effective dispute/expiry state."""

    if _initialize:
        db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_claim_id = _required_text("claim_id", claim_id, maximum=128)
    selected_valid_at = valid_at or db.now_iso()
    claim = conn.execute(
        """
        SELECT * FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
          AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)
        ORDER BY recorded_from_sequence DESC LIMIT 1
        """,
        (project_id, selected_claim_id, selected_valid_at, selected_valid_at),
    ).fetchone()
    if claim is None:
        return {
            "status": "abstain",
            "reason": "no current claim is valid at the requested time",
            "claim_id": selected_claim_id,
        }
    relation_rows = conn.execute(
        """
        SELECT from_claim_id, to_claim_id FROM truth_relations
        WHERE project_id = ? AND relation_type = 'contradicts'
          AND recorded_to_sequence IS NULL
          AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?)
          AND (from_claim_id = ? OR to_claim_id = ?)
        ORDER BY relation_id
        """,
        (
            project_id,
            selected_valid_at,
            selected_valid_at,
            selected_claim_id,
            selected_claim_id,
        ),
    ).fetchall()
    contradictions = sorted(
        {
            row["to_claim_id"]
            if row["from_claim_id"] == selected_claim_id
            else row["from_claim_id"]
            for row in relation_rows
        }
    )
    effective_state = str(claim["epistemic_state"])
    validator_rows = conn.execute(
        """
        SELECT v.validator_id, v.failure_effect, r.outcome
        FROM truth_validators v
        JOIN truth_validator_results r
          ON r.project_id = v.project_id AND r.validator_id = v.validator_id
        WHERE v.project_id = ? AND v.claim_id = ? AND v.status = 'active'
          AND r.evaluated_sequence = (
              SELECT MAX(r2.evaluated_sequence)
              FROM truth_validator_results r2
              WHERE r2.project_id = r.project_id
                AND r2.validator_id = r.validator_id
          )
        ORDER BY v.validator_id
        """,
        (project_id, selected_claim_id),
    ).fetchall()
    failed_validators = [
        str(row["validator_id"]) for row in validator_rows if row["outcome"] == "fail"
    ]
    failure_effects = {
        str(row["failure_effect"]) for row in validator_rows if row["outcome"] == "fail"
    }
    if claim["expires_at"] and str(claim["expires_at"]) <= selected_valid_at:
        effective_state = "stale"
    if contradictions and effective_state not in {
        "refuted", "superseded", "retracted"
    }:
        effective_state = "disputed"
    if effective_state not in {"refuted", "superseded", "retracted"}:
        if "refuted" in failure_effects:
            effective_state = "refuted"
        elif "stale" in failure_effects:
            effective_state = "stale"
        elif "disputed" in failure_effects:
            effective_state = "disputed"
    effective_privacy_class = _claim_effective_privacy_class(
        conn,
        project_id=project_id,
        claim_id=selected_claim_id,
        claim_privacy_class=claim["privacy_class"],
    )
    return {
        "status": "ok",
        "valid_at": selected_valid_at,
        "claim": {
            "claim_id": claim["claim_id"],
            "subject": claim["subject_display"],
            "predicate": claim["predicate"],
            "object": json.loads(str(claim["object_json"])),
            "privacy_class": effective_privacy_class,
            "sharing_policy": claim["sharing_policy"],
            "epistemic_state": claim["epistemic_state"],
            "effective_state": effective_state,
            "contradictions": contradictions,
            "validator_failures": failed_validators,
            "recorded_from_sequence": int(claim["recorded_from_sequence"]),
        },
    }


def search_truth(
    conn: sqlite3.Connection,
    query: str,
    *,
    project: str,
    limit: int = 8,
    _initialize: bool = True,
) -> list[dict[str, Any]]:
    """Return bounded lexical truth candidates with explicit effective states."""

    if _initialize:
        db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_limit = max(1, min(50, int(limit)))
    tokens = list(dict.fromkeys(
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9_.:/-]+", str(query)[:10_000])
        if len(token) >= 2
    ))[:32]
    if not tokens:
        return []
    rows = conn.execute(
        """
        SELECT * FROM truth_claim_versions
        WHERE project_id = ? AND recorded_to_sequence IS NULL
        ORDER BY recorded_from_sequence DESC LIMIT 2000
        """,
        (project_id,),
    ).fetchall()
    state_weight = {
        "accepted": 9, "corroborated": 7, "observed": 5, "hypothesis": 2,
        "disputed": 1, "stale": 0, "refuted": -3, "superseded": -2,
        "retracted": -4,
    }
    candidates = []
    for row in rows:
        object_value = json.loads(str(row["object_json"]))
        haystack = " ".join((
            str(row["subject_display"]), str(row["predicate"]),
            _canonical_json(object_value), str(row["state_reason"] or ""),
        )).casefold()
        lexical_hits = sum(haystack.count(token) for token in tokens)
        if lexical_hits == 0:
            continue
        current = truth_current(
            conn, project=project, claim_id=str(row["claim_id"]),
            _initialize=False,
        )
        if current["status"] != "ok":
            continue
        claim = current["claim"]
        epistemic_state = str(row["epistemic_state"])
        score = lexical_hits * 10 + state_weight.get(epistemic_state, 0)
        if str(row["verification_status"]) == "verified":
            score += 3
        candidates.append({
            "claim_id": claim["claim_id"],
            "subject": claim["subject"],
            "predicate": claim["predicate"],
            "object": claim["object"],
            "privacy_class": claim["privacy_class"],
            "sharing_policy": row["sharing_policy"],
            "epistemic_state": epistemic_state,
            "effective_state": claim["effective_state"],
            "authority_class": row["authority_class"],
            "confidence": float(row["confidence"]),
            "verification_status": row["verification_status"],
            "recorded_from_sequence": int(row["recorded_from_sequence"]),
            "contradictions": claim["contradictions"],
            "validator_failures": claim["validator_failures"],
            "score": score,
        })
    return redact_truth_for_operator(sorted(
        candidates,
        key=lambda item: (-int(item["score"]), str(item["claim_id"])),
    )[:selected_limit])


def _project_evidence(
    conn: sqlite3.Connection,
    project_id: int,
    project_sequence: int,
    event_id: str,
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO truth_evidence(
            project_id, evidence_id, claim_id, source_identifier, source_hash,
            method, actor_type, actor_id, authority_class, confidence,
            uncertainty, polarity, validator_id, valid_from, valid_to,
            recorded_from_sequence, recorded_to_sequence, opened_by_event_id,
            closed_by_event_id, provenance_json, privacy_class, sharing_policy
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?,
                  NULL, ?, ?, ?)
        """,
        (
            project_id,
            payload["evidence_id"],
            payload["claim_id"],
            payload["source_identifier"],
            payload["source_hash"],
            payload["method"],
            payload["actor_type"],
            payload["actor_id"],
            payload["authority_class"],
            float(payload["confidence"]),
            payload["uncertainty"],
            payload["polarity"],
            payload["validator_id"],
            payload["valid_from"],
            payload["valid_to"],
            project_sequence,
            event_id,
            _canonical_json(payload["provenance"]),
            payload["privacy_class"],
            payload["sharing_policy"],
        ),
    )


def attach_evidence(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    claim_id: str,
    evidence_id: str,
    source_identifier: str,
    method: str,
    polarity: str,
    authority_class: str,
    confidence: float,
    provenance: dict[str, Any],
    idempotency_key: str,
    expected_stream_version: int,
    source_hash: str | None = None,
    uncertainty: str = "",
    validator_id: str | None = None,
    valid_from: str | None = None,
    valid_to: str | None = None,
    verification_status: str = "unverified",
    privacy_class: str = "internal",
    sharing_policy: str = "local-only",
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
) -> dict[str, Any]:
    """Attach bounded provenance-bearing evidence to a current claim."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_claim_id = _required_text("claim_id", claim_id, maximum=128)
    claim = conn.execute(
        """
        SELECT 1 FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
        """,
        (project_id, selected_claim_id),
    ).fetchone()
    if claim is None:
        raise ValueError(f"claim does not exist: {selected_claim_id}")
    selected_evidence_id = _required_text("evidence_id", evidence_id, maximum=128)
    selected_polarity = str(polarity).strip().lower()
    if selected_polarity not in {"supporting", "weakening", "refuting"}:
        raise ValueError(f"unsupported evidence polarity: {polarity}")
    selected_hash = str(source_hash).strip().lower() if source_hash else None
    if selected_hash and not re.fullmatch(r"[0-9a-f]{64}", selected_hash):
        raise ValueError("source_hash must be a lowercase SHA-256 digest")
    selected_confidence = float(confidence)
    if not 0.0 <= selected_confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    if not isinstance(provenance, dict):
        raise TypeError("provenance must be an object")
    selected_actor_type = _required_text("actor_type", actor_type).lower()
    selected_actor_id = _required_text("actor_id", actor_id)
    payload = {
        "actor_id": selected_actor_id,
        "actor_type": selected_actor_type,
        "authority_class": _required_text(
            "authority_class", authority_class, maximum=128
        ),
        "claim_id": selected_claim_id,
        "confidence": selected_confidence,
        "evidence_id": selected_evidence_id,
        "method": _required_text("method", method, maximum=256),
        "polarity": selected_polarity,
        "privacy_class": str(privacy_class).strip().lower(),
        "provenance": provenance,
        "sharing_policy": _required_text(
            "sharing_policy", sharing_policy, maximum=128
        ),
        "source_hash": selected_hash,
        "source_identifier": _required_text(
            "source_identifier", source_identifier, maximum=2048
        ),
        "uncertainty": str(uncertainty).strip(),
        "valid_from": valid_from or db.now_iso(),
        "valid_to": valid_to,
        "validator_id": validator_id,
    }
    event, duplicate = _append_project_event(
        conn,
        project=project,
        active_root=active_root,
        stream_id=f"evidence:{selected_evidence_id}",
        expected_stream_version=expected_stream_version,
        event_type="evidence_attached.v1",
        idempotency_key=idempotency_key,
        payload=payload,
        projector=_project_evidence,
        actor_type=actor_type,
        actor_id=selected_actor_id,
        source=source,
        verification_status=verification_status,
        privacy_class=payload["privacy_class"],
    )
    evidence = conn.execute(
        """
        SELECT * FROM truth_evidence
        WHERE project_id = ? AND opened_by_event_id = ?
        """,
        (project_id, event["event_id"]),
    ).fetchone()
    if evidence is None:
        raise RuntimeError("truth evidence event exists without its projection")
    return {
        "status": "ok",
        "idempotent_replay": duplicate,
        "event": {
            "event_id": event["event_id"],
            "project_sequence": int(event["project_sequence"]),
            "stream_version": int(event["stream_version"]),
        },
        "evidence": {
            "evidence_id": evidence["evidence_id"],
            "claim_id": evidence["claim_id"],
            "polarity": evidence["polarity"],
            "verification_status": verification_status,
        },
    }


def truth_explain(
    conn: sqlite3.Connection,
    *,
    project: str,
    claim_id: str,
    valid_at: str | None = None,
    limit: int = 25,
) -> dict[str, Any]:
    """Explain one claim with bounded evidence, relations, and provenance."""

    selected_limit = max(1, min(50, int(limit)))
    current = truth_current(
        conn, project=project, claim_id=claim_id, valid_at=valid_at
    )
    if current["status"] != "ok":
        return current
    project_id = int(_project_row(conn, project)["id"])
    evidence_rows = conn.execute(
        """
        SELECT * FROM truth_evidence
        WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
        ORDER BY recorded_from_sequence, evidence_id LIMIT ?
        """,
        (project_id, str(claim_id).strip(), selected_limit + 1),
    ).fetchall()
    relation_rows = conn.execute(
        """
        SELECT relation_id, from_claim_id, relation_type, to_claim_id,
               authority_class, confidence
        FROM truth_relations
        WHERE project_id = ? AND recorded_to_sequence IS NULL
          AND (from_claim_id = ? OR to_claim_id = ?)
        ORDER BY recorded_from_sequence, relation_id LIMIT ?
        """,
        (
            project_id, str(claim_id).strip(), str(claim_id).strip(),
            selected_limit + 1,
        ),
    ).fetchall()
    return {
        **current,
        "evidence": [
            {
                "evidence_id": row["evidence_id"],
                "source_identifier": row["source_identifier"],
                "source_hash": row["source_hash"],
                "method": row["method"],
                "polarity": row["polarity"],
                "authority_class": row["authority_class"],
                "confidence": float(row["confidence"]),
                "provenance": _bounded_truth_output(
                    json.loads(str(row["provenance_json"])), maximum_bytes=16 * 1024
                ),
                "privacy_class": row["privacy_class"],
            }
            for row in evidence_rows[:selected_limit]
        ],
        "relations": [
            _row_as_dict(row)
            for row in relation_rows[:selected_limit]
        ],
        "evidence_truncated": len(evidence_rows) > selected_limit,
        "relations_truncated": len(relation_rows) > selected_limit,
    }


def _project_abstention(
    conn: sqlite3.Connection,
    project_id: int,
    project_sequence: int,
    event_id: str,
    payload: dict[str, Any],
) -> None:
    recorded_at = conn.execute(
        "SELECT recorded_at FROM truth_events WHERE event_id = ?", (event_id,)
    ).fetchone()[0]
    conn.execute(
        """
        INSERT INTO truth_abstentions(
            project_id, abstention_id, query_scope, missing_evidence_json,
            unresolved_conflicts_json, minimum_revalidation_action,
            recorded_sequence, event_id, recorded_at, privacy_class
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            payload["abstention_id"],
            payload["query_scope"],
            _canonical_json(payload["missing_evidence"]),
            _canonical_json(payload["unresolved_conflicts"]),
            payload["minimum_revalidation_action"],
            project_sequence,
            event_id,
            recorded_at,
            payload["privacy_class"],
        ),
    )


def _bounded_text_list(name: str, values: list[str]) -> list[str]:
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError(f"{name} must be a list with at most 100 entries")
    return [_required_text(name, value, maximum=1024) for value in values]


def record_abstention(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    query_scope: str,
    missing_evidence: list[str],
    unresolved_conflicts: list[str],
    minimum_revalidation_action: str,
    idempotency_key: str,
    expected_stream_version: int,
    abstention_id: str | None = None,
    privacy_class: str = "internal",
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
) -> dict[str, Any]:
    """Record why the brain must abstain without creating a truth claim."""

    selected_id = _required_text(
        "abstention_id", abstention_id or uuid.uuid4().hex, maximum=128
    )
    payload = {
        "abstention_id": selected_id,
        "minimum_revalidation_action": _required_text(
            "minimum_revalidation_action", minimum_revalidation_action, maximum=2048
        ),
        "missing_evidence": _bounded_text_list("missing_evidence", missing_evidence),
        "privacy_class": str(privacy_class).strip().lower(),
        "query_scope": _required_text("query_scope", query_scope, maximum=4096),
        "unresolved_conflicts": _bounded_text_list(
            "unresolved_conflicts", unresolved_conflicts
        ),
    }
    event, duplicate = _append_project_event(
        conn,
        project=project,
        active_root=active_root,
        stream_id=f"abstention:{selected_id}",
        expected_stream_version=expected_stream_version,
        event_type="abstention_recorded.v1",
        idempotency_key=idempotency_key,
        payload=payload,
        projector=_project_abstention,
        actor_type=actor_type,
        actor_id=actor_id,
        source=source,
        verification_status="unverified",
        privacy_class=payload["privacy_class"],
    )
    row = conn.execute(
        """
        SELECT * FROM truth_abstentions
        WHERE project_id = ? AND event_id = ?
        """,
        (int(event["project_id"]), event["event_id"]),
    ).fetchone()
    if row is None:
        raise RuntimeError("abstention event exists without its projection")
    return {
        "status": "abstain",
        "idempotent_replay": duplicate,
        "event": {
            "event_id": event["event_id"],
            "project_sequence": int(event["project_sequence"]),
        },
        "abstention": {
            "abstention_id": row["abstention_id"],
            "query_scope": row["query_scope"],
            "missing_evidence": json.loads(str(row["missing_evidence_json"])),
            "unresolved_conflicts": json.loads(
                str(row["unresolved_conflicts_json"])
            ),
            "minimum_revalidation_action": row["minimum_revalidation_action"],
        },
    }


VALID_VALIDATOR_TYPES = {
    "file_exists",
    "file_sha256",
    "json_pointer_equals",
    "sqlite_integrity",
    "git_head_equals",
    "git_clean_state",
    "command_exit",
}


def _project_validator_definition(
    conn: sqlite3.Connection,
    project_id: int,
    project_sequence: int,
    event_id: str,
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO truth_validators(
            project_id, validator_id, validator_type, claim_id, config_json,
            failure_effect, status, defined_sequence, defined_by_event_id,
            privacy_class
        ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
        """,
        (
            project_id,
            payload["validator_id"],
            payload["validator_type"],
            payload["claim_id"],
            _canonical_json(payload["config"]),
            payload["failure_effect"],
            project_sequence,
            event_id,
            payload["privacy_class"],
        ),
    )


def _validate_validator_config(validator_type: str, config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        raise TypeError("validator config must be an object")
    selected = dict(config)
    if validator_type in {
        "file_exists", "file_sha256", "json_pointer_equals", "sqlite_integrity"
    }:
        path = _required_text("validator path", selected.get("path", ""), maximum=2048)
        if Path(path).is_absolute():
            raise ValueError("validator paths must be relative to the canonical root")
        selected["path"] = path.replace("\\", "/")
    if validator_type == "file_sha256":
        digest = str(selected.get("sha256", "")).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("file_sha256 requires a lowercase SHA-256 digest")
        selected["sha256"] = digest
    if validator_type == "json_pointer_equals":
        pointer = str(selected.get("pointer", ""))
        if pointer and not pointer.startswith("/"):
            raise ValueError("json_pointer_equals pointer must be empty or start with /")
        if len(pointer) > 2048:
            raise ValueError("json_pointer_equals pointer exceeds 2,048 characters")
        if "equals" not in selected:
            raise ValueError("json_pointer_equals requires an equals value")
        selected["pointer"] = pointer
    if validator_type == "git_head_equals":
        commit = str(selected.get("commit", "")).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
            raise ValueError("git_head_equals requires a full lowercase Git object ID")
        selected["commit"] = commit
    if validator_type == "git_clean_state":
        clean = selected.get("clean", True)
        if not isinstance(clean, bool):
            raise ValueError("git_clean_state clean must be boolean")
        selected["clean"] = clean
    if validator_type == "command_exit":
        argv = selected.get("argv")
        if not isinstance(argv, list) or not argv or len(argv) > 32:
            raise ValueError("command_exit requires an argv list with 1 to 32 items")
        selected["argv"] = [
            _required_text("command argv", item, maximum=1024) for item in argv
        ]
        if not Path(selected["argv"][0]).is_absolute():
            raise ValueError("command_exit executable must be an absolute path")
        timeout_seconds = float(selected.get("timeout_seconds", 5.0))
        if not 0.1 <= timeout_seconds <= 30.0:
            raise ValueError("command_exit timeout_seconds must be between 0.1 and 30")
        selected["timeout_seconds"] = timeout_seconds
    _canonical_json(selected)
    return selected


def define_validator(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    validator_id: str,
    validator_type: str,
    claim_id: str,
    config: dict[str, Any],
    failure_effect: str,
    idempotency_key: str,
    expected_stream_version: int,
    privacy_class: str = "internal",
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
) -> dict[str, Any]:
    """Define an inert, bounded validator policy."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_id = _required_text("validator_id", validator_id, maximum=128)
    selected_type = str(validator_type).strip().lower()
    if selected_type not in VALID_VALIDATOR_TYPES:
        raise ValueError(f"unsupported validator type: {validator_type}")
    if selected_type == "command_exit" and str(actor_type).strip().lower() != "operator":
        raise PermissionError("only an operator can define command_exit validators")
    selected_claim_id = _required_text("claim_id", claim_id, maximum=128)
    selected_actor_type = _required_text("actor_type", actor_type).lower()
    claim = conn.execute(
        """
        SELECT authority_class, epistemic_state FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
        """,
        (project_id, selected_claim_id),
    ).fetchone()
    if claim is None:
        raise ValueError(f"claim does not exist: {selected_claim_id}")
    if (
        selected_actor_type == "agent"
        and not str(claim["authority_class"]).startswith("agent-")
    ):
        raise PermissionError(
            "agents cannot attach consequential validators to operator-authoritative claims"
        )
    selected_effect = str(failure_effect).strip().lower()
    if selected_effect not in {"disputed", "stale", "refuted"}:
        raise ValueError(f"unsupported validator failure effect: {failure_effect}")
    payload = {
        "claim_id": selected_claim_id,
        "config": _validate_validator_config(selected_type, config),
        "failure_effect": selected_effect,
        "privacy_class": str(privacy_class).strip().lower(),
        "validator_id": selected_id,
        "validator_type": selected_type,
    }
    event, duplicate = _append_project_event(
        conn,
        project=project,
        active_root=active_root,
        stream_id=f"validator:{selected_id}",
        expected_stream_version=expected_stream_version,
        event_type="validator_defined.v1",
        idempotency_key=idempotency_key,
        payload=payload,
        projector=_project_validator_definition,
        actor_type=selected_actor_type,
        actor_id=actor_id,
        source=source,
        verification_status="unverified",
        privacy_class=payload["privacy_class"],
    )
    validator = conn.execute(
        """
        SELECT * FROM truth_validators
        WHERE project_id = ? AND defined_by_event_id = ?
        """,
        (project_id, event["event_id"]),
    ).fetchone()
    if validator is None:
        raise RuntimeError("validator definition event exists without its projection")
    return {
        "status": "ok",
        "idempotent_replay": duplicate,
        "event": {
            "event_id": event["event_id"],
            "stream_version": int(event["stream_version"]),
        },
        "validator": {
            "validator_id": validator["validator_id"],
            "type": validator["validator_type"],
            "claim_id": validator["claim_id"],
            "failure_effect": validator["failure_effect"],
        },
    }


def _project_validator_result(
    conn: sqlite3.Connection,
    project_id: int,
    project_sequence: int,
    event_id: str,
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO truth_validator_results(
            project_id, validator_id, claim_id, outcome, details_json,
            evaluated_sequence, event_id, evaluated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            payload["validator_id"],
            payload["claim_id"],
            payload["outcome"],
            _canonical_json(payload["details"]),
            project_sequence,
            event_id,
            payload["evaluated_at"],
        ),
    )


def run_validator(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    validator_id: str,
    idempotency_key: str,
    expected_stream_version: int,
    allow_command: bool = False,
    trusted_executables: list[str] | tuple[str, ...] = (),
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
) -> dict[str, Any]:
    """Evaluate a registered validator and append its bounded result."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_id = _required_text("validator_id", validator_id, maximum=128)
    validator = conn.execute(
        """
        SELECT * FROM truth_validators
        WHERE project_id = ? AND validator_id = ? AND status = 'active'
        """,
        (project_id, selected_id),
    ).fetchone()
    if validator is None:
        raise ValueError(f"active validator does not exist: {selected_id}")
    if validator["validator_type"] == "command_exit" and str(actor_type).lower() != "operator":
        raise PermissionError("agents cannot execute command validators")
    outcome, details = evaluate_validator(
        str(validator["validator_type"]),
        json.loads(str(validator["config_json"])),
        active_root=active_root,
        allow_command=allow_command,
        trusted_executables=trusted_executables,
    )
    payload = {
        "claim_id": validator["claim_id"],
        "details": details,
        "evaluated_at": db.now_iso(),
        "failure_effect": validator["failure_effect"],
        "outcome": outcome,
        "validator_id": selected_id,
        "validator_type": validator["validator_type"],
    }
    event, duplicate = _append_project_event(
        conn,
        project=project,
        active_root=active_root,
        stream_id=f"validator:{selected_id}",
        expected_stream_version=expected_stream_version,
        event_type="validator_evaluated.v1",
        idempotency_key=idempotency_key,
        payload=payload,
        projector=_project_validator_result,
        actor_type=actor_type,
        actor_id=actor_id,
        source=source,
        verification_status="verified" if outcome in {"pass", "fail"} else "unverified",
        privacy_class=validator["privacy_class"],
    )
    result = conn.execute(
        """
        SELECT * FROM truth_validator_results
        WHERE project_id = ? AND event_id = ?
        """,
        (project_id, event["event_id"]),
    ).fetchone()
    if result is None:
        raise RuntimeError("validator result event exists without its projection")
    return {
        "status": "ok",
        "idempotent_replay": duplicate,
        "event": {
            "event_id": event["event_id"],
            "stream_version": int(event["stream_version"]),
        },
        "evaluation": {
            "validator_id": selected_id,
            "claim_id": result["claim_id"],
            "outcome": result["outcome"],
            "details": json.loads(str(result["details_json"])),
            "failure_effect": validator["failure_effect"],
        },
    }


def validator_history(
    conn: sqlite3.Connection,
    *,
    project: str,
    validator_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return one validator definition and its bounded evaluation history."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_id = _required_text("validator_id", validator_id, maximum=128)
    selected_limit = int(limit)
    if not 1 <= selected_limit <= 500:
        raise ValueError("validator history limit must be between 1 and 500")
    validator = conn.execute(
        """
        SELECT * FROM truth_validators
        WHERE project_id = ? AND validator_id = ?
        """,
        (project_id, selected_id),
    ).fetchone()
    if validator is None:
        return {
            "status": "abstain",
            "reason": "validator is not defined",
            "validator_id": selected_id,
            "results": [],
        }
    rows = conn.execute(
        """
        SELECT * FROM truth_validator_results
        WHERE project_id = ? AND validator_id = ?
        ORDER BY evaluated_sequence DESC LIMIT ?
        """,
        (project_id, selected_id, selected_limit),
    ).fetchall()
    return {
        "status": "ok",
        "validator": {
            "validator_id": validator["validator_id"],
            "type": validator["validator_type"],
            "claim_id": validator["claim_id"],
            "config": json.loads(str(validator["config_json"])),
            "failure_effect": validator["failure_effect"],
            "status": validator["status"],
        },
        "results": [
            {
                "outcome": row["outcome"],
                "details": json.loads(str(row["details_json"])),
                "evaluated_sequence": int(row["evaluated_sequence"]),
                "event_id": row["event_id"],
                "evaluated_at": row["evaluated_at"],
            }
            for row in rows
        ],
        "truncated": len(rows) == selected_limit,
    }


def truth_as_of(
    conn: sqlite3.Connection,
    *,
    project: str,
    claim_id: str,
    valid_at: str,
    recorded_sequence: int,
) -> dict[str, Any]:
    """Return one claim at valid time V as known at recorded sequence R."""

    db.init_schema(conn)
    row = conn.execute(
        "SELECT id FROM projects WHERE name = ?", (str(project).strip(),)
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {project}")
    selected_sequence = int(recorded_sequence)
    if selected_sequence < 1:
        raise ValueError("recorded_sequence must be positive")
    selected_valid_at = _required_text("valid_at", valid_at, maximum=64)
    claim = conn.execute(
        """
        SELECT * FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ?
          AND recorded_from_sequence <= ?
          AND (recorded_to_sequence IS NULL OR recorded_to_sequence > ?)
          AND valid_from <= ?
          AND (valid_to IS NULL OR valid_to > ?)
        ORDER BY recorded_from_sequence DESC LIMIT 1
        """,
        (
            int(row["id"]),
            str(claim_id).strip(),
            selected_sequence,
            selected_sequence,
            selected_valid_at,
            selected_valid_at,
        ),
    ).fetchone()
    if claim is None:
        return {
            "status": "abstain",
            "reason": "no claim is valid at the requested valid and recorded times",
            "claim_id": str(claim_id).strip(),
            "valid_at": selected_valid_at,
            "recorded_sequence": selected_sequence,
        }
    return {
        "status": "ok",
        "valid_at": selected_valid_at,
        "recorded_sequence": selected_sequence,
        "claim": {
            "claim_id": claim["claim_id"],
            "subject": claim["subject_display"],
            "predicate": claim["predicate"],
            "object": json.loads(str(claim["object_json"])),
            "privacy_class": claim["privacy_class"],
            "sharing_policy": claim["sharing_policy"],
            "polarity": claim["polarity"],
            "epistemic_state": claim["epistemic_state"],
            "valid_from": claim["valid_from"],
            "valid_to": claim["valid_to"],
            "recorded_from_sequence": int(claim["recorded_from_sequence"]),
            "recorded_to_sequence": claim["recorded_to_sequence"],
        },
    }


def _claim_version_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "claim_id": row["claim_id"],
        "subject": row["subject_display"],
        "predicate": row["predicate"],
        "object": json.loads(str(row["object_json"])),
        "privacy_class": row["privacy_class"],
        "sharing_policy": row["sharing_policy"],
        "polarity": row["polarity"],
        "epistemic_state": row["epistemic_state"],
        "state_reason": row["state_reason"],
        "authority_class": row["authority_class"],
        "confidence": float(row["confidence"]),
        "verification_status": row["verification_status"],
        "valid_from": row["valid_from"],
        "valid_to": row["valid_to"],
        "recorded_from_sequence": int(row["recorded_from_sequence"]),
        "recorded_to_sequence": row["recorded_to_sequence"],
        "opened_by_event_id": row["opened_by_event_id"],
        "closed_by_event_id": row["closed_by_event_id"],
        "revalidate_at": row["revalidate_at"],
        "expires_at": row["expires_at"],
    }


_PRIVATE_TRUTH_CLASSES = frozenset({"sensitive", "restricted"})
_PRIVATE_TRUTH_SAFE_KEYS = frozenset({
    "status", "reason", "project", "claim_id", "evidence_id", "relation_id",
    "validator_id", "abstention_id", "event_id", "stream_id", "stream_version",
    "project_sequence", "event_type", "privacy_class", "sharing_policy", "redacted",
    "epistemic_state", "effective_state", "verification_status", "polarity",
    "authority_class", "confidence", "recorded_from_sequence", "recorded_to_sequence",
    "recorded_sequence", "evaluated_sequence", "recorded_at", "evaluated_at",
    "valid_at", "valid_from", "valid_to", "revalidate_at", "expires_at",
    "contradictions", "validator_failures", "truncated",
})


def _bounded_truth_output(value: Any, *, maximum_bytes: int) -> Any:
    encoded = _canonical_json(value).encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value
    return {
        "value_omitted": True,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "utf8_bytes": len(encoded),
    }


def redact_truth_for_operator(payload: Any) -> Any:
    """Redact privacy-classified values before they enter an operator browser."""

    if isinstance(payload, list):
        return [redact_truth_for_operator(item) for item in payload]
    if not isinstance(payload, dict):
        return payload
    privacy_class = str(payload.get("privacy_class", "")).strip().lower()
    if privacy_class in _PRIVATE_TRUTH_CLASSES:
        redacted = {
            key: redact_truth_for_operator(value)
            for key, value in payload.items()
            if key in _PRIVATE_TRUTH_SAFE_KEYS
        }
        redacted["privacy_class"] = privacy_class
        redacted["redacted"] = True
        if "object" in payload:
            redacted["object"] = {"redacted": True, "privacy_class": privacy_class}
        return redacted
    return {key: redact_truth_for_operator(value) for key, value in payload.items()}


def truth_history(
    conn: sqlite3.Connection,
    *,
    project: str,
    claim_id: str,
    limit: int = 500,
) -> dict[str, Any]:
    """Return bounded recorded-time history for one claim."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_claim_id = _required_text("claim_id", claim_id, maximum=128)
    selected_limit = int(limit)
    if not 1 <= selected_limit <= 500:
        raise ValueError("history limit must be between 1 and 500")
    rows = conn.execute(
        """
        SELECT * FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ?
        ORDER BY recorded_from_sequence LIMIT ?
        """,
        (project_id, selected_claim_id, selected_limit),
    ).fetchall()
    return {
        "status": "ok" if rows else "abstain",
        "project": str(project).strip(),
        "claim_id": selected_claim_id,
        "versions": [_claim_version_dict(row) for row in rows],
        "truncated": len(rows) == selected_limit,
    }


def truth_diff(
    conn: sqlite3.Connection,
    *,
    project: str,
    from_sequence: int,
    to_sequence: int,
    valid_at: str,
    limit: int = 500,
) -> dict[str, Any]:
    """Compare project truth at two recorded sequences for one valid time."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_from = int(from_sequence)
    selected_to = int(to_sequence)
    if selected_from < 1 or selected_to < 1 or selected_from >= selected_to:
        raise ValueError("truth diff requires 1 <= from_sequence < to_sequence")
    selected_limit = int(limit)
    if not 1 <= selected_limit <= 500:
        raise ValueError("diff limit must be between 1 and 500")
    selected_valid_at = _required_text("valid_at", valid_at, maximum=64)
    claim_ids = [
        str(row["claim_id"])
        for row in conn.execute(
            """
            SELECT DISTINCT claim_id FROM truth_claim_versions
            WHERE project_id = ? AND recorded_from_sequence <= ?
            ORDER BY claim_id LIMIT ?
            """,
            (project_id, selected_to, selected_limit + 1),
        ).fetchall()
    ]
    truncated = len(claim_ids) > selected_limit
    changes = []
    for selected_claim_id in claim_ids[:selected_limit]:
        before_result = truth_as_of(
            conn,
            project=project,
            claim_id=selected_claim_id,
            valid_at=selected_valid_at,
            recorded_sequence=selected_from,
        )
        after_result = truth_as_of(
            conn,
            project=project,
            claim_id=selected_claim_id,
            valid_at=selected_valid_at,
            recorded_sequence=selected_to,
        )
        before = before_result.get("claim")
        after = after_result.get("claim")
        if before != after:
            changes.append(
                {"claim_id": selected_claim_id, "before": before, "after": after}
            )
    return {
        "status": "ok",
        "project": str(project).strip(),
        "from_sequence": selected_from,
        "to_sequence": selected_to,
        "valid_at": selected_valid_at,
        "changes": changes,
        "truncated": truncated,
    }


def _project_repository_anchor(
    conn: sqlite3.Connection,
    project_id: int,
    project_sequence: int,
    event_id: str,
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        INSERT INTO truth_repository_anchors(
            project_id, anchor_id, repository_identity, checkout_identity,
            repository_ref, repository_commit, dirty_digest,
            recorded_sequence, event_id, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            payload["anchor_id"],
            payload["repository_identity"],
            payload["checkout_identity"],
            payload["repository_ref"],
            payload["repository_commit"],
            payload["dirty_digest"],
            project_sequence,
            event_id,
            payload["observed_at"],
        ),
    )


def observe_repository_anchor(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    anchor_id: str,
    idempotency_key: str,
    expected_stream_version: int,
    actor_type: str = "operator",
    actor_id: str = "local-operator",
    source: str = "python",
) -> dict[str, Any]:
    """Record an exact observed Git commit and checkout state."""

    db.init_schema(conn)
    row = conn.execute(
        """
        SELECT id, repository_identity, checkout_identity FROM projects
        WHERE name = ?
        """,
        (str(project).strip(),),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {project}")
    selected_id = _required_text("anchor_id", anchor_id, maximum=128)
    state = git_anchor_state(active_root)
    payload = {
        "anchor_id": selected_id,
        "checkout_identity": row["checkout_identity"],
        "dirty_digest": state["dirty_digest"],
        "dirty_files": state["dirty_files"],
        "observed_at": db.now_iso(),
        "repository_commit": state["commit"],
        "repository_identity": row["repository_identity"],
        "repository_ref": state["branch"],
    }
    event, duplicate = _append_project_event(
        conn,
        project=project,
        active_root=active_root,
        stream_id=f"repository-anchor:{selected_id}",
        expected_stream_version=expected_stream_version,
        event_type="repository_anchor_observed.v1",
        idempotency_key=idempotency_key,
        payload=payload,
        projector=_project_repository_anchor,
        actor_type=actor_type,
        actor_id=actor_id,
        source=source,
        verification_status="verified",
        privacy_class="internal",
    )
    anchor = conn.execute(
        """
        SELECT * FROM truth_repository_anchors
        WHERE project_id = ? AND event_id = ?
        """,
        (int(row["id"]), event["event_id"]),
    ).fetchone()
    if anchor is None:
        raise RuntimeError("repository anchor event exists without its projection")
    return {
        "status": "ok",
        "idempotent_replay": duplicate,
        "event": {
            "event_id": event["event_id"],
            "project_sequence": int(event["project_sequence"]),
        },
        "anchor": {
            "anchor_id": anchor["anchor_id"],
            "commit": anchor["repository_commit"],
            "ref": anchor["repository_ref"],
            "dirty_digest": anchor["dirty_digest"],
        },
    }


def truth_at_commit(
    conn: sqlite3.Connection,
    *,
    project: str,
    claim_id: str,
    commit: str,
    valid_at: str,
) -> dict[str, Any]:
    """Return truth at an exact observed Git commit, or explicitly abstain."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_commit = str(commit).strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", selected_commit):
        raise ValueError("commit must be a full lowercase Git object ID")
    anchor = conn.execute(
        """
        SELECT * FROM truth_repository_anchors
        WHERE project_id = ? AND repository_commit = ?
        ORDER BY recorded_sequence DESC LIMIT 1
        """,
        (project_id, selected_commit),
    ).fetchone()
    if anchor is None:
        return {
            "status": "abstain",
            "reason": "no explicit anchor exists for the requested Git commit",
            "commit": selected_commit,
        }
    result = truth_as_of(
        conn,
        project=project,
        claim_id=claim_id,
        valid_at=valid_at,
        recorded_sequence=int(anchor["recorded_sequence"]),
    )
    if result["status"] == "ok":
        result["anchor"] = {
            "anchor_id": anchor["anchor_id"],
            "commit": anchor["repository_commit"],
            "ref": anchor["repository_ref"],
            "dirty_digest": anchor["dirty_digest"],
            "recorded_sequence": int(anchor["recorded_sequence"]),
        }
    return result


def _project_row(conn: sqlite3.Connection, project: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT id FROM projects WHERE name = ?", (str(project).strip(),)
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {project}")
    return row


def _projection_payload(conn: sqlite3.Connection, project_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT claim_id, subject_key, subject_display, predicate, object_json,
               polarity, epistemic_state, state_reason, authority_class,
               confidence, verification_status, valid_from, valid_to,
               recorded_from_sequence, recorded_to_sequence,
               opened_by_event_id, closed_by_event_id,
               repository_anchor_event_id, provenance_json, revalidate_at,
               expires_at, privacy_class, sharing_policy, legacy_memory_id
        FROM truth_claim_versions
        WHERE project_id = ?
        ORDER BY claim_id, recorded_from_sequence
        """,
        (project_id,),
    ).fetchall()
    return [_row_as_dict(row) for row in rows]


def _relation_projection_payload(
    conn: sqlite3.Connection, project_id: int
) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT relation_id, from_claim_id, relation_type, to_claim_id,
               authority_class, confidence, valid_from, valid_to,
               recorded_from_sequence, recorded_to_sequence,
               opened_by_event_id, closed_by_event_id
        FROM truth_relations WHERE project_id = ?
        ORDER BY relation_id, recorded_from_sequence
        """,
        (project_id,),
    ).fetchall()
    return [_row_as_dict(row) for row in rows]


def _all_projection_payload(conn: sqlite3.Connection, project_id: int) -> dict[str, Any]:
    evidence = conn.execute(
        """
        SELECT evidence_id, claim_id, source_identifier, source_hash, method,
               actor_type, actor_id, authority_class, confidence, uncertainty,
               polarity, validator_id, valid_from, valid_to,
               recorded_from_sequence, recorded_to_sequence,
               opened_by_event_id, closed_by_event_id, provenance_json,
               privacy_class, sharing_policy
        FROM truth_evidence WHERE project_id = ?
        ORDER BY evidence_id, recorded_from_sequence
        """,
        (project_id,),
    ).fetchall()
    abstentions = conn.execute(
        """
        SELECT abstention_id, query_scope, missing_evidence_json,
               unresolved_conflicts_json, minimum_revalidation_action,
               recorded_sequence, event_id, recorded_at, privacy_class
        FROM truth_abstentions WHERE project_id = ?
        ORDER BY recorded_sequence, abstention_id
        """,
        (project_id,),
    ).fetchall()
    validators = conn.execute(
        """
        SELECT validator_id, validator_type, claim_id, config_json,
               failure_effect, status, defined_sequence, defined_by_event_id,
               privacy_class
        FROM truth_validators WHERE project_id = ?
        ORDER BY validator_id
        """,
        (project_id,),
    ).fetchall()
    validator_results = conn.execute(
        """
        SELECT validator_id, claim_id, outcome, details_json,
               evaluated_sequence, event_id, evaluated_at
        FROM truth_validator_results WHERE project_id = ?
        ORDER BY evaluated_sequence, validator_id
        """,
        (project_id,),
    ).fetchall()
    anchors = conn.execute(
        """
        SELECT anchor_id, repository_identity, checkout_identity,
               repository_ref, repository_commit, dirty_digest,
               recorded_sequence, event_id, observed_at
        FROM truth_repository_anchors WHERE project_id = ?
        ORDER BY recorded_sequence, anchor_id
        """,
        (project_id,),
    ).fetchall()
    return {
        "abstentions": [_row_as_dict(row) for row in abstentions],
        "anchors": [_row_as_dict(row) for row in anchors],
        "claims": _projection_payload(conn, project_id),
        "evidence": [_row_as_dict(row) for row in evidence],
        "relations": _relation_projection_payload(conn, project_id),
        "validator_results": [_row_as_dict(row) for row in validator_results],
        "validators": [_row_as_dict(row) for row in validators],
    }


def projection_digest(conn: sqlite3.Connection, *, project: str) -> str:
    """Return the canonical digest of the current claim projection."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    return _streaming_projection_digest(conn, project_id)


def _streaming_projection_digest(
    conn: sqlite3.Connection,
    project_id: int,
    *,
    row_observer: Callable[[sqlite3.Row, str], None] | None = None,
) -> str:
    """Digest projections with constant aggregate memory and deterministic ordering."""

    tables = (
        ("truth_abstentions", "recorded_sequence, abstention_id"),
        ("truth_repository_anchors", "recorded_sequence, anchor_id"),
        ("truth_claim_versions", "claim_id, recorded_from_sequence"),
        ("truth_evidence", "evidence_id, recorded_from_sequence"),
        ("truth_relations", "relation_id, recorded_from_sequence"),
        ("truth_validator_results", "evaluated_sequence, validator_id"),
        ("truth_validators", "validator_id"),
    )
    digest = hashlib.sha256()
    digest.update(b"rta-smriti-projection-digest-v2\0")
    for table, order_by in tables:
        digest.update(table.encode("ascii") + b"\0")
        cursor = conn.execute(
            f"SELECT * FROM {table} WHERE project_id = ? ORDER BY {order_by}",
            (project_id,),
        )
        for row in cursor:
            if row_observer is not None:
                row_observer(row, table)
            value = _row_as_dict(row, exclude=frozenset({"id", "project_id"}))
            encoded = _canonical_json(value).encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        digest.update(b"\xff")
    return digest.hexdigest()


def _event_envelope_from_row(event: sqlite3.Row) -> dict[str, Any]:
    return {
        "actor_id": event["actor_id"],
        "actor_type": event["actor_type"],
        "checkout_identity": event["checkout_identity"],
        "dirty_digest": event["dirty_digest"],
        "event_id": event["event_id"],
        "event_schema": int(event["event_schema"]),
        "event_type": event["event_type"],
        "idempotency_key": event["idempotency_key"],
        "occurred_at": event["occurred_at"],
        "payload_sha256": event["payload_sha256"],
        "previous_event_hash": event["previous_event_hash"],
        "privacy_class": event["privacy_class"],
        "project_id": int(event["project_id"]),
        "project_sequence": int(event["project_sequence"]),
        "recorded_at": event["recorded_at"],
        "repository_commit": event["repository_commit"],
        "repository_identity": event["repository_identity"],
        "repository_ref": event["repository_ref"],
        "source": event["source"],
        "stream_id": event["stream_id"],
        "stream_version": int(event["stream_version"]),
        "verification_status": event["verification_status"],
    }


def _verify_event(event: sqlite3.Row, *, sequence: int, previous_hash: str | None) -> None:
    if int(event["project_sequence"]) != sequence:
        raise ValueError(
            f"truth event sequence gap: expected {sequence}, "
            f"found {event['project_sequence']}"
        )
    if event["previous_event_hash"] != previous_hash:
        raise ValueError(f"truth event chain mismatch at sequence {sequence}")
    payload_json = str(event["payload_json"])
    if _sha256_text(payload_json) != event["payload_sha256"]:
        raise ValueError(f"truth event payload hash mismatch at sequence {sequence}")
    if _event_hash(_event_envelope_from_row(event)) != event["event_hash"]:
        raise ValueError(f"truth event envelope hash mismatch at sequence {sequence}")
    if (
        event["event_type"]
        not in {
            "claim_asserted.v1",
            "claim_state_changed.v1",
            "claim_related.v1",
            "evidence_attached.v1",
            "abstention_recorded.v1",
            "validator_defined.v1",
            "validator_evaluated.v1",
            "repository_anchor_observed.v1",
            "legacy_memory_registered.v1",
        }
        or int(event["event_schema"]) != 1
    ):
        raise ValueError(
            f"unsupported truth event schema: {event['event_type']} "
            f"schema {event['event_schema']}"
        )


def _legacy_epistemic_state(memory: sqlite3.Row) -> str:
    status = str(memory["status"]).strip().lower()
    verification = str(memory["verification_status"] or "unverified").strip().lower()
    if status == "stale":
        return "stale"
    if status in {"contradicted", "disputed"}:
        return "disputed"
    if status == "superseded":
        return "superseded"
    if verification == "failed":
        return "refuted"
    if verification == "verified":
        return "corroborated" if memory["pramana"] == "pratyaksha" else "observed"
    return "hypothesis"


def _legacy_privacy_class(raw_metadata: Any) -> str:
    """Recover a legacy classification without treating unknown as shareable."""

    try:
        metadata = (
            raw_metadata
            if isinstance(raw_metadata, dict)
            else json.loads(str(raw_metadata or "{}"))
        )
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return "restricted"
    if not isinstance(metadata, dict):
        return "restricted"
    if "privacy_class" not in metadata:
        return "restricted"
    raw_class = metadata["privacy_class"]
    selected = str(raw_class).strip().casefold()
    if selected == "private":
        selected = "restricted"
    return selected if selected in VALID_PRIVACY_CLASSES else "restricted"


def _bounded_legacy_json(raw: Any, *, maximum_bytes: int = 32 * 1024) -> Any:
    """Preserve bounded legacy JSON or register a digest-only omission marker."""

    text = str(raw or "{}")
    raw_bytes = text.encode("utf-8", errors="replace")
    try:
        value = json.loads(text)
        canonical = _canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, RecursionError, json.JSONDecodeError):
        canonical = raw_bytes
        value = None
    if value is not None and len(canonical) <= maximum_bytes:
        return value
    return {
        "legacy_value_omitted": True,
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "utf8_bytes": len(raw_bytes),
    }


def _bounded_legacy_text(raw: Any, *, maximum_chars: int = 4096) -> str | None:
    if raw is None:
        return None
    value = str(raw)
    if len(value) <= maximum_chars:
        return value
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return f"[legacy value omitted: chars={len(value)} sha256={digest}]"


def migrate_legacy_memories(conn: sqlite3.Connection) -> dict[str, int]:
    """Register schema-v7 memories without inventing historical recorded time.

    The caller owns the migration transaction and must have created the v0.7
    ledger and projection tables already.
    """

    memories = conn.execute(
        """
        SELECT m.*, mp.source_path, mp.source_hash, mp.command,
               mp.timestamp AS provenance_timestamp,
               mp.verification_status, mp.metadata_json AS provenance_metadata,
               p.repository_identity, p.checkout_identity
        FROM memories m
        JOIN projects p ON p.id = m.project_id
        LEFT JOIN memory_provenance mp ON mp.memory_id = m.id
        ORDER BY m.project_id, m.id
        """
    ).fetchall()
    migrated = 0
    reclassified = 0
    migration_time = db.now_iso()
    for memory in memories:
        project_id = int(memory["project_id"])
        privacy_class = _legacy_privacy_class(memory["metadata_json"])
        idempotency_key = f"migration:v8:memory:{project_id}:{int(memory['id'])}"
        exists = conn.execute(
            """
            SELECT 1 FROM truth_events
            WHERE project_id = ? AND idempotency_key = ?
            """,
            (project_id, idempotency_key),
        ).fetchone()
        if exists is not None:
            projection_rows = conn.execute(
                "SELECT id, privacy_class FROM truth_claim_versions "
                "WHERE project_id = ? AND legacy_memory_id = ?",
                (project_id, int(memory["id"])),
            ).fetchall()
            for projection in projection_rows:
                repaired_class = _more_restrictive_privacy_class(
                    projection["privacy_class"], privacy_class
                )
                if repaired_class != projection["privacy_class"]:
                    conn.execute(
                        "UPDATE truth_claim_versions SET privacy_class = ? WHERE id = ?",
                        (repaired_class, int(projection["id"])),
                    )
                    reclassified += 1
            continue
        previous = conn.execute(
            """
            SELECT project_sequence, event_hash FROM truth_events
            WHERE project_id = ? ORDER BY project_sequence DESC LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        project_sequence = int(previous["project_sequence"]) + 1 if previous else 1
        previous_event_hash = str(previous["event_hash"]) if previous else None
        memory_id = int(memory["id"])
        claim_id = f"legacy-memory:{memory_id}"
        event_id = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"rta-smriti:{project_id}:legacy-memory:{memory_id}",
        ).hex
        state = _legacy_epistemic_state(memory)
        verification_status = str(
            memory["verification_status"] or "unverified"
        ).strip().lower()
        provenance = {
            "command": _bounded_legacy_text(memory["command"]),
            "metadata": _bounded_legacy_json(memory["provenance_metadata"]),
            "source_hash": _bounded_legacy_text(memory["source_hash"]),
            "source_path": _bounded_legacy_text(memory["source_path"]),
            "timestamp": _bounded_legacy_text(memory["provenance_timestamp"]),
        }
        payload = {
            "authority_class": f"legacy:{memory['pramana']}",
            "claim_id": claim_id,
            "confidence": float(memory["confidence"]),
            "epistemic_state": state,
            "legacy_created_at": memory["created_at"],
            "legacy_memory_id": memory_id,
            "legacy_metadata": _bounded_legacy_json(memory["metadata_json"]),
            "legacy_status": memory["status"],
            "legacy_updated_at": memory["updated_at"],
            "object": memory["text"],
            "polarity": "for",
            "predicate": memory["type"],
            "privacy_class": privacy_class,
            "provenance": provenance,
            "state_reason": "Registered from schema-v7 memory without authority promotion.",
            "subject": f"memory:{memory_id}",
            "subject_key": f"memory:{memory_id}",
            "valid_from": memory["created_at"],
            "valid_to": None,
            "verification_status": verification_status,
        }
        payload_json = _canonical_event_payload(payload)
        payload_sha256 = _sha256_text(payload_json)
        envelope = {
            "actor_id": "schema-v8",
            "actor_type": "migration",
            "checkout_identity": memory["checkout_identity"],
            "dirty_digest": None,
            "event_id": event_id,
            "event_schema": 1,
            "event_type": "legacy_memory_registered.v1",
            "idempotency_key": idempotency_key,
            "occurred_at": memory["created_at"],
            "payload_sha256": payload_sha256,
            "previous_event_hash": previous_event_hash,
            "privacy_class": privacy_class,
            "project_id": project_id,
            "project_sequence": project_sequence,
            "recorded_at": migration_time,
            "repository_commit": None,
            "repository_identity": memory["repository_identity"],
            "repository_ref": None,
            "source": "migration",
            "stream_id": f"claim:{claim_id}",
            "stream_version": 1,
            "verification_status": verification_status,
        }
        event_hash = _event_hash(envelope)
        conn.execute(
            """
            INSERT INTO truth_events(
                project_id, project_sequence, event_id, stream_id, stream_version,
                event_type, event_schema, idempotency_key, payload_json,
                payload_sha256, previous_event_hash, event_hash, actor_type,
                actor_id, source, verification_status, repository_identity,
                checkout_identity, repository_ref, repository_commit,
                dirty_digest, occurred_at, recorded_at, privacy_class
            ) VALUES (?, ?, ?, ?, 1, 'legacy_memory_registered.v1', 1, ?, ?, ?, ?, ?,
                      'migration', 'schema-v8', 'migration', ?, ?, ?, NULL, NULL,
                      NULL, ?, ?, ?)
            """,
            (
                project_id,
                project_sequence,
                event_id,
                envelope["stream_id"],
                idempotency_key,
                payload_json,
                payload_sha256,
                previous_event_hash,
                event_hash,
                verification_status,
                memory["repository_identity"],
                memory["checkout_identity"],
                memory["created_at"],
                migration_time,
                privacy_class,
            ),
        )
        conn.execute(
            """
            INSERT INTO truth_claim_versions(
                project_id, claim_id, subject_key, subject_display, predicate,
                object_json, polarity, epistemic_state, state_reason,
                authority_class, confidence, verification_status, valid_from,
                valid_to, recorded_from_sequence, recorded_to_sequence,
                opened_by_event_id, provenance_json, privacy_class,
                legacy_memory_id
            ) VALUES (?, ?, ?, ?, ?, ?, 'for', ?, ?, ?, ?, ?, ?, NULL, ?, NULL,
                      ?, ?, ?, ?)
            """,
            (
                project_id,
                claim_id,
                payload["subject_key"],
                payload["subject"],
                payload["predicate"],
                _canonical_json(payload["object"]),
                state,
                payload["state_reason"],
                payload["authority_class"],
                float(memory["confidence"]),
                verification_status,
                memory["created_at"],
                project_sequence,
                event_id,
                _canonical_json(provenance),
                privacy_class,
                memory_id,
            ),
        )
        migrated += 1
    return {
        "legacy_memories_registered": migrated,
        "legacy_memories_reclassified": reclassified,
    }


def _replay_claim_assertion(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    event: sqlite3.Row,
) -> None:
    try:
        payload = json.loads(str(event["payload_json"]))
    except json.JSONDecodeError as exc:
        raise ValueError("truth event payload is not valid JSON") from exc
    required = {
        "authority_class",
        "claim_id",
        "confidence",
        "epistemic_state",
        "object",
        "polarity",
        "predicate",
        "privacy_class",
        "state_reason",
        "subject",
        "subject_key",
        "valid_from",
        "valid_to",
        "verification_status",
    }
    if not required.issubset(payload):
        raise ValueError("claim assertion event is missing required fields")
    if event["event_type"] == "legacy_memory_registered.v1":
        memory_id = payload.get("legacy_memory_id")
        memory = conn.execute(
            "SELECT metadata_json FROM memories WHERE project_id = ? AND id = ?",
            (project_id, memory_id),
        ).fetchone()
        if memory is not None:
            payload["privacy_class"] = _more_restrictive_privacy_class(
                payload.get("privacy_class"),
                _legacy_privacy_class(memory["metadata_json"]),
            )
    existing = conn.execute(
        """
        SELECT id FROM truth_claim_versions
        WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
        """,
        (project_id, payload["claim_id"]),
    ).fetchone()
    if existing is not None:
        conn.execute(
            """
            UPDATE truth_claim_versions
            SET recorded_to_sequence = ?, closed_by_event_id = ?
            WHERE id = ?
            """,
            (
                int(event["project_sequence"]),
                event["event_id"],
                int(existing["id"]),
            ),
        )
    conn.execute(
        """
        INSERT INTO truth_claim_versions(
            project_id, claim_id, subject_key, subject_display, predicate,
            object_json, polarity, epistemic_state, state_reason,
            authority_class, confidence, verification_status, valid_from,
            valid_to, recorded_from_sequence, recorded_to_sequence,
            opened_by_event_id, provenance_json, revalidate_at, expires_at,
            privacy_class, sharing_policy, legacy_memory_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            payload["claim_id"],
            payload["subject_key"],
            payload["subject"],
            payload["predicate"],
            _canonical_json(payload["object"]),
            payload["polarity"],
            payload["epistemic_state"],
            payload["state_reason"],
            payload["authority_class"],
            float(payload["confidence"]),
            payload["verification_status"],
            payload["valid_from"],
            payload["valid_to"],
            int(event["project_sequence"]),
            event["event_id"],
            _canonical_json(payload.get("provenance", {})),
            payload.get("revalidate_at"),
            payload.get("expires_at"),
            payload["privacy_class"],
            payload.get("sharing_policy", "local-only"),
            payload.get("legacy_memory_id"),
        ),
    )


def rebuild_projections(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
) -> dict[str, Any]:
    """Verify the ledger and atomically rebuild all v0.7 truth projections."""

    db.init_schema(conn)
    try:
        conn.execute("BEGIN IMMEDIATE")
        project_row = _project_for_write(conn, str(project).strip(), active_root)
        project_id = int(project_row["id"])
        event_count = 0
        previous_hash = None
        for expected_sequence, event in enumerate(conn.execute(
            "SELECT * FROM truth_events WHERE project_id = ? ORDER BY project_sequence",
            (project_id,),
        ), start=1):
            _verify_event(
                event,
                sequence=expected_sequence,
                previous_hash=previous_hash,
            )
            previous_hash = str(event["event_hash"])
            event_count = expected_sequence

        conn.execute("DELETE FROM truth_claim_versions WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM truth_relations WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM truth_evidence WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM truth_abstentions WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM truth_validator_results WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM truth_validators WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM truth_repository_anchors WHERE project_id = ?", (project_id,))
        for event in conn.execute(
            "SELECT * FROM truth_events WHERE project_id = ? ORDER BY project_sequence",
            (project_id,),
        ):
            event_type = str(event["event_type"])
            if event_type in {
                "claim_asserted.v1",
                "claim_state_changed.v1",
                "legacy_memory_registered.v1",
            }:
                _replay_claim_assertion(conn, project_id=project_id, event=event)
            elif event_type == "claim_related.v1":
                _project_relation(
                    conn,
                    project_id,
                    int(event["project_sequence"]),
                    str(event["event_id"]),
                    json.loads(str(event["payload_json"])),
                )
            elif event_type == "evidence_attached.v1":
                _project_evidence(
                    conn,
                    project_id,
                    int(event["project_sequence"]),
                    str(event["event_id"]),
                    json.loads(str(event["payload_json"])),
                )
            elif event_type == "abstention_recorded.v1":
                _project_abstention(
                    conn,
                    project_id,
                    int(event["project_sequence"]),
                    str(event["event_id"]),
                    json.loads(str(event["payload_json"])),
                )
            elif event_type == "validator_defined.v1":
                _project_validator_definition(
                    conn,
                    project_id,
                    int(event["project_sequence"]),
                    str(event["event_id"]),
                    json.loads(str(event["payload_json"])),
                )
            elif event_type == "validator_evaluated.v1":
                _project_validator_result(
                    conn,
                    project_id,
                    int(event["project_sequence"]),
                    str(event["event_id"]),
                    json.loads(str(event["payload_json"])),
                )
            elif event_type == "repository_anchor_observed.v1":
                _project_repository_anchor(
                    conn,
                    project_id,
                    int(event["project_sequence"]),
                    str(event["event_id"]),
                    json.loads(str(event["payload_json"])),
                )
            else:
                raise ValueError(f"unsupported truth event type: {event_type}")

        claim_count = int(conn.execute(
            "SELECT COUNT(*) FROM truth_claim_versions WHERE project_id = ?",
            (project_id,),
        ).fetchone()[0])
        digest = _streaming_projection_digest(conn, project_id)
        conn.execute(
            """
            INSERT INTO truth_projection_state(
                project_id, projection_name, schema_version,
                last_event_sequence, event_chain_hash, projection_digest,
                rebuilt_at
            ) VALUES (?, 'claims', 1, ?, ?, ?, ?)
            ON CONFLICT(project_id, projection_name) DO UPDATE SET
                schema_version = excluded.schema_version,
                last_event_sequence = excluded.last_event_sequence,
                event_chain_hash = excluded.event_chain_hash,
                projection_digest = excluded.projection_digest,
                rebuilt_at = excluded.rebuilt_at
            """,
            (
                project_id,
                event_count,
                previous_hash,
                digest,
                db.now_iso(),
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {
        "status": "ok",
        "project": str(project).strip(),
        "events_replayed": event_count,
        "claims_rebuilt": claim_count,
        "event_chain_hash": previous_hash,
        "projection_digest": digest,
    }


def verify_ledger(
    conn: sqlite3.Connection,
    *,
    project: str,
) -> dict[str, Any]:
    """Verify one project's event chain and report the live projection digest."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    events_verified = 0
    previous_hash = None
    for expected_sequence, event in enumerate(conn.execute(
        "SELECT * FROM truth_events WHERE project_id = ? ORDER BY project_sequence",
        (project_id,),
    ), start=1):
        _verify_event(
            event,
            sequence=expected_sequence,
            previous_hash=previous_hash,
        )
        previous_hash = str(event["event_hash"])
        events_verified = expected_sequence
    state = conn.execute(
        """
        SELECT * FROM truth_projection_state
        WHERE project_id = ? AND projection_name = 'claims'
        """,
        (project_id,),
    ).fetchone()
    digest = _streaming_projection_digest(conn, project_id)
    return {
        "status": "ok",
        "project": str(project).strip(),
        "chain_valid": True,
        "events_verified": events_verified,
        "event_chain_hash": previous_hash,
        "projection_digest": digest,
        "last_rebuilt_sequence": (
            int(state["last_event_sequence"]) if state is not None else None
        ),
        "last_rebuilt_digest_matches": (
            str(state["projection_digest"]) == digest if state is not None else None
        ),
    }


def temporal_readiness(
    conn: sqlite3.Connection,
    *,
    project: str,
) -> dict[str, Any]:
    """Summarize ledger and consequential truth risks for operator readiness."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    try:
        ledger = verify_ledger(conn, project=project)
        ledger_intact = True
        ledger_error = None
    # Readiness must fail closed and still report unexpected ledger corruption.
    except Exception as exc:  # noqa: BLE001
        ledger = None
        ledger_intact = False
        ledger_error = {"type": type(exc).__name__, "message": str(exc)[:500]}
    contradictions = conn.execute(
        """
        SELECT r.relation_id, r.from_claim_id, r.to_claim_id
        FROM truth_relations r
        JOIN truth_claim_versions a
          ON a.project_id = r.project_id AND a.claim_id = r.from_claim_id
         AND a.recorded_to_sequence IS NULL
        JOIN truth_claim_versions b
          ON b.project_id = r.project_id AND b.claim_id = r.to_claim_id
         AND b.recorded_to_sequence IS NULL
        WHERE r.project_id = ? AND r.relation_type = 'contradicts'
          AND r.recorded_to_sequence IS NULL
          AND (a.epistemic_state IN ('accepted', 'corroborated')
               OR b.epistemic_state IN ('accepted', 'corroborated'))
        ORDER BY r.recorded_from_sequence LIMIT 100
        """,
        (project_id,),
    ).fetchall()
    failed_validators = conn.execute(
        """
        SELECT v.validator_id, v.claim_id, v.failure_effect, r.outcome
        FROM truth_validators v
        JOIN truth_claim_versions c
          ON c.project_id = v.project_id AND c.claim_id = v.claim_id
         AND c.recorded_to_sequence IS NULL
        JOIN truth_validator_results r
          ON r.project_id = v.project_id AND r.validator_id = v.validator_id
        WHERE v.project_id = ? AND v.status = 'active'
          AND c.epistemic_state IN ('accepted', 'corroborated')
          AND r.evaluated_sequence = (
              SELECT MAX(r2.evaluated_sequence)
              FROM truth_validator_results r2
              WHERE r2.project_id = r.project_id AND r2.validator_id = r.validator_id
          )
          AND r.outcome IN ('fail', 'error')
        ORDER BY r.evaluated_sequence LIMIT 100
        """,
        (project_id,),
    ).fetchall()
    expired = conn.execute(
        """
        SELECT claim_id FROM truth_claim_versions
        WHERE project_id = ? AND recorded_to_sequence IS NULL
          AND epistemic_state IN ('accepted', 'corroborated')
          AND expires_at IS NOT NULL AND expires_at <= ?
        ORDER BY claim_id LIMIT 100
        """,
        (project_id, db.now_iso()),
    ).fetchall()
    return {
        "status": "ok" if ledger_intact else "error",
        "ledger_intact": ledger_intact,
        "ledger": ledger,
        "ledger_error": ledger_error,
        "high_impact_contradictions": [dict(row) for row in contradictions],
        "high_impact_contradiction_count": len(contradictions),
        "failed_critical_validators": [dict(row) for row in failed_validators],
        "failed_critical_validator_count": len(failed_validators),
        "expired_accepted_claims": [str(row["claim_id"]) for row in expired],
        "expired_accepted_claim_count": len(expired),
        "operationally_ready": (
            ledger_intact and not contradictions and not failed_validators and not expired
        ),
    }


def truth_overview(
    conn: sqlite3.Connection,
    *,
    project: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return a bounded, privacy-aware operator overview of temporal truth."""

    db.init_schema(conn)
    project_id = int(_project_row(conn, project)["id"])
    selected_limit = max(1, min(500, int(limit)))
    claim_rows = conn.execute(
        """
        SELECT claim_id FROM truth_claim_versions
        WHERE project_id = ? AND recorded_to_sequence IS NULL
        ORDER BY recorded_from_sequence DESC LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    claims = []
    for row in claim_rows:
        result = truth_current(conn, project=project, claim_id=str(row["claim_id"]))
        if result["status"] == "ok":
            claims.append(redact_truth_for_operator(result["claim"]))
    contradiction_rows = conn.execute(
        """
        SELECT relation_id, from_claim_id, to_claim_id, authority_class,
               confidence, recorded_from_sequence
        FROM truth_relations
        WHERE project_id = ? AND relation_type = 'contradicts'
          AND recorded_to_sequence IS NULL
        ORDER BY recorded_from_sequence DESC LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    validator_rows = conn.execute(
        """
        SELECT v.validator_id, v.validator_type, v.claim_id, v.failure_effect,
               r.outcome, r.details_json, r.evaluated_sequence, r.evaluated_at
        FROM truth_validators v
        LEFT JOIN truth_validator_results r
          ON r.project_id = v.project_id AND r.validator_id = v.validator_id
         AND r.evaluated_sequence = (
             SELECT MAX(r2.evaluated_sequence)
             FROM truth_validator_results r2
             WHERE r2.project_id = v.project_id AND r2.validator_id = v.validator_id
         )
        WHERE v.project_id = ? AND v.status = 'active'
        ORDER BY v.defined_sequence DESC LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    abstention_rows = conn.execute(
        """
        SELECT abstention_id, query_scope, missing_evidence_json,
               unresolved_conflicts_json, minimum_revalidation_action,
               recorded_sequence, recorded_at
        FROM truth_abstentions WHERE project_id = ?
        ORDER BY recorded_sequence DESC LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    event_rows = conn.execute(
        """
        SELECT project_sequence, event_id, stream_id, stream_version,
               event_type, payload_json, actor_type, actor_id, source,
               verification_status, recorded_at, privacy_class,
               repository_ref, repository_commit
        FROM truth_events WHERE project_id = ?
        ORDER BY project_sequence DESC LIMIT ?
        """,
        (project_id, selected_limit),
    ).fetchall()
    summary_keys = {
        "claim_id", "subject", "predicate", "epistemic_state", "state_reason",
        "revision_reason", "relation_id", "relation_type", "from_claim_id",
        "to_claim_id", "evidence_id", "polarity", "validator_id",
        "validator_type", "outcome", "abstention_id", "query_scope", "anchor_id",
    }
    events = []
    for row in event_rows:
        privacy_class = str(row["privacy_class"])
        if privacy_class in {"sensitive", "restricted"}:
            payload_summary = {"redacted": True, "privacy_class": privacy_class}
        else:
            payload = json.loads(str(row["payload_json"]))
            payload_summary = {
                key: payload[key] for key in summary_keys if key in payload
            }
        events.append({
            "project_sequence": int(row["project_sequence"]),
            "event_id": row["event_id"],
            "stream_id": row["stream_id"],
            "stream_version": int(row["stream_version"]),
            "event_type": row["event_type"],
            "actor_type": row["actor_type"],
            "actor_id": row["actor_id"],
            "source": row["source"],
            "verification_status": row["verification_status"],
            "recorded_at": row["recorded_at"],
            "repository_ref": row["repository_ref"],
            "repository_commit": row["repository_commit"],
            "payload_summary": payload_summary,
        })
    validators = [
        {
            "validator_id": row["validator_id"],
            "type": row["validator_type"],
            "claim_id": row["claim_id"],
            "failure_effect": row["failure_effect"],
            "outcome": row["outcome"] or "not_run",
            "details": json.loads(str(row["details_json"])) if row["details_json"] else {},
            "evaluated_sequence": row["evaluated_sequence"],
            "evaluated_at": row["evaluated_at"],
        }
        for row in validator_rows
    ]
    return {
        "status": "ok",
        "project": str(project).strip(),
        "readiness": temporal_readiness(conn, project=project),
        "counts": {
            "events": int(conn.execute(
                "SELECT COUNT(*) FROM truth_events WHERE project_id = ?", (project_id,)
            ).fetchone()[0]),
            "current_claims": int(conn.execute(
                "SELECT COUNT(*) FROM truth_claim_versions WHERE project_id = ? AND recorded_to_sequence IS NULL",
                (project_id,),
            ).fetchone()[0]),
            "contradictions": int(conn.execute(
                "SELECT COUNT(*) FROM truth_relations WHERE project_id = ? AND relation_type = 'contradicts' AND recorded_to_sequence IS NULL",
                (project_id,),
            ).fetchone()[0]),
            "failed_validators": sum(1 for item in validators if item["outcome"] in {"fail", "error"}),
            "abstentions": int(conn.execute(
                "SELECT COUNT(*) FROM truth_abstentions WHERE project_id = ?", (project_id,)
            ).fetchone()[0]),
        },
        "claims": claims,
        "contradictions": [dict(row) for row in contradiction_rows],
        "validators": validators,
        "abstentions": [
            {
                "abstention_id": row["abstention_id"],
                "query_scope": row["query_scope"],
                "missing_evidence": json.loads(str(row["missing_evidence_json"])),
                "unresolved_conflicts": json.loads(str(row["unresolved_conflicts_json"])),
                "minimum_revalidation_action": row["minimum_revalidation_action"],
                "recorded_sequence": int(row["recorded_sequence"]),
                "recorded_at": row["recorded_at"],
            }
            for row in abstention_rows
        ],
        "events": events,
        "truncated": any(
            len(items) == selected_limit
            for items in (claims, contradiction_rows, validator_rows, abstention_rows, event_rows)
        ),
    }
