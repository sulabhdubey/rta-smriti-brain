"""Deterministic, provenance-preserving projections for accepted federation events."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from .federation import deterministic_event_order
from .federation_crypto import decrypt_event
from .federation_governance import authorize_operation
from .federation_types import FederationEventEnvelope, canonical_json_bytes

_EVENT_TYPES = frozenset(
    {
        "memory.asserted",
        "memory.corrected",
        "evidence.attached",
        "comment.added",
        "review.requested",
        "approval.proposed",
        "decision.recorded",
    }
)
_MEMORY_TYPES = frozenset({"memory.asserted", "memory.corrected"})


def _now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _text(payload: dict[str, Any], name: str, *, maximum: int = 256_000) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} is required")
    selected = value.strip()
    if len(selected) > maximum or "\0" in selected:
        raise ValueError(f"{name} exceeds the configured limit")
    return selected


def _string_list(
    payload: dict[str, Any], name: str, *, required: bool = False
) -> list[str]:
    value = payload.get(name, [])
    if not isinstance(value, list) or len(value) > 256:
        raise ValueError(f"{name} must be a bounded list")
    selected = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 512 or "\0" in item:
            raise ValueError(f"{name} contains an invalid identifier")
        selected.append(item)
    if len(selected) != len(set(selected)) or (required and not selected):
        raise ValueError(f"{name} must contain unique values")
    return sorted(selected)


def _validate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    event_type = _text(payload, "event_type", maximum=128)
    if event_type not in _EVENT_TYPES:
        raise ValueError(f"unsupported federation domain event: {event_type}")
    object_id = _text(payload, "object_id", maximum=512)
    normalized = dict(payload)
    normalized["event_type"] = event_type
    normalized["object_id"] = object_id
    if event_type in _MEMORY_TYPES:
        normalized["text"] = _text(payload, "text")
        privacy = _text(payload, "privacy_class", maximum=32).casefold()
        if privacy not in {"public", "internal", "sensitive", "restricted"}:
            raise ValueError("privacy_class is invalid")
        epistemic = _text(payload, "epistemic_state", maximum=32).casefold()
        if epistemic not in {
            "hypothesis", "observed", "corroborated", "accepted", "disputed",
            "stale", "refuted", "superseded", "retracted",
        }:
            raise ValueError("epistemic_state is invalid")
        normalized["privacy_class"] = privacy
        normalized["epistemic_state"] = epistemic
        normalized["supersedes_event_ids"] = _string_list(
            payload, "supersedes_event_ids"
        )
    elif event_type == "evidence.attached":
        normalized["evidence_id"] = _text(payload, "evidence_id", maximum=512)
        normalized["source_identifier"] = _text(
            payload, "source_identifier", maximum=4096
        )
        source_hash = _text(payload, "source_hash", maximum=64)
        if len(source_hash) != 64 or any(char not in "0123456789abcdef" for char in source_hash):
            raise ValueError("source_hash must be lower-case SHA-256")
        polarity = _text(payload, "polarity", maximum=32).casefold()
        if polarity not in {"supporting", "weakening", "refuting"}:
            raise ValueError("polarity is invalid")
        normalized["source_hash"] = source_hash
        normalized["polarity"] = polarity
    elif event_type == "comment.added":
        normalized["comment_id"] = _text(payload, "comment_id", maximum=512)
        normalized["text"] = _text(payload, "text")
    elif event_type == "review.requested":
        normalized["review_id"] = _text(payload, "review_id", maximum=512)
        normalized["summary"] = _text(payload, "summary", maximum=8192)
    elif event_type == "approval.proposed":
        normalized["proposal_id"] = _text(payload, "proposal_id", maximum=512)
        normalized["review_id"] = _text(payload, "review_id", maximum=512)
        outcome = _text(payload, "outcome", maximum=32).casefold()
        if outcome not in {"approve", "reject", "abstain", "changes_requested"}:
            raise ValueError("approval outcome is invalid")
        normalized["outcome"] = outcome
        normalized["reason"] = _text(payload, "reason", maximum=8192)
    elif event_type == "decision.recorded":
        normalized["decision_id"] = _text(payload, "decision_id", maximum=512)
        outcome = _text(payload, "outcome", maximum=32).casefold()
        if outcome not in {"accepted", "rejected", "deferred"}:
            raise ValueError("decision outcome is invalid")
        normalized["outcome"] = outcome
        normalized["selected_event_ids"] = _string_list(
            payload, "selected_event_ids", required=outcome == "accepted"
        )
        normalized["resolved_event_ids"] = _string_list(
            payload, "resolved_event_ids", required=True
        )
        normalized["reason"] = _text(payload, "reason", maximum=8192)
    canonical_json_bytes(normalized)
    return normalized


def _envelope(row: sqlite3.Row) -> FederationEventEnvelope:
    return FederationEventEnvelope(
        space_id=str(row["space_id"]),
        scope_id=str(row["scope_id"]),
        epoch=int(row["epoch"]),
        event_id=str(row["event_id"]),
        author_peer_id=str(row["author_peer_id"]),
        author_sequence=int(row["author_sequence"]),
        capability_event_id=str(row["capability_event_id"]),
        parents=tuple(json.loads(str(row["parents_json"]))),
        nonce=bytes(row["nonce"]),
        ciphertext=bytes(row["ciphertext"]),
        ciphertext_sha256=str(row["ciphertext_sha256"]),
        signature=bytes(row["signature"]),
        received_at=str(row["received_at"]),
    )


def _is_ancestor(event_id: str, descendant_id: str, parents: dict[str, tuple[str, ...]]) -> bool:
    pending = list(parents.get(descendant_id, ()))
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current == event_id:
            return True
        if current not in visited:
            visited.add(current)
            pending.extend(parents.get(current, ()))
    return False


def rebuild_domain_projection(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    actor_peer_id: str,
    scope_keys: dict[int | tuple[str, int], bytes],
) -> dict[str, Any]:
    """Decrypt only index-authorized events and derive a deterministic collaboration view."""

    ordered = deterministic_event_order(conn, project_id=project_id, space_id=space_id)
    projected: list[dict[str, Any]] = []
    authorization_by_scope: dict[str, bool] = {}
    try:
        conn.execute("BEGIN IMMEDIATE")
        for position, item in enumerate(ordered, start=1):
            row = conn.execute(
                """
                SELECT e.*, v.validation_state
                FROM federation_events e
                JOIN federation_event_validation v ON v.event_row_id = e.id
                WHERE e.project_id = ? AND e.space_id = ? AND e.event_id = ?
                """,
                (project_id, space_id, item["event_id"]),
            ).fetchone()
            if row is None or str(row["validation_state"]) != "accepted":
                continue
            epoch = int(row["epoch"])
            scope_id = str(row["scope_id"])
            if scope_id not in authorization_by_scope:
                authorization_by_scope[scope_id] = bool(
                    authorize_operation(
                        conn,
                        project_id=project_id,
                        space_id=space_id,
                        scope_id=scope_id,
                        peer_id=actor_peer_id,
                        operation="index",
                    )["allowed"]
                )
            if not authorization_by_scope[scope_id]:
                continue
            scope_key = scope_keys.get((scope_id, epoch))
            if scope_key is None:
                legacy_scopes = {
                    str(candidate["scope_id"])
                    for candidate in ordered
                }
                if len(legacy_scopes) == 1:
                    scope_key = scope_keys.get(epoch)
            if scope_key is None:
                raise ValueError(
                    f"scope key is unavailable for protection scope {scope_id} epoch {epoch}"
                )
            peer = conn.execute(
                "SELECT signing_public_key FROM federation_peers "
                "WHERE project_id = ? AND space_id = ? AND peer_id = ?",
                (project_id, space_id, str(row["author_peer_id"])),
            ).fetchone()
            if peer is None:
                raise ValueError("accepted federation event has an unknown author")
            payload = _validate_payload(
                decrypt_event(
                    _envelope(row),
                    author_signing_public_key=bytes(peer["signing_public_key"]),
                    scope_key=scope_key,
                )
            )
            encoded = canonical_json_bytes(payload)
            conn.execute(
                """
                INSERT OR IGNORE INTO federation_domain_events(
                    project_id, space_id, scope_id, event_id, event_type,
                    object_id, author_peer_id, causal_depth, deterministic_order,
                    payload_json, payload_digest, projected_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project_id,
                    space_id,
                    str(row["scope_id"]),
                    str(row["event_id"]),
                    payload["event_type"],
                    payload["object_id"],
                    str(row["author_peer_id"]),
                    int(item["causal_depth"]),
                    position,
                    encoded.decode("ascii"),
                    hashlib.sha256(encoded).hexdigest(),
                    _now_iso(),
                ),
            )
            projected.append(
                {
                    **payload,
                    "event_id": str(row["event_id"]),
                    "author_peer_id": str(row["author_peer_id"]),
                    "parents": list(item["parents"]),
                    "causal_depth": int(item["causal_depth"]),
                }
            )

        by_id = {item["event_id"]: item for item in projected}
        parents = {item["event_id"]: tuple(item["parents"]) for item in projected}
        memories = [item for item in projected if item["event_type"] in _MEMORY_TYPES]
        for item in projected:
            if item["event_type"] == "memory.corrected":
                for target in item["supersedes_event_ids"]:
                    if target not in by_id or by_id[target]["object_id"] != item["object_id"]:
                        raise ValueError("correction references an unknown memory version")

        decisions = [item for item in projected if item["event_type"] == "decision.recorded"]
        decisions_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in decisions:
            decisions_by_object[item["object_id"]].append(item)
        objects = []
        conflict_count = 0
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in memories:
            grouped[item["object_id"]].append(item)
        for object_id in sorted(grouped):
            versions = grouped[object_id]
            heads = [
                item
                for item in versions
                if not any(
                    item["event_id"] in other.get("supersedes_event_ids", [])
                    or _is_ancestor(item["event_id"], other["event_id"], parents)
                    for other in versions
                    if other["event_id"] != item["event_id"]
                )
            ]
            selected: list[str] = []
            object_decisions = decisions_by_object.get(object_id, [])
            decision_heads = [
                item
                for item in object_decisions
                if not any(
                    _is_ancestor(item["event_id"], other["event_id"], parents)
                    for other in object_decisions
                    if other["event_id"] != item["event_id"]
                )
            ]
            decision_conflicts = sorted(
                item["event_id"] for item in decision_heads
            ) if len(decision_heads) > 1 else []
            decision = decision_heads[0] if len(decision_heads) == 1 else None
            if decision is not None:
                resolved = set(decision["resolved_event_ids"])
                head_ids = {item["event_id"] for item in heads}
                if not head_ids.issubset(resolved):
                    raise ValueError("decision does not resolve every current conflicting head")
                prior_decision_parents = {
                    parent
                    for parent in decision["parents"]
                    if parent in {item["event_id"] for item in object_decisions}
                }
                if not prior_decision_parents.issubset(resolved):
                    raise ValueError("decision does not explicitly resolve its parent decisions")
                selected = list(decision["selected_event_ids"])
                if not set(selected).issubset(resolved) or not set(selected).issubset(by_id):
                    raise ValueError("decision selects an unknown or unresolved event")
                heads = [item for item in heads if item["event_id"] in selected]
            conflict = bool(decision_conflicts) or len(heads) > 1
            conflict_count += int(conflict)
            objects.append(
                {
                    "object_id": object_id,
                    "state": "conflict" if conflict else "ready",
                    "head_event_ids": sorted(item["event_id"] for item in heads),
                    "selected_event_ids": selected,
                    "decision_event_id": decision["event_id"] if decision is not None else None,
                    "decision_conflict_event_ids": decision_conflicts,
                    "versions": [
                        {
                            "event_id": item["event_id"],
                            "author_peer_id": item["author_peer_id"],
                            "text": item["text"],
                            "valid_from": item.get("valid_from"),
                            "valid_to": item.get("valid_to"),
                            "privacy_class": item["privacy_class"],
                            "epistemic_state": item["epistemic_state"],
                        }
                        for item in versions
                    ],
                }
            )

        categorized = {
            "evidence": [item for item in projected if item["event_type"] == "evidence.attached"],
            "comments": [item for item in projected if item["event_type"] == "comment.added"],
            "reviews": [item for item in projected if item["event_type"] == "review.requested"],
            "approvals": [item for item in projected if item["event_type"] == "approval.proposed"],
            "decisions": decisions,
        }
        counts = {
            "memories": len(memories),
            **{name: len(items) for name, items in categorized.items()},
        }
        digest_input = [
            {"event_id": item["event_id"], "payload": {k: v for k, v in item.items() if k not in {"parents", "causal_depth", "author_peer_id", "event_id"}}}
            for item in projected
        ]
        head_digest = hashlib.sha256(canonical_json_bytes(digest_input)).hexdigest()
        state = "conflict" if conflict_count else "ready"
        conn.execute(
            """
            INSERT INTO federation_projections(
                project_id, space_id, projection_name, schema_version,
                accepted_event_count, head_digest, state, rebuilt_at
            ) VALUES (?, ?, 'domain', 1, ?, ?, ?, ?)
            ON CONFLICT(project_id, space_id, projection_name) DO UPDATE SET
                accepted_event_count = excluded.accepted_event_count,
                head_digest = excluded.head_digest,
                state = excluded.state,
                rebuilt_at = excluded.rebuilt_at
            """,
            (project_id, space_id, len(projected), head_digest, state, _now_iso()),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise

    return {
        "state": state,
        "head_digest": head_digest,
        "conflict_count": conflict_count,
        "authorized_scope_count": sum(authorization_by_scope.values()),
        "objects": objects,
        "counts": counts,
        **categorized,
    }
