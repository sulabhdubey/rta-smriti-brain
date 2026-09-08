"""Permission-first retrieval over accepted local federation projections."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .federation_governance import authorize_operation

MAX_RETRIEVAL_QUERY_TERMS = 64
MAX_RETRIEVAL_PAYLOAD_BYTES = 32 * 1024 * 1024


def _text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for value_item in value for item in _text_values(value_item)]
    if isinstance(value, dict):
        return [item for key in sorted(value) for item in _text_values(value[key])]
    return []


def search_federated_events(
    conn: sqlite3.Connection,
    *,
    project_id: int,
    space_id: str,
    actor_peer_id: str,
    query: str,
    operation: str = "read",
    limit: int = 20,
) -> dict[str, Any]:
    """Search only projections the actor may read or compile into context."""

    selected_query = str(query).strip()
    if not 1 <= len(selected_query) <= 4096 or "\0" in selected_query:
        raise ValueError("federation query must be a bounded non-empty string")
    if operation not in {"read", "context", "diagnose", "export", "index"}:
        raise ValueError("federation retrieval operation is invalid")
    selected_limit = int(limit)
    if not 1 <= selected_limit <= 100:
        raise ValueError("federation retrieval limit is outside the supported range")
    terms = tuple(sorted(set(selected_query.casefold().split())))
    if len(terms) > MAX_RETRIEVAL_QUERY_TERMS:
        raise ValueError("federation query term count exceeds the supported bound")
    scope_rows = list(
        conn.execute(
            "SELECT scope_id FROM federation_scopes "
            "WHERE project_id = ? AND space_id = ? ORDER BY scope_id LIMIT 1001",
            (project_id, space_id),
        )
    )
    if len(scope_rows) > 1000:
        raise ValueError("federation scope inventory exceeds the retrieval bound")
    authorized_scopes = {
        str(row["scope_id"])
        for row in scope_rows
        if authorize_operation(
            conn,
            project_id=project_id,
            space_id=space_id,
            scope_id=str(row["scope_id"]),
            peer_id=actor_peer_id,
            operation=operation,
        )["allowed"]
    }
    rows = conn.execute(
        "SELECT event_id, scope_id, event_type, object_id, author_peer_id, "
        "causal_depth, deterministic_order, payload_json, payload_digest, "
        "LENGTH(CAST(payload_json AS BLOB)) AS payload_bytes "
        "FROM federation_domain_events WHERE project_id = ? AND space_id = ? "
        "ORDER BY deterministic_order LIMIT 10001",
        (project_id, space_id),
    )
    matches = []
    row_count = 0
    payload_bytes = 0
    for row in rows:
        row_count += 1
        if row_count > 10_000:
            raise ValueError("federation projection exceeds the retrieval bound")
        scope_id = str(row["scope_id"])
        if scope_id not in authorized_scopes:
            continue
        payload_bytes += int(row["payload_bytes"] or 0)
        if payload_bytes > MAX_RETRIEVAL_PAYLOAD_BYTES:
            raise ValueError("federation retrieval payload byte limit exceeded")
        payload = json.loads(str(row["payload_json"]))
        text_values = _text_values(payload)
        combined = " ".join(text_values)
        haystack = combined.casefold()
        score = sum(haystack.count(term) for term in terms)
        if score == 0:
            continue
        matches.append(
            {
                "event_id": str(row["event_id"]),
                "scope_id": scope_id,
                "event_type": str(row["event_type"]),
                "object_id": str(row["object_id"]),
                "author_peer_id": str(row["author_peer_id"]),
                "causal_depth": int(row["causal_depth"]),
                "deterministic_order": int(row["deterministic_order"]),
                "content_preview": combined[:4096],
                "payload_digest": str(row["payload_digest"]),
                "score": score,
            }
        )
    matches.sort(key=lambda item: (-item["score"], item["deterministic_order"], item["event_id"]))
    return {
        "schema": "rta-smriti.federation-retrieval/v1",
        "operation": operation,
        "authorized_scope_count": len(authorized_scopes),
        "result_count": min(len(matches), selected_limit),
        "results": matches[:selected_limit],
    }
