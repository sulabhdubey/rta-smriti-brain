"""Snapshot-bound progressive retrieval for bounded agent context."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Mapping
from typing import Any

from .db import latest_checkpoint, search

RETRIEVAL_SCHEMA = "rta-smriti.progressive-retrieval/v1"
STAGES = frozenset({"index", "timeline", "evidence"})
PRIVACY_RANKS = {"public": 0, "internal": 1, "sensitive": 2, "restricted": 3}
MAX_QUERY_CHARS = 10_000
MAX_SNAPSHOT_ROWS = 4_096
MAX_SNAPSHOT_ITEM_BYTES = 2 * 1024 * 1024


def _stable_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_stable_json(value)).hexdigest()


def _bounded_digest(value: Any) -> str:
    encoded = _stable_json(value)
    if len(encoded) > MAX_SNAPSHOT_ITEM_BYTES:
        raise PermissionError(
            "progressive retrieval snapshot material exceeds its bound"
        )
    return hashlib.sha256(encoded).hexdigest()


def _token_estimate(value: Any) -> int:
    return max(1, math.ceil(len(_stable_json(value)) / 4))


def _privacy_rank(value: str) -> int:
    selected = str(value).casefold()
    if selected == "private":
        selected = "restricted"
    return PRIVACY_RANKS.get(selected, len(PRIVACY_RANKS))


def _metadata_privacy_class(metadata: Any) -> str:
    if not isinstance(metadata, Mapping) or "privacy_class" not in metadata:
        return "restricted"
    selected = str(metadata.get("privacy_class") or "").strip().casefold()
    if selected == "private":
        selected = "restricted"
    return selected if selected in PRIVACY_RANKS else "restricted"


def _privacy_class(value: Any) -> str:
    selected = str(value or "").strip().casefold()
    if selected == "private":
        selected = "restricted"
    return selected if selected in PRIVACY_RANKS else "restricted"


def _fit_items_to_budget(
    items: list[dict[str, Any]], max_tokens: int
) -> tuple[list[dict[str, Any]], bool]:
    bounded = list(items)
    truncated = False
    while bounded and _token_estimate(bounded) > max_tokens:
        bounded.pop()
        truncated = True
    return bounded, truncated


def _bounded_rows(conn, sql: str, parameters: tuple[Any, ...]) -> list[dict[str, Any]]:
    rows = conn.execute(sql, parameters).fetchmany(MAX_SNAPSHOT_ROWS + 1)
    if len(rows) > MAX_SNAPSHOT_ROWS:
        raise PermissionError(
            "progressive retrieval snapshot references exceed their bound"
        )
    return [dict(row) for row in rows]


def _public_descriptor(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in descriptor.items() if not str(key).startswith("_")
    }


class ProgressiveRetriever:
    """Keep opaque expansion handles bound to one server session and snapshot."""

    def __init__(self, secret: bytes, *, max_handles: int = 1_024) -> None:
        if not isinstance(secret, bytes) or len(secret) < 8:
            raise ValueError("progressive retrieval requires a session secret")
        self._secret = secret
        self._max_handles = max(1, min(10_000, int(max_handles)))
        self._handles: dict[str, dict[str, Any]] = {}

    def _opaque_reference(self, value: Any) -> str | None:
        if value in (None, ""):
            return None
        return hmac.new(self._secret, _stable_json(value), hashlib.sha256).hexdigest()

    def _bind_memory(
        self, conn, descriptor: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        row = conn.execute(
            """
            SELECT m.id, m.type, m.pramana, m.text, m.confidence, m.priority,
                   m.status, m.metadata_json, m.created_at, m.updated_at,
                   mp.source_path, mp.source_hash, mp.command,
                   mp.timestamp AS provenance_timestamp,
                   mp.verification_status, mp.metadata_json AS provenance_metadata_json
            FROM memories m
            LEFT JOIN memory_provenance mp ON mp.memory_id = m.id
            WHERE m.id = ?
            """,
            (descriptor["id"],),
        ).fetchone()
        if row is None:
            raise PermissionError("progressive retrieval handle snapshot is stale")
        item = dict(row)
        bound = {
            **descriptor,
            "_content_fingerprint": _bounded_digest(
                {
                    key: item[key]
                    for key in (
                        "id",
                        "type",
                        "pramana",
                        "text",
                        "confidence",
                        "priority",
                        "status",
                        "metadata_json",
                    )
                }
            ),
            "_authority_fingerprint": _bounded_digest(
                {
                    "pramana": item["pramana"],
                    "confidence": item["confidence"],
                    "priority": item["priority"],
                    "verification_status": item["verification_status"],
                }
            ),
            "_privacy_fingerprint": _bounded_digest(
                {
                    "privacy_class": descriptor["privacy_class"],
                    "metadata_json": item["metadata_json"],
                }
            ),
            "_temporal_fingerprint": _bounded_digest(
                {
                    "status": item["status"],
                    "created_at": item["created_at"],
                    "updated_at": item["updated_at"],
                }
            ),
            "_provenance_fingerprint": _bounded_digest(
                {
                    key: item[key]
                    for key in (
                        "source_path",
                        "source_hash",
                        "command",
                        "provenance_timestamp",
                        "verification_status",
                        "provenance_metadata_json",
                    )
                }
            ),
        }
        references = [
            {
                "kind": "memory",
                "memory_id": int(item["id"]),
                "provenance_fingerprint": self._opaque_reference(
                    bound["_provenance_fingerprint"]
                ),
            }
        ]
        return bound, references

    def _bind_chunk(
        self, conn, descriptor: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        row = conn.execute(
            """
            SELECT c.id, c.ordinal, c.text, c.hash AS chunk_hash,
                   s.id AS source_id, s.kind AS source_kind, s.path AS source_path,
                   s.title AS source_title, s.hash AS source_hash,
                   s.metadata_json AS source_metadata_json,
                   s.created_at AS source_created_at, s.updated_at AS source_updated_at
            FROM chunks c
            JOIN sources s ON s.id = c.source_id
            WHERE c.id = ?
            """,
            (descriptor["id"],),
        ).fetchone()
        if row is None:
            raise PermissionError("progressive retrieval handle snapshot is stale")
        item = dict(row)
        bound = {
            **descriptor,
            "_content_fingerprint": _bounded_digest(
                {
                    "id": item["id"],
                    "ordinal": item["ordinal"],
                    "text": item["text"],
                    "chunk_hash": item["chunk_hash"],
                }
            ),
            "_authority_fingerprint": _bounded_digest(
                {"authority_score": descriptor["authority_score"]}
            ),
            "_privacy_fingerprint": _bounded_digest(
                {"privacy_class": descriptor["privacy_class"]}
            ),
            "_temporal_fingerprint": _bounded_digest(
                {
                    "created_at": item["source_created_at"],
                    "updated_at": item["source_updated_at"],
                }
            ),
            "_provenance_fingerprint": _bounded_digest(
                {
                    key: item[key]
                    for key in (
                        "source_id",
                        "source_kind",
                        "source_path",
                        "source_title",
                        "source_hash",
                        "source_metadata_json",
                    )
                }
            ),
        }
        references = [
            {
                "kind": "repository_chunk",
                "chunk_id": int(item["id"]),
                "source_id": int(item["source_id"]),
                "provenance_fingerprint": self._opaque_reference(
                    bound["_provenance_fingerprint"]
                ),
            }
        ]
        return bound, references

    def _bind_truth(
        self,
        conn,
        project: str,
        descriptor: dict[str, Any],
        operator_view: Mapping[str, Any],
        privacy_ceiling: str,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], int]:
        row = conn.execute(
            """
            SELECT t.* FROM truth_claim_versions t
            JOIN projects p ON p.id = t.project_id
            WHERE p.name = ? AND t.claim_id = ? AND t.recorded_to_sequence IS NULL
            ORDER BY t.recorded_from_sequence DESC LIMIT 1
            """,
            (project, descriptor["id"]),
        ).fetchone()
        if row is None:
            raise PermissionError("progressive retrieval handle snapshot is stale")
        item = dict(row)
        project_id = int(item["project_id"])
        claim_id = str(item["claim_id"])
        evidence = _bounded_rows(
            conn,
            """
            SELECT * FROM truth_evidence
            WHERE project_id = ? AND claim_id = ? AND recorded_to_sequence IS NULL
            ORDER BY recorded_from_sequence, evidence_id
            """,
            (project_id, claim_id),
        )
        evidence_ceiling = _privacy_rank(privacy_ceiling)
        visible_evidence = []
        filtered_evidence = 0
        for evidence_item in evidence:
            evidence_privacy = _privacy_class(evidence_item.get("privacy_class"))
            if _privacy_rank(evidence_privacy) > evidence_ceiling:
                filtered_evidence += 1
                continue
            visible_evidence.append(evidence_item)
        relations = _bounded_rows(
            conn,
            f"""
            WITH related AS (
                SELECT r.*,
                       CASE WHEN r.from_claim_id = ?
                            THEN r.to_claim_id ELSE r.from_claim_id END
                            AS other_claim_id
                FROM truth_relations r
                WHERE r.project_id = ? AND r.recorded_to_sequence IS NULL
                  AND (r.from_claim_id = ? OR r.to_claim_id = ?)
            )
            SELECT related.*, c.privacy_class AS other_privacy_class
            FROM related
            LEFT JOIN truth_claim_versions c
              ON c.project_id = related.project_id
             AND c.claim_id = related.other_claim_id
             AND c.recorded_to_sequence IS NULL
            ORDER BY related.recorded_from_sequence, related.relation_id
            LIMIT {MAX_SNAPSHOT_ROWS + 1}
            """,
            (claim_id, project_id, claim_id, claim_id),
        )
        visible_relations = [
            relation
            for relation in relations
            if _privacy_rank(_privacy_class(relation.get("other_privacy_class")))
            <= evidence_ceiling
        ]
        filtered_relations = len(relations) - len(visible_relations)
        validators = _bounded_rows(
            conn,
            """
            SELECT v.validator_id, v.failure_effect, v.status,
                   r.outcome, r.evaluated_sequence, r.evaluated_at
            FROM truth_validators v
            LEFT JOIN truth_validator_results r
              ON r.project_id = v.project_id AND r.validator_id = v.validator_id
            WHERE v.project_id = ? AND v.claim_id = ?
            ORDER BY v.validator_id, r.evaluated_sequence
            """,
            (project_id, claim_id),
        )
        content = {
            key: item[key]
            for key in (
                "claim_id",
                "subject_key",
                "subject_display",
                "predicate",
                "object_json",
                "polarity",
                "state_reason",
            )
        }
        authority = {
            key: item[key]
            for key in (
                "authority_class",
                "confidence",
                "verification_status",
            )
        }
        privacy = {
            "privacy_class": item["privacy_class"],
            "sharing_policy": item["sharing_policy"],
        }
        temporal = {
            key: item[key]
            for key in (
                "epistemic_state",
                "valid_from",
                "valid_to",
                "recorded_from_sequence",
                "recorded_to_sequence",
                "revalidate_at",
                "expires_at",
            )
        }
        temporal["effective_state"] = operator_view.get("effective_state")
        visible_related_claim_ids = {
            str(relation["other_claim_id"]) for relation in visible_relations
        }
        temporal["contradictions"] = [
            related_id
            for related_id in operator_view.get("contradictions", [])
            if str(related_id) in visible_related_claim_ids
        ]
        temporal["validator_failures"] = operator_view.get("validator_failures", [])
        provenance = {
            "opened_by_event_id": item["opened_by_event_id"],
            "closed_by_event_id": item["closed_by_event_id"],
            "repository_anchor_event_id": item["repository_anchor_event_id"],
            "provenance_json": item["provenance_json"],
            "legacy_memory_id": item["legacy_memory_id"],
            "evidence": evidence,
            "relations": relations,
            "validators": validators,
        }
        bound = {
            **descriptor,
            "_content_fingerprint": _bounded_digest(content),
            "_authority_fingerprint": _bounded_digest(authority),
            "_privacy_fingerprint": _bounded_digest(privacy),
            "_temporal_fingerprint": _bounded_digest(temporal),
            "_provenance_fingerprint": _bounded_digest(provenance),
        }
        references: list[dict[str, Any]] = [
            {
                "kind": "truth_claim",
                "claim_id": claim_id,
                "recorded_from_sequence": int(item["recorded_from_sequence"]),
                "opened_by_event_id": item["opened_by_event_id"],
                "repository_anchor_event_id": item["repository_anchor_event_id"],
                "provenance_fingerprint": self._opaque_reference(
                    item["provenance_json"] or "{}"
                ),
            }
        ]
        references.extend(
            {
                "kind": "truth_evidence",
                "evidence_id": evidence_item["evidence_id"],
                "source_hash": evidence_item["source_hash"],
                "source_identifier_fingerprint": self._opaque_reference(
                    evidence_item["source_identifier"]
                ),
                "method": evidence_item["method"],
                "polarity": evidence_item["polarity"],
                "authority_class": evidence_item["authority_class"],
                "verification_event_id": evidence_item["opened_by_event_id"],
                "provenance_fingerprint": self._opaque_reference(
                    evidence_item["provenance_json"] or "{}"
                ),
            }
            for evidence_item in visible_evidence
        )
        references.extend(
            {
                "kind": "truth_relation",
                "relation_id": relation["relation_id"],
                "relation_type": relation["relation_type"],
                "other_claim_id": (
                    relation["to_claim_id"]
                    if relation["from_claim_id"] == claim_id
                    else relation["from_claim_id"]
                ),
                "opened_by_event_id": relation["opened_by_event_id"],
            }
            for relation in visible_relations
        )
        return bound, references, filtered_evidence + filtered_relations

    def _bind_descriptors(
        self,
        conn,
        project: str,
        result: Mapping[str, Any],
        descriptors: list[dict[str, Any]],
        privacy_ceiling: str,
    ) -> tuple[
        list[dict[str, Any]],
        dict[tuple[str, str], list[dict[str, Any]]],
        int,
    ]:
        truth_by_id = {
            str(item.get("claim_id") or ""): item for item in result.get("truth", [])
        }
        bound: list[dict[str, Any]] = []
        references: dict[tuple[str, str], list[dict[str, Any]]] = {}
        filtered = 0
        for descriptor in descriptors:
            kind = str(descriptor["kind"])
            if kind == "memory":
                item, item_references = self._bind_memory(conn, descriptor)
            elif kind == "chunk":
                item, item_references = self._bind_chunk(conn, descriptor)
            else:
                item, item_references, item_filtered = self._bind_truth(
                    conn,
                    project,
                    descriptor,
                    truth_by_id.get(str(descriptor["id"]), {}),
                    privacy_ceiling,
                )
                filtered += item_filtered
            bound.append(item)
            references[(kind, str(descriptor["id"]))] = item_references
        return bound, references, filtered

    def _select(
        self,
        conn,
        *,
        project: str,
        query: str,
        limit: int,
        privacy_ceiling: str,
    ) -> tuple[
        dict[str, Any],
        list[dict[str, Any]],
        dict[tuple[str, str], list[dict[str, Any]]],
        int,
    ]:
        result = search(
            conn,
            query,
            project=project,
            limit=limit,
            record_recall=False,
        )
        ceiling = _privacy_rank(privacy_ceiling)
        descriptors: list[dict[str, Any]] = []
        filtered = 0
        for memory in result.get("memories", []):
            metadata = memory.get("metadata")
            if not isinstance(metadata, Mapping):
                try:
                    metadata = json.loads(memory.get("metadata_json") or "{}")
                except json.JSONDecodeError:
                    metadata = {}
            privacy_class = _metadata_privacy_class(metadata)
            if _privacy_rank(privacy_class) > ceiling:
                filtered += 1
                continue
            descriptors.append(
                {
                    "kind": "memory",
                    "id": int(memory["id"]),
                    "type": str(memory.get("type") or "memory"),
                    "pramana": str(memory.get("pramana") or "unknown"),
                    "authority": str(
                        (memory.get("provenance") or {}).get(
                            "verification_status", "unverified"
                        )
                    ),
                    "privacy_class": privacy_class,
                }
            )
        for chunk in result.get("chunks", []):
            privacy_class = str(chunk.get("privacy_class") or "restricted")
            if _privacy_rank(privacy_class) > ceiling:
                filtered += 1
                continue
            descriptors.append(
                {
                    "kind": "chunk",
                    "id": int(chunk["id"]),
                    "path": str(chunk.get("path") or ""),
                    "source_hash": str(chunk.get("source_hash") or ""),
                    "authority_score": int(chunk.get("source_authority_score") or 0),
                    "privacy_class": privacy_class,
                }
            )
        for claim in result.get("truth", []):
            privacy_class = _privacy_class(claim.get("privacy_class"))
            if _privacy_rank(privacy_class) > ceiling:
                filtered += 1
                continue
            descriptors.append(
                {
                    "kind": "truth",
                    "id": str(claim.get("claim_id") or ""),
                    "state": str(
                        claim.get("effective_state")
                        or claim.get("epistemic_state")
                        or "unknown"
                    ),
                    "privacy_class": privacy_class,
                }
            )
        bound, references, child_filtered = self._bind_descriptors(
            conn, project, result, descriptors, privacy_ceiling
        )
        return result, bound, references, filtered + child_filtered

    def _issue_handle(self, payload: dict[str, Any]) -> str:
        token = hmac.new(
            self._secret, _stable_json(payload), hashlib.sha256
        ).hexdigest()
        self._handles.pop(token, None)
        while len(self._handles) >= self._max_handles:
            del self._handles[next(iter(self._handles))]
        self._handles[token] = payload
        return token

    def _resolve_handle(self, handle: str | None, project: str) -> dict[str, Any]:
        payload = self._handles.get(str(handle or ""))
        if payload is None:
            raise PermissionError("progressive retrieval handle is invalid or expired")
        expected = hmac.new(
            self._secret, _stable_json(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, str(handle)):
            raise PermissionError("progressive retrieval handle failed validation")
        if payload["project"] != project:
            raise PermissionError(
                "progressive retrieval handle belongs to another project"
            )
        return payload

    def _timeline_identity(
        self, conn, project: str, privacy_ceiling: str
    ) -> str:
        checkpoint = (
            None
            if privacy_ceiling == "public"
            else latest_checkpoint(conn, project)
        )
        checkpoint_identity = None
        if checkpoint is not None:
            checkpoint_identity = {
                "id": int(checkpoint["id"]),
                "version": int(checkpoint["version"]),
                "digest": _bounded_digest(checkpoint),
            }
        event_head = conn.execute(
            """
            SELECT e.project_sequence, e.event_id, e.event_hash,
                   (SELECT COUNT(*) FROM truth_events counted
                    WHERE counted.project_id = p.id
                      AND CASE LOWER(counted.privacy_class)
                            WHEN 'public' THEN 0
                            WHEN 'internal' THEN 1
                            WHEN 'sensitive' THEN 2
                            WHEN 'restricted' THEN 3
                            ELSE 4
                          END <= ?) AS event_count
            FROM projects p
            LEFT JOIN truth_events e
              ON e.project_id = p.id
              AND e.project_sequence = (
                  SELECT MAX(latest.project_sequence) FROM truth_events latest
                  WHERE latest.project_id = p.id
                    AND CASE LOWER(latest.privacy_class)
                          WHEN 'public' THEN 0
                          WHEN 'internal' THEN 1
                          WHEN 'sensitive' THEN 2
                          WHEN 'restricted' THEN 3
                          ELSE 4
                        END <= ?
             )
            WHERE p.name = ?
            """,
            (
                _privacy_rank(privacy_ceiling),
                _privacy_rank(privacy_ceiling),
                project,
            ),
        ).fetchone()
        stream_identity = None
        if event_head is not None and event_head["project_sequence"] is not None:
            stream_identity = {
                "event_count": int(event_head["event_count"]),
                "project_sequence": int(event_head["project_sequence"]),
                "event_id": str(event_head["event_id"]),
                "event_hash": str(event_head["event_hash"]),
            }
        return _bounded_digest(
            {
                "checkpoint": checkpoint_identity,
                "event_stream": stream_identity,
            }
        )

    def retrieve(
        self,
        conn,
        *,
        project: str,
        stage: str,
        query: str | None = None,
        expansion_handle: str | None = None,
        limit: int = 8,
        max_tokens: int = 4_000,
        privacy_ceiling: str = "internal",
    ) -> dict[str, Any]:
        """Return index, timeline, or evidence without silently widening scope."""

        selected_stage = str(stage).casefold()
        if selected_stage not in STAGES:
            raise ValueError(
                "progressive retrieval stage must be index, timeline, or evidence"
            )
        limit = max(1, min(50, int(limit)))
        max_tokens = max(64, min(100_000, int(max_tokens)))
        selected_privacy_ceiling = str(privacy_ceiling).casefold()
        if selected_privacy_ceiling not in PRIVACY_RANKS:
            raise ValueError("progressive retrieval privacy ceiling is invalid")
        privacy_ceiling = selected_privacy_ceiling
        content_truncated = False
        if selected_stage == "index":
            selected_query = str(query or "").strip()
            if not selected_query:
                raise ValueError("index retrieval requires a query")
            if len(selected_query) > MAX_QUERY_CHARS:
                raise ValueError("progressive retrieval query exceeds the size limit")
            result, descriptors, references, filtered = self._select(
                conn,
                project=project,
                query=selected_query,
                limit=limit,
                privacy_ceiling=privacy_ceiling,
            )
            snapshot_digest = _digest(descriptors)
            handle_payload = {
                "project": project,
                "query": selected_query,
                "limit": limit,
                "privacy_ceiling": privacy_ceiling,
                "snapshot_digest": snapshot_digest,
                "timeline_identity": self._timeline_identity(
                    conn, project, privacy_ceiling
                ),
            }
            handle = self._issue_handle(handle_payload)
            items = [_public_descriptor(descriptor) for descriptor in descriptors]
        else:
            handle_payload = self._resolve_handle(expansion_handle, project)
            if (
                selected_stage == "timeline"
                and self._timeline_identity(
                    conn,
                    project,
                    str(handle_payload["privacy_ceiling"]),
                )
                != handle_payload["timeline_identity"]
            ):
                raise PermissionError("progressive retrieval handle snapshot is stale")
            result, descriptors, references, filtered = self._select(
                conn,
                project=project,
                query=handle_payload["query"],
                limit=int(handle_payload["limit"]),
                privacy_ceiling=str(handle_payload["privacy_ceiling"]),
            )
            if _digest(descriptors) != handle_payload["snapshot_digest"]:
                raise PermissionError("progressive retrieval handle snapshot is stale")
            if PRIVACY_RANKS[privacy_ceiling] < PRIVACY_RANKS[str(handle_payload["privacy_ceiling"])]:
                result, descriptors, references, filtered = self._select(
                    conn,
                    project=project,
                    query=handle_payload["query"],
                    limit=int(handle_payload["limit"]),
                    privacy_ceiling=privacy_ceiling,
                )
            snapshot_digest = _digest(descriptors)
            handle = str(expansion_handle)
            if selected_stage == "timeline":
                checkpoint = (
                    None
                    if privacy_ceiling == "public"
                    else latest_checkpoint(conn, project)
                )
                items = (
                    [
                        {
                            "kind": "checkpoint",
                            "version": checkpoint.get("version"),
                        }
                    ]
                    if checkpoint
                    else []
                )
                items.extend(
                    _public_descriptor(descriptor)
                    for descriptor in descriptors
                    if descriptor["kind"] == "truth"
                )
            else:
                by_memory = {
                    int(item["id"]): item for item in result.get("memories", [])
                }
                by_chunk = {int(item["id"]): item for item in result.get("chunks", [])}
                by_truth = {
                    str(item.get("claim_id") or ""): item
                    for item in result.get("truth", [])
                }
                items = []
                remaining_chars = max_tokens * 4
                for descriptor in descriptors:
                    public_descriptor = _public_descriptor(descriptor)
                    source = (
                        by_memory.get(descriptor["id"])
                        if descriptor["kind"] == "memory"
                        else by_chunk.get(descriptor["id"])
                        if descriptor["kind"] == "chunk"
                        else by_truth.get(descriptor["id"])
                    )
                    if source is None:
                        continue
                    text = str(
                        source.get("text")
                        if descriptor["kind"] != "truth"
                        else source.get("object") or source.get("value") or ""
                    )
                    if remaining_chars <= 0:
                        break
                    excerpt = text[:remaining_chars]
                    item_references = references.get(
                        (str(descriptor["kind"]), str(descriptor["id"])), []
                    )
                    items.append(
                        {
                            **public_descriptor,
                            "excerpt": excerpt,
                            "provenance_refs": item_references,
                        }
                    )
                    remaining_chars -= len(excerpt)
                budget_bytes = max_tokens * 4
                while items and len(_stable_json(items)) > budget_bytes:
                    last = items[-1]
                    excerpt = str(last.get("excerpt") or "")
                    if not excerpt:
                        items.pop()
                        content_truncated = True
                        continue
                    excess = len(_stable_json(items)) - budget_bytes
                    keep = max(0, len(excerpt) - max(1, excess))
                    last["excerpt"] = excerpt[:keep]
                    content_truncated = True
        items, budget_truncated = _fit_items_to_budget(items, max_tokens)
        content_truncated = content_truncated or budget_truncated
        token_estimate = _token_estimate(items)
        omitted = max(0, len(descriptors) - len(items))
        reported_privacy_filtered = (
            min(1, filtered) if privacy_ceiling == "public" else filtered
        )
        return {
            "status": "ok",
            "schema": RETRIEVAL_SCHEMA,
            "stage": selected_stage,
            "privacy_ceiling": privacy_ceiling,
            "snapshot_digest": snapshot_digest,
            "expansion_handle": handle,
            "items": items,
            "report": {
                "token_estimate": token_estimate,
                "included_count": len(items),
                "omitted_count": omitted,
                "truncated": omitted > 0 or content_truncated,
                "privacy_filtered_count": reported_privacy_filtered,
                "privacy_filtered_count_semantics": (
                    "presence-only" if privacy_ceiling == "public" else "exact"
                ),
                "authority_reported": True,
                "freshness_reported": True,
                "temporal_validity_reported": selected_stage != "index",
                "contradictions_reported": selected_stage != "index",
                "provenance_reported": selected_stage == "evidence",
                "abstention": "no_matching_evidence" if not descriptors else None,
            },
        }
