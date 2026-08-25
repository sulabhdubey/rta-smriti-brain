"""Normalized, privacy-aware inputs for deterministic context compilation."""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import unicodedata
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .agent_profiles import (
    PRIVACY_LEVELS,
    builtin_agent_profile,
    validate_agent_profile,
)
from .capture import _read_capture_replay_snapshot
from .ingest import chunk_text, read_text, sha256_text
from .privacy import find_sensitive_text

CONTEXT_CANDIDATE_SCHEMA_VERSION = "rta-smriti.context-candidate/v1"
MAX_MINIMUM_EXCERPT_BYTES = 8 * 1024
MAX_EXPANDED_EXCERPT_BYTES = 32 * 1024
MAX_PROVENANCE_ITEMS = 32
MAX_PRIVACY_SCAN_CHARS = 1_000_000
PRIVACY_SCAN_CHUNK_CHARS = 100_000
MAX_ADAPTER_ROWS = 200_000
MAX_ADAPTER_BYTES = 256 * 1024 * 1024
MAX_CAPTURE_CONTEXT_EVENTS = 64
MAX_CAPTURE_CONTEXT_BYTES = 128 * 1024
SIGNAL_NAMES = (
    "lexical", "semantic", "graph", "temporal", "risk", "outcome", "continuation",
)
_CANDIDATE_AUTHORITY_SECRET = secrets.token_bytes(32)
FINAL_DISPOSITIONS = frozenset({
    "included_mandatory", "included_ranked", "excluded_privacy", "excluded_scope",
    "excluded_stale_or_invalid", "excluded_duplicate",
    "excluded_low_marginal_utility", "excluded_budget",
    "excluded_profile_incompatible", "summarized_dependency", "redacted",
})
ADAPTER_HARD_DISPOSITIONS = frozenset(
    disposition
    for disposition in FINAL_DISPOSITIONS
    if disposition.startswith("excluded_") or disposition == "redacted"
)
_NORMALIZED_FIELDS = (
    "schema_version", "candidate_id", "source_id", "source_version", "project",
    "source_type", "source_location", "content_hash", "content_ref", "token_cost",
    "renderings", "valid_from", "valid_to", "recorded_sequence", "freshness",
    "authority_class", "epistemic_state", "verification_status", "privacy_class",
    "signals", "contradiction_group", "duplicate_group", "dependency_group",
    "minimum_excerpt", "expanded_excerpt", "provenance_chain", "validator_state",
    "hard_disposition", "hard_reason",
)
_RAW_FIELDS = frozenset({
    "project", "source_type", "source_id", "source_version", "source_location",
    "content", "content_hash", "valid_from", "valid_to", "recorded_sequence",
    "freshness", "authority_class", "epistemic_state", "verification_status",
    "privacy_class", "signals", "contradiction_group", "duplicate_group",
    "dependency_group", "provenance_chain", "validator_state",
    "hard_disposition", "hard_reason",
})


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()


def _instant(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("candidate temporal boundaries require a timezone")
    return parsed.astimezone(UTC)


def _row_is_valid_at(row: sqlite3.Row, boundary: datetime | None) -> bool:
    if boundary is None:
        return True
    try:
        valid_from = _instant(str(row["valid_from"]))
        valid_to = (
            None if row["valid_to"] is None else _instant(str(row["valid_to"]))
        )
    except (TypeError, ValueError):
        return False
    return valid_from <= boundary and (valid_to is None or boundary < valid_to)


class _AggregateBudget:
    __slots__ = ("bytes", "rows")

    def __init__(self) -> None:
        self.rows = 0
        self.bytes = 0

    def consume(self, row: Any, *, label: str, count_row: bool = True) -> None:
        if count_row:
            self.rows += 1
            if self.rows > MAX_ADAPTER_ROWS:
                raise ValueError("candidate adaptation exceeds the aggregate row limit")
        for value in row:
            if isinstance(value, bytes):
                self.bytes += len(value)
            elif value is not None:
                self.bytes += len(str(value).encode("utf-8", errors="replace"))
        if self.bytes > MAX_ADAPTER_BYTES:
            raise ValueError(f"{label} exceeds the aggregate adapter byte limit")


def _bounded_rows(cursor, *, label: str, budget: _AggregateBudget) -> list[Any]:
    rows = []
    for row in cursor:
        budget.consume(row, label=label)
        rows.append(row)
    return rows


def _warning(source_id: Any, reason: str) -> dict[str, str]:
    return {
        "source_ref": f"warning:{_sha256(str(source_id))}",
        "reason": reason,
    }


def _logical_source_id(source_type: str, *parts: Any, opaque: bool = False) -> str:
    logical = ":".join(str(part) for part in parts)
    candidate = f"{source_type}:{logical}"
    if opaque or "\x00" in candidate or len(candidate) > 512:
        return f"{source_type}:{_sha256(_canonical_json(parts))}"
    return candidate


def _text(value: Any, name: str, *, maximum: int, required: bool = False) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    normalized = unicodedata.normalize(
        "NFC", value.replace("\r\n", "\n").replace("\r", "\n")
    ).strip()
    if "\x00" in normalized:
        raise ValueError(f"{name} must not contain NUL characters")
    if required and not normalized:
        raise ValueError(f"{name} is required")
    if len(normalized) > maximum:
        raise ValueError(f"{name} exceeds {maximum:,} characters")
    return normalized


def _nullable_text(value: Any, name: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    return _text(value, name, maximum=maximum)


def _bounded_utf8(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    encoded = value.encode("utf-8", errors="strict")
    if len(encoded) <= limit:
        return value
    marker = b"\n[TRUNCATED]"
    selected = encoded[: max(0, limit - len(marker))]
    while selected:
        try:
            return selected.decode("utf-8", errors="strict") + marker.decode("ascii")
        except UnicodeDecodeError:
            selected = selected[:-1]
    return marker.decode("ascii")


def _token_cost(value: str | None) -> int:
    if not value:
        return 0
    return max(1, math.ceil(len(value.encode("utf-8", errors="strict")) / 4))


def _privacy(value: Any) -> str:
    selected = _text(value, "privacy_class", maximum=32, required=True).lower()
    if selected not in PRIVACY_LEVELS:
        raise ValueError("privacy_class is invalid")
    return selected


def _signals(value: Any) -> dict[str, float]:
    supplied = {} if value is None else value
    if not isinstance(supplied, dict):
        raise TypeError("signals must be an object")
    unknown = sorted(set(supplied) - set(SIGNAL_NAMES))
    if unknown:
        raise ValueError(f"unknown signal: {unknown[0]}")
    normalized = {}
    for name in SIGNAL_NAMES:
        score = supplied.get(name, 0.0)
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise TypeError(f"signals.{name} must be numeric")
        score = float(score)
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError(f"signals.{name} must be between 0 and 1")
        normalized[name] = score
    return normalized


def _provenance(value: Any) -> list[dict[str, Any]]:
    rows = [] if value is None else value
    if not isinstance(rows, list):
        raise TypeError("provenance_chain must be a list")
    if len(rows) > MAX_PROVENANCE_ITEMS:
        raise ValueError(f"provenance_chain exceeds {MAX_PROVENANCE_ITEMS} items")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise TypeError("provenance_chain items must be objects")
        canonical = _canonical_json(row)
        if len(canonical.encode("utf-8")) > 4096:
            raise ValueError("provenance_chain item exceeds 4 KiB")
        result.append(json.loads(canonical))
    return result


def _candidate_identity(candidate: dict[str, Any]) -> str:
    """Bind every normalized field except the self-referential candidate ID."""
    payload = {
        field: candidate[field]
        for field in _NORMALIZED_FIELDS
        if field != "candidate_id"
    }
    return f"cand-{_sha256(_canonical_json(payload))}"


class CandidateAuthority:
    """Host-owned, out-of-band receipts for one candidate compilation batch."""

    __slots__ = ("__receipts", "__redaction_key", "__sealed")

    def __init__(self, binding_digest: str) -> None:
        if (
            not isinstance(binding_digest, str)
            or len(binding_digest) != 64
            or any(character not in "0123456789abcdef" for character in binding_digest.lower())
        ):
            raise ValueError("candidate authority requires a SHA-256 binding digest")
        self.__receipts: dict[str, str] = {}
        self.__redaction_key = hmac.new(
            _CANDIDATE_AUTHORITY_SECRET,
            bytes.fromhex(binding_digest),
            hashlib.sha256,
        ).digest()
        self.__sealed = False

    def issue(self, candidates: Iterable[dict[str, Any]]) -> None:
        """Register normalized adapter output before it crosses an untrusted boundary."""
        if self.__sealed:
            raise ValueError("candidate authority batch is already sealed")
        receipts = {}
        for candidate in candidates:
            _verify_normalized_candidate(candidate)
            candidate_id = candidate["candidate_id"]
            if candidate_id in receipts:
                raise ValueError("candidate authority batch contains duplicate IDs")
            receipts[candidate_id] = _sha256(_canonical_json(candidate))
        self.__receipts = receipts
        self.__sealed = True

    def verify(self, candidate: dict[str, Any]) -> None:
        if not self.__sealed:
            raise ValueError("candidate authority batch is not sealed")
        expected = self.__receipts.get(candidate["candidate_id"])
        if expected is None or expected != _sha256(_canonical_json(candidate)):
            raise ValueError("candidate authority receipt is missing or invalid")

    def redaction_tokens(
        self, candidate: dict[str, Any], disposition: str,
    ) -> tuple[str, str, str]:
        payload = _canonical_json({
            "candidate": candidate,
            "disposition": disposition,
        }).encode("utf-8")
        return tuple(
            hmac.new(
                self.__redaction_key,
                payload + label.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            for label in ("source", "version", "content")
        )


def _privacy_findings(*values: Any):
    findings = []
    for value in values:
        if value is None:
            continue
        text = value if isinstance(value, str) else _canonical_json(value)
        text = text[:MAX_PRIVACY_SCAN_CHARS]
        start = 0
        while start < len(text):
            end = min(len(text), start + PRIVACY_SCAN_CHUNK_CHARS)
            findings.extend(find_sensitive_text(text[start:end]))
            if end == len(text):
                break
            start = max(start + 1, end - 512)
    return findings


def _effective_privacy(metadata: dict[str, Any], *values: Any) -> str:
    """Apply declared privacy plus complete bounded field scanning."""
    declared = _privacy_from_metadata(metadata)
    findings = _privacy_findings(*values)
    path_labels = {
        "windows-user-path", "posix-user-path", "unc-path",
        "windows-absolute-path", "posix-absolute-path",
    }
    if any(finding.label not in path_labels for finding in findings):
        detected = "restricted"
    elif findings:
        detected = "sensitive"
    else:
        detected = "public"
    return PRIVACY_LEVELS[
        max(PRIVACY_LEVELS.index(declared), PRIVACY_LEVELS.index(detected))
    ]


def normalize_candidate(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize one source item without trusting source-supplied identity fields."""
    if not isinstance(payload, dict):
        raise TypeError("candidate must be an object")
    unknown = sorted(set(payload) - _RAW_FIELDS)
    if unknown:
        raise ValueError(f"unknown candidate field: {unknown[0]}")
    project = _text(payload.get("project"), "project", maximum=200, required=True)
    source_type = _text(
        payload.get("source_type"), "source_type", maximum=128, required=True,
    ).lower()
    source_id = _text(payload.get("source_id"), "source_id", maximum=512, required=True)
    source_version = _text(
        payload.get("source_version"), "source_version", maximum=1024, required=True,
    )
    source_location = _nullable_text(
        payload.get("source_location"), "source_location", maximum=2048,
    )
    content = payload.get("content")
    if content is not None:
        content = _text(content, "content", maximum=1_000_000)
        content_hash = _sha256(content)
    else:
        supplied_hash = payload.get("content_hash")
        if not isinstance(supplied_hash, str) or not supplied_hash:
            supplied_hash = _sha256(
                _canonical_json({
                    "project": project,
                    "source_id": source_id,
                    "source_version": source_version,
                    "state": "content-unavailable",
                })
            )
        content_hash = supplied_hash.lower()
        if not all(character in "0123456789abcdef" for character in content_hash) or len(content_hash) != 64:
            content_hash = _sha256(content_hash)
    minimum_excerpt = _bounded_utf8(content, MAX_MINIMUM_EXCERPT_BYTES)
    expanded_excerpt = _bounded_utf8(content, MAX_EXPANDED_EXCERPT_BYTES)
    hard_disposition = payload.get("hard_disposition")
    if hard_disposition is not None:
        hard_disposition = _text(
            hard_disposition, "hard_disposition", maximum=64, required=True,
        )
        if hard_disposition not in ADAPTER_HARD_DISPOSITIONS:
            raise ValueError("hard_disposition is invalid")
    validator_state = payload.get("validator_state", {"status": "not_configured"})
    if not isinstance(validator_state, dict):
        raise TypeError("validator_state must be an object")
    validator_state = json.loads(_canonical_json(validator_state))
    if len(_canonical_json(validator_state).encode("utf-8")) > 4096:
        raise ValueError("validator_state exceeds 4 KiB")
    renderings = {} if content is None else {
        "inline_text": minimum_excerpt,
        "expanded_text": expanded_excerpt,
    }
    provenance_chain = _provenance(payload.get("provenance_chain"))
    hard_reason = _nullable_text(payload.get("hard_reason"), "hard_reason", maximum=1024)
    normalized_signals = _signals(payload.get("signals"))
    privacy_class = _effective_privacy(
        {"privacy_class": payload.get("privacy_class", "internal")},
        project,
        source_type,
        source_id,
        source_version,
        content,
        source_location,
        payload.get("valid_from"),
        payload.get("valid_to"),
        payload.get("freshness", "current"),
        payload.get("authority_class", "unverified_source"),
        payload.get("epistemic_state", "observed"),
        payload.get("verification_status", "unverified"),
        normalized_signals,
        payload.get("contradiction_group"),
        payload.get("duplicate_group"),
        payload.get("dependency_group"),
        provenance_chain,
        validator_state,
        hard_disposition,
        hard_reason,
    )
    recorded_sequence = payload.get("recorded_sequence")
    if recorded_sequence is not None and (
        isinstance(recorded_sequence, bool)
        or not isinstance(recorded_sequence, int)
        or recorded_sequence < 0
    ):
        raise ValueError("recorded_sequence must be a non-negative integer or null")
    result = {
        "schema_version": CONTEXT_CANDIDATE_SCHEMA_VERSION,
        "candidate_id": "",
        "source_id": source_id,
        "source_version": source_version,
        "project": project,
        "source_type": source_type,
        "source_location": source_location,
        "content_hash": content_hash,
        "content_ref": f"sha256:{content_hash}",
        "token_cost": _token_cost(expanded_excerpt),
        "renderings": renderings,
        "valid_from": _nullable_text(payload.get("valid_from"), "valid_from", maximum=64),
        "valid_to": _nullable_text(payload.get("valid_to"), "valid_to", maximum=64),
        "recorded_sequence": recorded_sequence,
        "freshness": _text(
            payload.get("freshness", "current"), "freshness", maximum=64, required=True,
        ),
        "authority_class": _text(
            payload.get("authority_class", "unverified_source"),
            "authority_class", maximum=128, required=True,
        ),
        "epistemic_state": _text(
            payload.get("epistemic_state", "observed"),
            "epistemic_state", maximum=64, required=True,
        ),
        "verification_status": _text(
            payload.get("verification_status", "unverified"),
            "verification_status", maximum=64, required=True,
        ),
        "privacy_class": privacy_class,
        "signals": normalized_signals,
        "contradiction_group": _nullable_text(
            payload.get("contradiction_group"), "contradiction_group", maximum=512,
        ),
        "duplicate_group": _nullable_text(
            payload.get("duplicate_group"), "duplicate_group", maximum=512,
        ),
        "dependency_group": _nullable_text(
            payload.get("dependency_group"), "dependency_group", maximum=512,
        ),
        "minimum_excerpt": minimum_excerpt,
        "expanded_excerpt": expanded_excerpt,
        "provenance_chain": provenance_chain,
        "validator_state": validator_state,
        "hard_disposition": hard_disposition,
        "hard_reason": hard_reason,
    }
    result["candidate_id"] = _candidate_identity(result)
    return result


def _safe_json(value: Any) -> tuple[Any | None, str | None]:
    try:
        parsed = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError):
        return None, "malformed_json"
    if not isinstance(parsed, dict):
        return None, "metadata_not_object"
    return parsed, None


def _privacy_from_metadata(metadata: dict[str, Any]) -> str:
    return _privacy(metadata.get("privacy_class", "internal"))


def _invalid_candidate(
    *, project: str, source_type: str, source_id: str, source_version: str,
    source_location: str | None, reason: str,
) -> dict[str, Any]:
    safe_type = str(source_type or "invalid").strip().lower()
    if not safe_type or "\x00" in safe_type or len(safe_type) > 128:
        safe_type = "invalid"
    safe_source_id = _logical_source_id(safe_type, source_id, opaque=True)
    return normalize_candidate({
        "project": project,
        "source_type": safe_type,
        "source_id": safe_source_id,
        "source_version": _sha256(str(source_version)),
        "source_location": None,
        "content_hash": _sha256(f"invalid\0{source_type}\0{source_id}\0{source_version}"),
        "privacy_class": "restricted",
        "freshness": "invalid",
        "authority_class": "unverified_source",
        "epistemic_state": "stale",
        "verification_status": "failed",
        "validator_state": {"status": "invalid", "reason": reason},
        "hard_disposition": "excluded_stale_or_invalid",
        "hard_reason": "source metadata is invalid",
    })


def _project_row(conn, project: str):
    row = conn.execute(
        "SELECT id, name, root_path, repository_identity, checkout_identity FROM projects WHERE name = ?",
        (project,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown project: {project}")
    return row


def _checkpoint_candidates(
    conn, project: str, project_id: int, budget: _AggregateBudget,
):
    row = conn.execute(
        """
        SELECT * FROM checkpoints WHERE project_id = ?
        ORDER BY version DESC, updated_at DESC, id DESC LIMIT 1
        """,
        (project_id,),
    ).fetchone()
    if row is None:
        return []
    budget.consume(row, label="checkpoint candidate")
    content = "\n".join(
        f"{label}: {row[field]}"
        for field, label in (
            ("objective", "Objective"), ("verified_evidence", "Verified evidence"),
            ("remaining_gaps", "Remaining gaps"), ("next_action", "Next action"),
            ("prohibited_repetition", "Do not repeat"),
        )
        if row[field]
    )
    if row["source"] == "operator":
        authority_class = "operator_checkpoint"
        epistemic_state = "accepted"
        verification_status = "verified"
    elif row["source"] == "system":
        authority_class = "system_checkpoint"
        epistemic_state = "accepted"
        verification_status = "verified"
    elif row["source"] == "agent":
        authority_class = "agent_checkpoint"
        epistemic_state = "observed"
        verification_status = "unverified"
    else:
        authority_class = "unverified_checkpoint"
        epistemic_state = "observed"
        verification_status = "unverified"
    return [normalize_candidate({
        "project": project,
        "source_type": "checkpoint",
        "source_id": "checkpoint:current",
        "source_version": _sha256(_canonical_json({
            "version": row["version"], "updated_at": row["updated_at"],
            "content": content, "source": row["source"], "trigger": row["trigger"],
        })),
        "source_location": f"checkpoint://{row['id']}",
        "content": content,
        "valid_from": row["updated_at"],
        "authority_class": authority_class,
        "epistemic_state": epistemic_state,
        "verification_status": verification_status,
        "privacy_class": _effective_privacy(
            {"privacy_class": "internal"}, content, row["source"], row["trigger"],
        ),
        "signals": {"continuation": 1.0, "risk": 0.8},
        "dependency_group": "control-plane",
        "provenance_chain": [{"checkpoint_id": row["id"], "source": row["source"]}],
    })]


def _truth_contradiction_groups(
    conn: sqlite3.Connection,
    project_id: int,
    claim_ids: set[str],
    budget: _AggregateBudget,
    *,
    valid_at: datetime | None,
    recorded_sequence: int | None,
) -> tuple[dict[str, str], dict[str, list[str]]]:
    if recorded_sequence is None:
        relation_cursor = conn.execute(
            """
            SELECT relation_id, from_claim_id, to_claim_id, authority_class,
                   confidence, valid_from, valid_to,
                   recorded_from_sequence, recorded_to_sequence
            FROM truth_relations
            WHERE project_id = ? AND relation_type = 'contradicts'
              AND recorded_to_sequence IS NULL
            ORDER BY relation_id, recorded_from_sequence
            """,
            (project_id,),
        )
    else:
        relation_cursor = conn.execute(
            """
            SELECT relation_id, from_claim_id, to_claim_id, authority_class,
                   confidence, valid_from, valid_to,
                   recorded_from_sequence, recorded_to_sequence
            FROM truth_relations
            WHERE project_id = ? AND relation_type = 'contradicts'
              AND recorded_from_sequence <= ?
              AND (recorded_to_sequence IS NULL OR recorded_to_sequence > ?)
            ORDER BY relation_id, recorded_from_sequence
            """,
            (project_id, recorded_sequence, recorded_sequence),
        )
    rows = [
        row
        for row in _bounded_rows(
            relation_cursor,
            label="truth contradiction relations",
            budget=budget,
        )
        if float(row["confidence"]) > 0.0 and _row_is_valid_at(row, valid_at)
    ]
    parent = {claim_id: claim_id for claim_id in claim_ids}
    relation_ids: dict[str, list[str]] = {claim_id: [] for claim_id in claim_ids}

    def find(claim_id: str) -> str:
        root = claim_id
        while parent[root] != root:
            root = parent[root]
        while parent[claim_id] != claim_id:
            next_id = parent[claim_id]
            parent[claim_id] = root
            claim_id = next_id
        return root

    def union(left: str, right: str) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root == right_root:
            return
        first, second = sorted((left_root, right_root))
        parent[second] = first

    accepted_relations = []
    for row in rows:
        left = str(row["from_claim_id"])
        right = str(row["to_claim_id"])
        if left not in parent or right not in parent:
            continue
        union(left, right)
        accepted_relations.append((str(row["relation_id"]), left, right))

    components: dict[str, list[str]] = {}
    for claim_id in sorted(parent):
        components.setdefault(find(claim_id), []).append(claim_id)
    groups = {}
    for members in components.values():
        if len(members) < 2:
            continue
        group = f"truth-contradiction:{_sha256(_canonical_json(members))}"
        for claim_id in members:
            groups[claim_id] = group
    for relation_id, left, right in accepted_relations:
        if left in groups and groups[left] == groups.get(right):
            relation_ids[left].append(relation_id)
            relation_ids[right].append(relation_id)
    return groups, {
        claim_id: sorted(set(ids))
        for claim_id, ids in relation_ids.items()
        if ids
    }


def _truth_candidates(
    conn,
    project: str,
    project_id: int,
    budget: _AggregateBudget,
    *,
    valid_at: datetime | None,
    recorded_sequence: int | None,
):
    if recorded_sequence is None:
        claim_cursor = conn.execute(
            """
            SELECT * FROM truth_claim_versions
            WHERE project_id = ? AND recorded_to_sequence IS NULL
            ORDER BY recorded_from_sequence, id
            """,
            (project_id,),
        )
    else:
        claim_cursor = conn.execute(
            """
            SELECT * FROM truth_claim_versions
            WHERE project_id = ? AND recorded_from_sequence <= ?
              AND (recorded_to_sequence IS NULL OR recorded_to_sequence > ?)
            ORDER BY recorded_from_sequence, id
            """,
            (project_id, recorded_sequence, recorded_sequence),
        )
    rows = [
        row
        for row in _bounded_rows(
            claim_cursor,
            label="truth candidates",
            budget=budget,
        )
        if _row_is_valid_at(row, valid_at)
    ]
    claim_ids = {str(row["claim_id"]) for row in rows}
    contradiction_groups, contradiction_relations = _truth_contradiction_groups(
        conn,
        project_id,
        claim_ids,
        budget,
        valid_at=valid_at,
        recorded_sequence=recorded_sequence,
    )
    candidates, warnings = [], []
    for row in rows:
        try:
            object_value = json.loads(row["object_json"])
            content = f"{row['subject_display']} {row['predicate']} {_canonical_json(object_value)}"
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "truth",
                "source_id": f"truth:{row['claim_id']}",
                "source_version": _sha256(_canonical_json({
                    "recorded_from_sequence": row["recorded_from_sequence"],
                    "subject_key": row["subject_key"], "predicate": row["predicate"],
                    "object_json": row["object_json"], "polarity": row["polarity"],
                    "epistemic_state": row["epistemic_state"],
                    "authority_class": row["authority_class"],
                    "verification_status": row["verification_status"],
                    "valid_from": row["valid_from"], "valid_to": row["valid_to"],
                    "privacy_class": row["privacy_class"],
                    "sharing_policy": row["sharing_policy"],
                    "provenance_json": row["provenance_json"],
                })),
                "source_location": f"truth://{row['claim_id']}",
                "content": content,
                "valid_from": row["valid_from"],
                "valid_to": row["valid_to"],
                "recorded_sequence": int(row["recorded_from_sequence"]),
                "authority_class": row["authority_class"],
                "epistemic_state": row["epistemic_state"],
                "verification_status": row["verification_status"],
                "privacy_class": _effective_privacy(
                    {"privacy_class": row["privacy_class"]}, content,
                ),
                "signals": {"temporal": 1.0, "risk": float(row["confidence"])},
                "contradiction_group": contradiction_groups.get(str(row["claim_id"])),
                "provenance_chain": [{
                    "event_id": row["opened_by_event_id"],
                    "contradiction_relation_ids": contradiction_relations.get(
                        str(row["claim_id"]), []
                    ),
                }],
            }))
        except (TypeError, ValueError, json.JSONDecodeError):
            source_id = f"truth:{row['claim_id']}"
            candidates.append(_invalid_candidate(
                project=project,
                source_type="truth",
                source_id=source_id,
                source_version=_sha256(
                    f"{row['recorded_from_sequence']}:{row['claim_id']}:invalid"
                ),
                source_location=f"truth://{row['claim_id']}",
                reason="malformed_truth_object",
            ))
            warnings.append(_warning(source_id, "malformed_truth_object"))
    return candidates, warnings


def _policy_candidates(conn, project: str, project_id: int, budget: _AggregateBudget):
    rows = _bounded_rows(conn.execute(
        "SELECT * FROM governance_policies WHERE project_id = ? AND status = 'active' ORDER BY id",
        (project_id,),
    ), label="policy candidates", budget=budget)
    candidates, warnings = [], []
    for row in rows:
        policy_identity = _sha256(_canonical_json({
            "kind": row["kind"], "statement": row["statement"],
            "action_contains": row["action_contains"], "path_glob": row["path_glob"],
            "required_check": row["required_check"],
        }))
        source_id = f"policy:{policy_identity}"
        provenance, error = _safe_json(row["provenance_json"])
        if error:
            candidates.append(_invalid_candidate(
                project=project, source_type="policy", source_id=source_id,
                source_version=_sha256(f"{policy_identity}:invalid"),
                source_location=f"policy://{policy_identity}", reason=error,
            ))
            warnings.append(_warning(source_id, error))
            continue
        content = "\n".join(filter(None, (
            row["statement"], f"Effect: {row['effect']}",
            f"Required check: {row['required_check']}" if row["required_check"] else None,
        )))
        candidates.append(normalize_candidate({
            "project": project,
            "source_type": "policy",
            "source_id": source_id,
            "source_version": _sha256(_canonical_json({
                "identity": policy_identity, "effect": row["effect"],
                "expires_at": row["expires_at"], "status": row["status"],
                "overrideable": row["overrideable"], "provenance": provenance,
                "pramana": row["pramana"], "confidence": row["confidence"],
            })),
            "source_location": f"policy://{policy_identity}",
            "content": content,
            "valid_from": row["created_at"],
            "valid_to": row["expires_at"],
            "authority_class": "governance_policy",
            "epistemic_state": "accepted",
            "verification_status": (
                "verified"
                if row["pramana"] in {"pratyaksha", "sabda"}
                and float(row["confidence"]) >= 0.75
                else "unverified"
            ),
            "privacy_class": _effective_privacy({"privacy_class": "internal"}, content),
            "signals": {"risk": 1.0},
            "dependency_group": "control-plane",
            "provenance_chain": [{"policy_digest": policy_identity, "pramana": row["pramana"]}],
        }))
    return candidates, warnings


def _memory_candidates(conn, project: str, project_id: int, budget: _AggregateBudget):
    rows = _bounded_rows(conn.execute(
        """
        SELECT m.*, mp.source_path, mp.source_hash, mp.command,
               mp.timestamp AS provenance_timestamp,
               mp.verification_status AS provenance_verification,
               mp.metadata_json AS provenance_metadata_json
        FROM memories m LEFT JOIN memory_provenance mp ON mp.memory_id = m.id
        WHERE m.project_id = ? AND m.status = 'active' ORDER BY m.id
        """,
        (project_id,),
    ), label="memory candidates", budget=budget)
    candidates, warnings = [], []
    for row in rows:
        metadata, error = _safe_json(row["metadata_json"])
        provenance_metadata, provenance_error = _safe_json(row["provenance_metadata_json"])
        memory_identity = _sha256(_canonical_json({
            "type": row["type"], "pramana": row["pramana"],
            "source_path": row["source_path"], "source_hash": row["source_hash"],
            "text": row["text"],
        }))
        source_id = f"memory:{memory_identity}"
        error = error or provenance_error
        if error:
            candidates.append(_invalid_candidate(
                project=project, source_type="memory", source_id=source_id,
                source_version=f"{row['updated_at']}:{_sha256(row['text'])}",
                source_location=f"memory://{memory_identity}", reason=error,
            ))
            warnings.append(_warning(source_id, error))
            continue
        try:
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "memory",
                "source_id": source_id,
                "source_version": f"{row['updated_at']}:{_sha256(row['text'])}:{row['source_hash'] or ''}",
                "source_location": row["source_path"] or f"memory://{memory_identity}",
                "content": row["text"],
                "valid_from": row["created_at"],
                "authority_class": f"memory:{row['pramana']}",
                "epistemic_state": "accepted" if row["pramana"] in {"pratyaksha", "sabda"} else "observed",
                "verification_status": row["provenance_verification"] or "unverified",
                "privacy_class": _effective_privacy(
                    metadata, row["text"], row["source_path"], row["command"],
                    provenance_metadata,
                ),
                "signals": {"continuation": min(1.0, float(row["priority"]) / 10.0)},
                "duplicate_group": f"memory-content:{_sha256(row['text'])}",
                "provenance_chain": [{
                    "memory_digest": memory_identity, "source_hash": row["source_hash"],
                    "command": row["command"], "timestamp": row["provenance_timestamp"],
                    "metadata": provenance_metadata,
                }],
            }))
        except (TypeError, ValueError):
            candidates.append(_invalid_candidate(
                project=project, source_type="memory", source_id=source_id,
                source_version=f"{row['updated_at']}:{_sha256(row['text'])}",
                source_location=f"memory://{memory_identity}", reason="invalid_memory_metadata",
            ))
            warnings.append(_warning(source_id, "invalid_memory_metadata"))
    return candidates, warnings


def _repository_candidates(
    conn, project: str, project_id: int, budget: _AggregateBudget,
    project_root: str | None,
):
    rows = _bounded_rows(conn.execute(
        """
        SELECT s.id AS source_db_id, s.kind, s.path, s.title, s.hash AS source_hash,
               s.metadata_json, s.updated_at, c.ordinal, c.text, c.hash AS chunk_hash
        FROM sources s JOIN chunks c ON c.source_id = s.id
        WHERE s.project_id = ? ORDER BY s.id, c.ordinal
        """,
        (project_id,),
    ), label="repository candidates", budget=budget)
    candidates, warnings = [], []
    verification_cache: dict[int, dict[str, Any]] = {}
    source_chunk_rows: dict[int, list[Any]] = {}
    for candidate_row in rows:
        source_chunk_rows.setdefault(int(candidate_row["source_db_id"]), []).append(candidate_row)
    remaining_hash_bytes = MAX_ADAPTER_BYTES

    def verify_source(row) -> dict[str, Any]:
        nonlocal remaining_hash_bytes
        source_db_id = int(row["source_db_id"])
        cached = verification_cache.get(source_db_id)
        if cached is not None:
            return cached
        if row["kind"] != "file":
            result = {
                "freshness": "current",
                "verification_status": "indexed_snapshot",
                "reason": None,
                "content_hash": None,
                "size": None,
            }
            verification_cache[source_db_id] = result
            return result
        try:
            root = Path(str(project_root or "")).expanduser().resolve(strict=True)
            requested = Path(str(row["path"] or "")).expanduser()
            path = requested if requested.is_absolute() else root / requested
            resolved = path.resolve(strict=True)
            if os.path.commonpath(
                [os.path.normcase(str(root)), os.path.normcase(str(resolved))]
            ) != os.path.normcase(str(root)):
                raise ValueError("repository source is outside the canonical root")
            before = path.stat()
            if before.st_size > remaining_hash_bytes:
                raise ValueError("live repository hash budget exceeded")
            text = read_text(path, max_bytes=int(before.st_size), root=root)
            if text is None:
                raise ValueError("repository source failed bounded live reading")
            remaining_hash_bytes -= int(before.st_size)
            live_hash = sha256_text(text)
            expected_hash = str(row["source_hash"] or "").casefold()
            if not hmac.compare_digest(live_hash, expected_hash):
                raise ValueError("repository source content differs from the index")
            live_chunks = chunk_text(text)
            stored_chunks = source_chunk_rows.get(source_db_id, [])
            if len(stored_chunks) != len(live_chunks):
                raise ValueError("repository chunks differ from the live source")
            for expected_ordinal, (stored, live_chunk) in enumerate(zip(stored_chunks, live_chunks, strict=True)):
                stored_text = str(stored["text"] or "")
                stored_hash = str(stored["chunk_hash"] or "").casefold()
                live_chunk_hash = sha256_text(live_chunk)
                if (
                    int(stored["ordinal"]) != expected_ordinal
                    or not hmac.compare_digest(stored_hash, sha256_text(stored_text))
                    or not hmac.compare_digest(stored_hash, live_chunk_hash)
                    or not hmac.compare_digest(stored_text, live_chunk)
                ):
                    raise ValueError("repository chunks differ from the live source")
            result = {
                "freshness": "current",
                "verification_status": "live_hash_verified",
                "reason": None,
                "content_hash": live_hash,
                "size": int(before.st_size),
            }
        except (OSError, ValueError):
            result = {
                "freshness": "stale",
                "verification_status": "failed",
                "reason": "live_repository_verification_failed",
                "content_hash": None,
                "size": None,
            }
        verification_cache[source_db_id] = result
        return result

    for row in rows:
        logical_path = str(row["path"] or row["title"] or "unlocated").replace("\\", "/")
        source_id = _logical_source_id(
            "repository", logical_path, row["ordinal"], opaque=True,
        )
        metadata, error = _safe_json(row["metadata_json"])
        source_version = _sha256(_canonical_json({
            "source_hash": row["source_hash"], "chunk_hash": row["chunk_hash"],
            "updated_at": row["updated_at"], "metadata_json": row["metadata_json"],
        }))
        if error:
            candidates.append(_invalid_candidate(
                project=project, source_type="repository", source_id=source_id,
                source_version=source_version, source_location=row["path"], reason=error,
            ))
            warnings.append(_warning(source_id, error))
            continue
        live = verify_source(row)
        if live["reason"] is not None:
            try:
                candidates.append(normalize_candidate({
                    "project": project,
                    "source_type": "repository",
                    "source_id": source_id,
                    "source_version": source_version,
                    "source_location": row["path"],
                    "content": None,
                    "valid_from": row["updated_at"],
                    "freshness": live["freshness"],
                    "authority_class": "indexed_repository",
                    "epistemic_state": "stale",
                    "verification_status": live["verification_status"],
                    "privacy_class": _effective_privacy(
                        metadata, row["text"], row["path"], row["title"],
                    ),
                    "validator_state": {
                        "status": "invalid",
                        "reason": live["reason"],
                    },
                    "hard_disposition": "excluded_stale_or_invalid",
                    "hard_reason": "repository source failed live verification",
                }))
            except (TypeError, ValueError):
                candidates.append(_invalid_candidate(
                    project=project,
                    source_type="repository",
                    source_id=source_id,
                    source_version=source_version,
                    source_location=row["path"],
                    reason="invalid_repository_metadata",
                ))
            warnings.append(_warning(source_id, live["reason"]))
            continue
        try:
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "repository",
                "source_id": source_id,
                "source_version": source_version,
                "source_location": row["path"],
                "content": row["text"],
                "valid_from": row["updated_at"],
                "freshness": live["freshness"],
                "authority_class": "indexed_repository",
                "epistemic_state": "observed",
                "verification_status": live["verification_status"],
                "privacy_class": _effective_privacy(
                    metadata, row["text"], row["path"], row["title"],
                ),
                "signals": {"lexical": 0.5, "graph": 0.25},
                "duplicate_group": f"content:{_sha256(row['text'])}",
                "dependency_group": f"source:{logical_path}",
                "provenance_chain": [{
                    "source_hash": row["source_hash"],
                    "chunk_hash": row["chunk_hash"], "ordinal": row["ordinal"],
                    "live_content_hash": live["content_hash"],
                    "live_size": live["size"],
                }],
            }))
        except (TypeError, ValueError):
            candidates.append(_invalid_candidate(
                project=project, source_type="repository", source_id=source_id,
                source_version=source_version, source_location=row["path"],
                reason="invalid_repository_metadata",
            ))
            warnings.append(_warning(source_id, "invalid_repository_metadata"))
    return candidates, warnings


def _graph_candidates(conn, project: str, project_id: int, budget: _AggregateBudget):
    rows = _bounded_rows(conn.execute(
        """
        SELECT e.id, e.relation, e.confidence, e.created_at, e.source_id, e.memory_id,
               f.project_id AS from_project_id,
               f.type AS from_type, f.name AS from_name, f.canonical_key AS from_key,
               t.project_id AS to_project_id,
               t.type AS to_type, t.name AS to_name, t.canonical_key AS to_key
        FROM edges e
        JOIN entities f ON f.id = e.from_entity_id
        JOIN entities t ON t.id = e.to_entity_id
        WHERE e.project_id = ? ORDER BY e.id
        """,
        (project_id,),
    ), label="graph candidates", budget=budget)
    candidates, warnings = [], []
    for row in rows:
        fallback_id = _logical_source_id("graph", row["id"])
        fallback_version = _sha256(f"graph-row:{row['id']}")
        if (
            int(row["from_project_id"]) != project_id
            or int(row["to_project_id"]) != project_id
        ):
            candidates.append(_invalid_candidate(
                project=project,
                source_type="graph",
                source_id=fallback_id,
                source_version=fallback_version,
                source_location=None,
                reason="cross_project_graph_edge",
            ))
            warnings.append(_warning(fallback_id, "cross_project_graph_edge"))
            continue
        try:
            source_identity = {
                "from": row["from_key"],
                "relation": row["relation"],
                "to": row["to_key"],
            }
            source_id = f"graph:{_sha256(_canonical_json(source_identity))}"
            source_version = _sha256(_canonical_json({
                "from": row["from_key"], "relation": row["relation"],
                "to": row["to_key"], "confidence": row["confidence"],
            }))
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "graph",
                "source_id": source_id,
                "source_version": source_version,
                "source_location": (
                    f"graph://{row['from_key']}/{row['relation']}/{row['to_key']}"
                ),
                "content": (
                    f"{row['from_type']} {row['from_name']} {row['relation']} "
                    f"{row['to_type']} {row['to_name']}"
                ),
                "valid_from": row["created_at"],
                "authority_class": "derived_graph",
                "epistemic_state": "observed",
                "verification_status": (
                    "verified" if float(row["confidence"]) >= 1.0 else "approximate"
                ),
                "privacy_class": _effective_privacy(
                    {}, row["from_name"], row["to_name"], row["from_key"], row["to_key"],
                ),
                "signals": {"graph": min(1.0, max(0.0, float(row["confidence"])))},
                "dependency_group": f"entity:{row['from_key']}",
                "provenance_chain": [
                    {"source_id": row["source_id"], "memory_id": row["memory_id"]},
                ],
            }))
        except (TypeError, ValueError):
            candidates.append(_invalid_candidate(
                project=project,
                source_type="graph",
                source_id=fallback_id,
                source_version=fallback_version,
                source_location=None,
                reason="invalid_graph_metadata",
            ))
            warnings.append(_warning(fallback_id, "invalid_graph_metadata"))
    return candidates, warnings


def _continuity_candidates(
    conn, project: str, project_id: int, budget: _AggregateBudget,
):
    table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_events'"
    ).fetchone()
    if table is None:
        return [], []
    rows = _bounded_rows(conn.execute(
        "SELECT * FROM session_events "
        "WHERE project_id = ? AND payload_json <> 'null' ORDER BY id",
        (project_id,),
    ), label="continuity candidates", budget=budget)
    candidates, warnings = [], []
    for row in rows:
        source_id = _logical_source_id(
            "continuity", row["session_id"], row["cursor"],
        )
        try:
            payload = json.loads(row["payload_json"])
            content = f"{row['event_type']}: {_canonical_json(payload)}"
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "continuity",
                "source_id": source_id,
                "source_version": f"{row['source_hash'] or _sha256(row['payload_json'])}:{row['recorded_at']}",
                "source_location": f"session://{row['session_id']}/{row['cursor']}",
                "content": content,
                "valid_from": row["occurred_at"],
                "authority_class": "session_event",
                "epistemic_state": "observed",
                "verification_status": row["verification_status"],
                "privacy_class": _effective_privacy({"privacy_class": "internal"}, content),
                "signals": {"continuation": 0.8, "temporal": 0.8},
                "dependency_group": f"session:{row['session_id']}",
                "provenance_chain": [{"source": row["source"], "event_id": row["id"]}],
            }))
        except (TypeError, ValueError, json.JSONDecodeError):
            candidates.append(_invalid_candidate(
                project=project, source_type="continuity", source_id=source_id,
                source_version=f"{row['id']}:{row['recorded_at']}",
                source_location=f"session://{row['session_id']}/{row['cursor']}",
                reason="malformed_event_payload",
            ))
            warnings.append(_warning(source_id, "malformed_event_payload"))
    work_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'work_items'"
    ).fetchone()
    if work_table is not None:
        work_rows = _bounded_rows(conn.execute(
            "SELECT * FROM work_items WHERE project_id = ? ORDER BY item_type, external_id",
            (project_id,),
        ), label="work-state candidates", budget=budget)
        for row in work_rows:
            source_id = _logical_source_id(
                "work-state", row["item_type"], row["external_id"],
            )
            metadata, error = _safe_json(row["metadata_json"])
            if error:
                candidates.append(_invalid_candidate(
                    project=project, source_type="work_state", source_id=source_id,
                    source_version=f"{row['updated_at']}:invalid",
                    source_location=f"work-item://{row['item_type']}/{row['external_id']}",
                    reason=error,
                ))
                warnings.append(_warning(source_id, error))
                continue
            content = _canonical_json({
                "item_type": row["item_type"],
                "external_id": row["external_id"],
                "qa_state": row["qa_state"],
                "decision": row["decision"],
                "attempt_count": row["attempt_count"],
                "fallback": row["fallback"],
                "next_action": row["next_action"],
                "metadata": metadata,
            })
            try:
                candidates.append(normalize_candidate({
                    "project": project,
                    "source_type": "work_state",
                    "source_id": source_id,
                    "source_version": _sha256(f"{row['updated_at']}:{content}"),
                    "source_location": f"work-item://{row['item_type']}/{row['external_id']}",
                    "content": content,
                    "valid_from": row["updated_at"],
                    "authority_class": "structured_work_state",
                    "epistemic_state": "observed",
                    "verification_status": "verified" if row["qa_state"] == "verified" else "unverified",
                    "privacy_class": _effective_privacy(
                        {"privacy_class": "internal"}, content,
                    ),
                    "signals": {"continuation": 0.9, "risk": 0.7},
                    "dependency_group": f"work-item:{row['item_type']}",
                    "provenance_chain": [{"updated_at": row["updated_at"]}],
                }))
            except (TypeError, ValueError):
                candidates.append(_invalid_candidate(
                    project=project, source_type="work_state", source_id=source_id,
                    source_version=f"{row['updated_at']}:invalid",
                    source_location=f"work-item://{row['item_type']}/{row['external_id']}",
                    reason="invalid_work_state",
                ))
                warnings.append(_warning(source_id, "invalid_work_state"))
    return candidates, warnings


def _capture_interruption_snapshot(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Summarize interruption state without crossing a privacy partition."""

    selected = list(events)
    sessions: dict[tuple[str, str], dict[str, bool]] = {}
    incomplete_spans: set[tuple[str, str, str]] = set()
    gap_events = 0
    for event in selected:
        key = (str(event["source_id"]), str(event["external_session_id"]))
        state = sessions.setdefault(key, {"interrupted": False, "active": False})
        name = str(event["event_name"])
        if name in {"session.started.v1", "session.resumed.v1"}:
            state["active"] = True
        elif name == "session.ended.v1":
            state["active"] = False
            state["interrupted"] = False
        elif name == "turn.interrupted.v1":
            state["interrupted"] = True
        elif name == "turn.completed.v1":
            state["interrupted"] = False
        if name == "capture.gap.v1" or event["gap_state"] == "detected":
            gap_events += 1
        span = event.get("span_id")
        if span and name.endswith(".started.v1"):
            incomplete_spans.add((*key, str(span)))
        elif span and name.endswith((".completed.v1", ".failed.v1")):
            incomplete_spans.discard((*key, str(span)))
    interrupted = [state for state in sessions.values() if state["interrupted"]]
    latest = selected[-1] if selected else None
    return {
        "status": "interrupted"
        if interrupted or incomplete_spans or gap_events
        else "clear",
        "interrupted_sessions": len(interrupted),
        "incomplete_spans": len(incomplete_spans),
        "gap_events": gap_events,
        "latest_sequence": None if latest is None else latest["project_sequence"],
        "latest_event_hash": None if latest is None else latest["event_hash"],
    }


def _capture_candidates(
    conn, project: str, project_id: int, budget: _AggregateBudget,
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, Any]]:
    """Adapt only the latest bounded activity after the accepted checkpoint."""

    tables = {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN "
            "('capture_events', 'capture_tombstones')"
        )
    }
    empty_coverage = {
        "accepted_checkpoint_id": None,
        "accepted_checkpoint_version": None,
        "fence_sequence": 0,
        "total_uncheckpointed_events": 0,
        "selected_events": 0,
        "truncated": False,
        "replay_digest": None,
        "gap_events": 0,
        "incomplete_spans": 0,
        "interrupted_sessions": 0,
    }
    if tables != {"capture_events", "capture_tombstones"}:
        return [], [], empty_coverage
    checkpoint = conn.execute(
        """
        SELECT c.id, c.version, c.updated_at, f.fence_sequence
        FROM checkpoints c
        LEFT JOIN checkpoint_capture_fences f ON f.checkpoint_id = c.id
        WHERE c.project_id = ? AND c.source IN ('operator', 'system')
        ORDER BY version DESC, updated_at DESC, id DESC LIMIT 1
        """,
        (project_id,),
    ).fetchone()
    if checkpoint is not None:
        budget.consume(checkpoint, label="capture checkpoint fence")
    fence_sequence = 0
    if checkpoint is not None:
        if checkpoint["fence_sequence"] is not None:
            fence_sequence = int(checkpoint["fence_sequence"])
        else:
            fence_row = conn.execute(
                """
                SELECT COALESCE(MAX(project_sequence), 0) AS sequence
                FROM capture_events
                WHERE project_id = ? AND recorded_at < ?
                """,
                (project_id, checkpoint["updated_at"]),
            ).fetchone()
            budget.consume(fence_row, label="legacy capture checkpoint sequence")
            fence_sequence = int(fence_row["sequence"])
    count_row = conn.execute(
        """
        SELECT COUNT(*) AS event_count, COALESCE(MAX(project_sequence), 0) AS last_sequence
        FROM capture_events WHERE project_id = ? AND project_sequence > ?
        """,
        (project_id, fence_sequence),
    ).fetchone()
    budget.consume(count_row, label="capture candidate coverage")
    total_events = int(count_row["event_count"])
    last_sequence = int(count_row["last_sequence"])
    if total_events == 0:
        return [], [], {
            **empty_coverage,
            "accepted_checkpoint_id": None if checkpoint is None else int(checkpoint["id"]),
            "accepted_checkpoint_version": (
                None if checkpoint is None else int(checkpoint["version"])
            ),
            "fence_sequence": fence_sequence,
        }
    selected_after = max(fence_sequence, last_sequence - MAX_CAPTURE_CONTEXT_EVENTS)
    # Candidate adaptation already runs inside the compiler's read snapshot.
    # Reuse that transaction so event content and tombstones cannot diverge.
    replay = _read_capture_replay_snapshot(
        conn,
        project=project,
        mode="chronological",
        after_sequence=selected_after,
        limit=MAX_CAPTURE_CONTEXT_EVENTS,
        privacy_ceiling="restricted",
        max_bytes=MAX_CAPTURE_CONTEXT_BYTES,
    )
    budget.consume(
        [_canonical_json(replay)], label="capture replay candidate", count_row=False,
    )
    grouped: dict[str, list[dict[str, Any]]] = {
        privacy: [] for privacy in PRIVACY_LEVELS
    }
    for event in replay["events"]:
        grouped[str(event["privacy_class"])].append(event)
    candidates = []
    warnings = []
    for privacy_class in PRIVACY_LEVELS:
        events = grouped[privacy_class]
        if not events:
            continue
        interruption_snapshot = _capture_interruption_snapshot(events)
        observations = []
        for event in reversed(events):
            observations.append({
                "sequence": event["project_sequence"],
                "event": event["event_name"],
                "occurred_at": event["occurred_at"],
                "attributes": event["attributes"],
                "content_state": event["content_state"],
                "gap_state": event["gap_state"],
                "repository_ref": event["repository_ref"],
                "repository_commit": event["repository_commit"],
            })
        content = _canonical_json({
            "kind": "uncheckpointed_capture_activity",
            "order": "reverse-chronological",
            "accepted_checkpoint": None if checkpoint is None else {
                "id": int(checkpoint["id"]),
                "version": int(checkpoint["version"]),
            },
            "events": observations,
            "interruption_snapshot": interruption_snapshot,
        })
        source_version = _sha256(_canonical_json({
            "fence_sequence": fence_sequence,
            "privacy_class": privacy_class,
            "event_hashes": [event["event_hash"] for event in events],
        }))
        source_id = _logical_source_id(
            "capture", "uncheckpointed", privacy_class, source_version,
        )
        try:
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "capture",
                "source_id": source_id,
                "source_version": source_version,
                "source_location": f"capture://continuation/{source_version}",
                "content": content,
                "valid_from": events[0]["recorded_at"],
                "authority_class": "capture_observation",
                "epistemic_state": "observed",
                "verification_status": "unverified",
                "privacy_class": _effective_privacy(
                    {"privacy_class": privacy_class}, content,
                ),
                "signals": {
                    "continuation": 1.0,
                    "temporal": 1.0,
                    "risk": 1.0 if (
                        interruption_snapshot["gap_events"]
                        or interruption_snapshot["incomplete_spans"]
                        or interruption_snapshot["interrupted_sessions"]
                    ) else 0.4,
                },
                "dependency_group": "capture-continuation",
                "provenance_chain": [{
                    "replay_digest": replay["replay_digest"],
                    "first_sequence": events[0]["project_sequence"],
                    "last_sequence": events[-1]["project_sequence"],
                    "event_count": len(events),
                    "journal_metadata_verified": True,
                    "observation_authority": "unverified",
                }],
                "validator_state": {
                    "status": "observed",
                    "executes_actions": False,
                    "content_deleted_events": sum(
                        event["content_state"] == "logically-deleted"
                        for event in events
                    ),
                },
            }))
        except (TypeError, ValueError, json.JSONDecodeError):
            candidates.append(_invalid_candidate(
                project=project, source_type="capture", source_id=source_id,
                source_version=source_version, source_location=None,
                reason="invalid_capture_candidate",
            ))
            warnings.append(_warning(source_id, "invalid_capture_candidate"))
    coverage = {
        "accepted_checkpoint_id": None if checkpoint is None else int(checkpoint["id"]),
        "accepted_checkpoint_version": (
            None if checkpoint is None else int(checkpoint["version"])
        ),
        "fence_sequence": fence_sequence,
        "total_uncheckpointed_events": total_events,
        "selected_events": len(replay["events"]),
        "truncated": total_events > len(replay["events"]) or not replay["complete"],
        "replay_digest": replay["replay_digest"],
        "gap_events": int(replay["coverage"]["gap_events"]),
        "incomplete_spans": int(replay["coverage"]["incomplete_spans"]),
        "interrupted_sessions": int(replay["coverage"]["interrupted_sessions"]),
    }
    return candidates, warnings, coverage


def _cognition_candidates(
    conn,
    project: str,
    root_path: str,
    budget: _AggregateBudget,
):
    """Expose unresolved cognition as bounded derived context, never as source truth."""
    from .cognition import cognition_snapshot

    snapshot = cognition_snapshot(
        conn,
        project=project,
        active_root=root_path,
        include_change_impact=False,
    )
    warnings = []
    payloads = [{
        "kind": "cognition_readiness",
        "state": snapshot["readiness"]["state"],
        "reasons": snapshot["readiness"]["reasons"],
        "conflicts": snapshot["project_twin"]["conflicts"],
        "coverage": snapshot["knowledge_coverage"]["summary"],
    }]
    payloads.extend({
        "kind": "decision_debt",
        **item,
    } for item in snapshot["decision_debt"]["items"])
    candidates = []
    for index, payload in enumerate(payloads):
        try:
            content = _canonical_json(payload)
            source_id = (
                "cognition:readiness"
                if index == 0
                else f"cognition:decision-debt:{payload['claim_id']}"
            )
            disputed = bool(
                payload.get("kind") == "decision_debt"
                or payload.get("state") == "operationally_not_ready"
            )
            risk = 1.0 if payload.get("severity") == "critical" else (
                0.8 if payload.get("severity") == "high" or disputed else 0.2
            )
            candidates.append(normalize_candidate({
                "project": project,
                "source_type": "cognition",
                "source_id": source_id,
                "source_version": snapshot["digest"],
                "source_location": f"cognition://{source_id.split(':', 1)[1]}",
                "content": content,
                "freshness": "current",
                "authority_class": "deterministic_projection",
                "epistemic_state": "disputed" if disputed else "observed",
                "verification_status": "derived",
                "privacy_class": "internal",
                "signals": {"risk": risk, "continuation": 1.0 if index == 0 else 0.7},
                "dependency_group": "cognition-readiness",
                "provenance_chain": [{
                    "snapshot_digest": snapshot["digest"],
                    "contract_version": snapshot["contract_version"],
                }],
            }))
        except (TypeError, ValueError, KeyError):
            source_id = f"cognition:invalid:{index}"
            candidates.append(_invalid_candidate(
                project=project, source_type="cognition", source_id=source_id,
                source_version=snapshot["digest"],
                source_location=f"cognition://invalid/{index}",
                reason="invalid_cognition_projection",
            ))
            warnings.append(_warning(source_id, "invalid_cognition_projection"))
    budget.consume(candidates, label="cognition candidates")
    return candidates, warnings


def adapt_context_candidates(
    conn,
    *,
    project: str,
    valid_at: str | None = None,
    recorded_sequence: int | None = None,
) -> dict[str, Any]:
    """Read every supported source family without mutating the brain database."""
    selected_project = _text(project, "project", maximum=200, required=True)
    selected_valid_at = None if valid_at is None else _instant(valid_at)
    if recorded_sequence is not None and (
        isinstance(recorded_sequence, bool)
        or not isinstance(recorded_sequence, int)
        or recorded_sequence < 0
    ):
        raise ValueError("recorded_sequence must be a non-negative integer or null")
    row = _project_row(conn, selected_project)
    project_id = int(row["id"])
    budget = _AggregateBudget()
    budget.consume(row, label="project candidate")
    candidates = []
    warnings = []
    candidates.extend(_checkpoint_candidates(conn, selected_project, project_id, budget))
    truth, truth_warnings = _truth_candidates(
        conn,
        selected_project,
        project_id,
        budget,
        valid_at=selected_valid_at,
        recorded_sequence=recorded_sequence,
    )
    candidates.extend(truth)
    warnings.extend(truth_warnings)
    policies, policy_warnings = _policy_candidates(conn, selected_project, project_id, budget)
    candidates.extend(policies)
    warnings.extend(policy_warnings)
    memories, memory_warnings = _memory_candidates(conn, selected_project, project_id, budget)
    candidates.extend(memories)
    warnings.extend(memory_warnings)
    repository, repository_warnings = _repository_candidates(
        conn, selected_project, project_id, budget, row["root_path"],
    )
    candidates.extend(repository)
    warnings.extend(repository_warnings)
    graph, graph_warnings = _graph_candidates(conn, selected_project, project_id, budget)
    candidates.extend(graph)
    warnings.extend(graph_warnings)
    continuity, continuity_warnings = _continuity_candidates(
        conn, selected_project, project_id, budget,
    )
    candidates.extend(continuity)
    warnings.extend(continuity_warnings)
    capture, capture_warnings, capture_coverage = _capture_candidates(
        conn, selected_project, project_id, budget,
    )
    candidates.extend(capture)
    warnings.extend(capture_warnings)
    cognition, cognition_warnings = _cognition_candidates(
        conn, selected_project, str(row["root_path"]), budget,
    )
    candidates.extend(cognition)
    warnings.extend(cognition_warnings)
    candidates.sort(key=lambda item: (item["source_type"], item["source_id"], item["candidate_id"]))
    warnings.sort(key=lambda item: (item["source_ref"], item["reason"]))
    budget.consume(
        [_canonical_json(candidates), _canonical_json(warnings)],
        label="normalized candidate output",
        count_row=False,
    )
    return {
        "status": "degraded" if warnings else "ok",
        "project": selected_project,
        "candidates": candidates,
        "warnings": warnings,
        "capture_coverage": capture_coverage,
    }


def candidate_is_mandatory(candidate: dict[str, Any]) -> bool:
    """Derive mandatory status from host-adapted control-plane source identity."""
    return (
        candidate.get("source_type") == "policy"
        and candidate.get("authority_class") == "governance_policy"
    ) or (
        candidate.get("source_type") == "checkpoint"
        and candidate.get("authority_class") in {"operator_checkpoint", "system_checkpoint"}
    )


def _redacted_exclusion(
    candidate: dict[str, Any], disposition: str, *, authority: CandidateAuthority,
) -> dict[str, Any]:
    source_token, version_token, content_token = authority.redaction_tokens(
        candidate, disposition,
    )
    return normalize_candidate({
        "project": "redacted",
        "source_type": "redacted",
        "source_id": f"redacted:{source_token}",
        "source_version": version_token,
        "content_hash": content_token,
        "freshness": "redacted",
        "authority_class": "redacted",
        "epistemic_state": "redacted",
        "verification_status": "redacted",
        "privacy_class": "restricted",
        "validator_state": {"status": "not_disclosed"},
        "hard_disposition": disposition,
        "hard_reason": "candidate was excluded before scoring",
    })


def _validate_profile_grants(
    profile: dict[str, Any], contract: dict[str, Any], *, profile_authority: str,
) -> None:
    selected = str(profile_authority or "").strip().lower()
    if selected not in {"operator", "host", "builtin"}:
        raise ValueError("profile_authority must be operator, host, or builtin")
    source = profile["source"]
    if source == "builtin":
        if profile != builtin_agent_profile(profile["profile_id"]):
            raise ValueError("builtin profile body does not match the registered builtin profile")
        if selected != "builtin":
            raise ValueError("builtin profile requires builtin profile authority")
    elif source == "host_observed":
        raise ValueError("raw host_observed profile cannot authorize candidate filtering")
    elif source == "operator_declared":
        if selected != "operator" or profile["verification_status"] != "verified":
            raise ValueError("operator_declared profile requires verified operator authority")
    elif source == "resolved":
        field_sources = profile["field_sources"]
        if (
            selected != "operator"
            or profile["verification_status"] != "verified"
            or field_sources["privacy_ceiling"] != "operator_verified"
            or field_sources["project_scopes"] != "operator_verified"
        ):
            raise ValueError("resolved profile grants require verified operator authority")
    else:
        raise ValueError("agent profile source cannot authorize candidate filtering")
    if profile["profile_id"] != contract["agent_profile_id"]:
        raise ValueError("agent profile does not match task contract agent_profile_id")
    profile_scopes = set(profile["project_scopes"])
    contract_scopes = set(contract["scope"]["projects"])
    if not profile_scopes:
        raise ValueError("agent profile grants no project scope")
    if not contract_scopes.issubset(profile_scopes):
        raise ValueError("task contract project scope exceeds the agent profile grant")


def _verify_normalized_candidate(candidate: dict[str, Any]) -> None:
    if not isinstance(candidate, dict) or set(candidate) != set(_NORMALIZED_FIELDS):
        raise ValueError("candidate is not a normalized v1 candidate")
    try:
        if candidate["schema_version"] != CONTEXT_CANDIDATE_SCHEMA_VERSION:
            raise ValueError("schema")
        if candidate["content_ref"] != f"sha256:{candidate['content_hash']}":
            raise ValueError("content reference")
        if candidate["token_cost"] != _token_cost(candidate["expanded_excerpt"]):
            raise ValueError("token cost")
        expected_renderings = (
            {}
            if candidate["expanded_excerpt"] is None
            else {
                "inline_text": candidate["minimum_excerpt"],
                "expanded_text": candidate["expanded_excerpt"],
            }
        )
        if candidate["renderings"] != expected_renderings:
            raise ValueError("renderings")
        _privacy(candidate["privacy_class"])
        _signals(candidate["signals"])
        _provenance(candidate["provenance_chain"])
        if candidate["candidate_id"] != _candidate_identity(candidate):
            raise ValueError("identity")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("candidate integrity check failed") from exc


def filter_candidates_before_scoring(
    candidates: Iterable[dict[str, Any]], *, contract: dict[str, Any],
    profile: dict[str, Any], authority: str, profile_authority: str,
    candidate_authority: CandidateAuthority | None = None,
) -> dict[str, Any]:
    """Return the only candidate list a scorer may consume plus redacted exclusions."""
    from .task_contracts import validate_task_contract

    normalized_contract = validate_task_contract(contract, authority=authority)
    normalized_profile = validate_agent_profile(profile)
    _validate_profile_grants(
        normalized_profile, normalized_contract, profile_authority=profile_authority,
    )
    if not isinstance(candidate_authority, CandidateAuthority):
        raise TypeError("candidate_authority is required before scoring")
    scope = normalized_contract["scope"]
    contract_privacy = PRIVACY_LEVELS.index(scope["privacy_ceiling"])
    profile_privacy = PRIVACY_LEVELS.index(normalized_profile["privacy_ceiling"])
    allowed_sources = set(scope["source_types"])
    allowed_projects = set(scope["projects"])
    profile_projects = set(normalized_profile["project_scopes"])
    path_globs = scope["path_globs"]
    scorable, excluded = [], []
    mandatory_excluded = 0
    contradiction_totals: Counter[str] = Counter()
    contradiction_scorable: Counter[str] = Counter()
    seen = set()
    for candidate in candidates:
        _verify_normalized_candidate(candidate)
        candidate_authority.verify(candidate)
        if candidate["candidate_id"] in seen:
            raise ValueError("candidate IDs must be unique before scoring")
        seen.add(candidate["candidate_id"])
        if candidate["contradiction_group"]:
            contradiction_totals[candidate["contradiction_group"]] += 1
        if candidate["hard_disposition"] and (
            candidate["hard_disposition"].startswith("excluded_")
            or candidate["hard_disposition"] == "redacted"
        ):
            excluded.append(_redacted_exclusion(
                candidate, candidate["hard_disposition"], authority=candidate_authority,
            ))
            continue
        if (
            candidate["project"] not in allowed_projects
            or candidate["project"] not in profile_projects
            or (allowed_sources and candidate["source_type"] not in allowed_sources)
        ):
            excluded.append(_redacted_exclusion(
                candidate, "excluded_scope", authority=candidate_authority,
            ))
            mandatory_excluded += int(candidate_is_mandatory(candidate))
            continue
        location = str(candidate["source_location"] or "").replace("\\", "/")
        if path_globs and candidate["source_type"] == "repository" and not any(
            fnmatch.fnmatchcase(location, pattern) for pattern in path_globs
        ):
            excluded.append(_redacted_exclusion(
                candidate, "excluded_scope", authority=candidate_authority,
            ))
            mandatory_excluded += int(candidate_is_mandatory(candidate))
            continue
        valid_at = scope["valid_at"]
        if valid_at is not None:
            boundary = _instant(valid_at)
            try:
                outside_time = (
                    candidate["valid_from"] is not None
                    and _instant(candidate["valid_from"]) > boundary
                ) or (
                    candidate["valid_to"] is not None
                    and _instant(candidate["valid_to"]) <= boundary
                )
            except (TypeError, ValueError):
                outside_time = True
            if outside_time:
                excluded.append(_redacted_exclusion(
                    candidate, "excluded_scope", authority=candidate_authority,
                ))
                mandatory_excluded += int(candidate_is_mandatory(candidate))
                continue
        recorded_boundary = scope["recorded_sequence"]
        if (
            recorded_boundary is not None
            and not candidate_is_mandatory(candidate)
            and (
                candidate["recorded_sequence"] is None
                or candidate["recorded_sequence"] > recorded_boundary
            )
        ):
            excluded.append(_redacted_exclusion(
                candidate, "excluded_scope", authority=candidate_authority,
            ))
            mandatory_excluded += int(candidate_is_mandatory(candidate))
            continue
        candidate_privacy = PRIVACY_LEVELS.index(candidate["privacy_class"])
        if candidate_privacy > contract_privacy or candidate_privacy > profile_privacy:
            excluded.append(_redacted_exclusion(
                candidate, "excluded_privacy", authority=candidate_authority,
            ))
            mandatory_excluded += int(candidate_is_mandatory(candidate))
            continue
        scorable.append(json.loads(_canonical_json(candidate)))
        if candidate["contradiction_group"]:
            contradiction_scorable[candidate["contradiction_group"]] += 1
    incomplete_contradictions = sum(
        1
        for group, count in contradiction_totals.items()
        if count > 1 and contradiction_scorable[group] != count
    )
    return {
        "status": "ok",
        "scorable": scorable,
        "excluded": excluded,
        "counts": {"scorable": len(scorable), "excluded": len(excluded)},
        "blocking_counts": {
            "mandatory_excluded": mandatory_excluded,
            "incomplete_contradiction_groups": incomplete_contradictions,
        },
    }
