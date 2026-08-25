"""Deterministic v1.0 cognition projections over existing project evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import db
from .multimodal import list_multimodal_evidence
from .repository import repository_state, run_git_inspection


COGNITION_CONTRACT_VERSION = "1.0"
MAX_DEBT_ITEMS = 250
MAX_OBSERVATIONS = 500
MAX_WORK_ITEMS = 500
MAX_CHANGED_PATHS = 2_000
MAX_IMPACT_EDGES = 5_000
MAX_TRUTH_PROJECTION_ROWS = 10_000
OBSERVATION_STATUSES = frozenset({
    "observed", "expected", "missing", "stale", "conflicting", "blocked", "unknown"
})
MAX_COGNITION_OUTPUT_BYTES = 512 * 1024
COGNITION_OUTPUT_RESERVE_BYTES = 512
PRIVACY_CLASSES = frozenset({"public", "internal", "sensitive", "restricted"})
MAX_COGNITION_JSON_BYTES = 64 * 1024


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
        ).fetchone()
    )


def _json(value: Any, fallback: Any) -> Any:
    try:
        decoded = json.loads(value or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback
    return decoded


def _instant(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _now(value: str | None) -> tuple[str, datetime]:
    if value:
        parsed = _instant(value)
        if parsed is None:
            raise ValueError("now must be an ISO-8601 timestamp")
    else:
        parsed = datetime.now(timezone.utc).replace(microsecond=0)
    return parsed.isoformat(), parsed


def _project(conn: sqlite3.Connection, project: str) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT id, name, root_path, repository_identity, checkout_identity
        FROM projects WHERE name = ?
        """,
        (project,),
    ).fetchone()
    if row is None:
        raise ValueError(f"project does not exist: {project}")
    return row


def _required_text(value: Any, label: str, *, maximum: int) -> str:
    selected = str(value or "").strip()
    if not selected:
        raise ValueError(f"{label} is required")
    if len(selected) > maximum or any(ord(character) < 32 for character in selected):
        raise ValueError(f"{label} is invalid")
    return selected


def _optional_text(value: Any, label: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    return _required_text(value, label, maximum=maximum)


def _canonical_object(value: dict[str, Any] | None, label: str) -> str:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded.encode("utf-8")) > MAX_COGNITION_JSON_BYTES:
        raise ValueError(f"{label} exceeds 64 KiB")
    return encoded


def _source_hash(value: str | None) -> str | None:
    if value is None:
        return None
    selected = str(value).strip().casefold()
    if len(selected) != 64 or any(character not in "0123456789abcdef" for character in selected):
        raise ValueError("source_hash must be a SHA-256 hex digest")
    return selected


def _require_binding(
    conn: sqlite3.Connection, project: str, active_root: str | Path
) -> sqlite3.Row:
    row = _project(conn, project)
    binding = db.project_binding_status(conn, project, active_root)
    if not binding["ready"]:
        raise ValueError(f"canonical project binding is not ready: {binding['state']}")
    return row


def _observation_result(row: sqlite3.Row, *, idempotent_replay: bool) -> dict[str, Any]:
    return {
        "status": "ok",
        "observation_id": str(row["observation_id"]),
        "subsystem": str(row["subsystem"]),
        "entity_key": str(row["entity_key"]),
        "observation_status": str(row["status"]),
        "source_identifier": str(row["source_identifier"]),
        "source_hash": row["source_hash"],
        "observed_at": str(row["observed_at"]),
        "valid_until": row["valid_until"],
        "idempotent_replay": idempotent_replay,
    }


def record_observation(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    observation_id: str,
    subsystem: str,
    entity_key: str,
    observed_state: str,
    status: str,
    source_identifier: str,
    source_hash: str | None = None,
    expected_state: str | None = None,
    evidence: dict[str, Any] | None = None,
    observed_at: str | None = None,
    valid_until: str | None = None,
    privacy_class: str = "internal",
    sharing_policy: str = "local-only",
) -> dict[str, Any]:
    """Record one explicit observation without granting it truth authority."""

    db.init_schema(conn)
    selected_project = _required_text(project, "project", maximum=200)
    project_row = _require_binding(conn, selected_project, active_root)
    selected_id = _required_text(observation_id, "observation_id", maximum=256)
    selected_subsystem = _required_text(subsystem, "subsystem", maximum=128)
    selected_entity = _required_text(entity_key, "entity_key", maximum=512)
    selected_expected = _optional_text(expected_state, "expected_state", maximum=4096)
    selected_observed = _required_text(observed_state, "observed_state", maximum=4096)
    selected_status = _required_text(status, "status", maximum=32).casefold()
    if selected_status not in OBSERVATION_STATUSES:
        raise ValueError("status is invalid")
    selected_source = _required_text(source_identifier, "source_identifier", maximum=2048)
    selected_hash = _source_hash(source_hash)
    selected_evidence = _canonical_object(evidence, "evidence")
    selected_privacy = _required_text(privacy_class, "privacy_class", maximum=32).casefold()
    if selected_privacy not in PRIVACY_CLASSES:
        raise ValueError("privacy_class is invalid")
    selected_sharing = _required_text(sharing_policy, "sharing_policy", maximum=128)
    selected_observed_at, _ = _now(observed_at)
    selected_valid_until = None
    if valid_until is not None:
        parsed_until = _instant(valid_until)
        if parsed_until is None:
            raise ValueError("valid_until must be an ISO-8601 timestamp")
        selected_valid_until = parsed_until.isoformat()
    existing = conn.execute(
        "SELECT * FROM cognition_observations WHERE project_id = ? AND observation_id = ?",
        (int(project_row["id"]), selected_id),
    ).fetchone()
    identity = (
        selected_subsystem, selected_entity, selected_expected, selected_observed,
        selected_status, selected_source, selected_hash, selected_evidence,
        selected_observed_at, selected_valid_until, selected_privacy, selected_sharing,
    )
    if existing is not None:
        persisted = (
            existing["subsystem"], existing["entity_key"], existing["expected_state"],
            existing["observed_state"], existing["status"], existing["source_identifier"],
            existing["source_hash"], existing["evidence_json"], existing["observed_at"],
            existing["valid_until"], existing["privacy_class"], existing["sharing_policy"],
        )
        if persisted != identity:
            raise ValueError("observation_id is already bound to different evidence")
        return _observation_result(existing, idempotent_replay=True)
    created_at, _ = _now(None)
    with conn:
        conn.execute(
            """
            INSERT INTO cognition_observations(
                project_id, observation_id, subsystem, entity_key, expected_state,
                observed_state, status, source_identifier, source_hash, evidence_json,
                observed_at, valid_until, privacy_class, sharing_policy, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(project_row["id"]), selected_id, selected_subsystem, selected_entity,
                selected_expected, selected_observed, selected_status, selected_source,
                selected_hash, selected_evidence, selected_observed_at, selected_valid_until,
                selected_privacy, selected_sharing, created_at, created_at,
            ),
        )
    row = conn.execute(
        "SELECT * FROM cognition_observations WHERE project_id = ? AND observation_id = ?",
        (int(project_row["id"]), selected_id),
    ).fetchone()
    return _observation_result(row, idempotent_replay=False)


def reconcile_observation(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path,
    observation_id: str,
    receipt_id: str,
    action: str,
    outcome: str,
    reason: str,
    actor_type: str,
    actor_id: str,
    evidence: dict[str, Any] | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Apply an explicit operator reconciliation and append its immutable receipt."""

    db.init_schema(conn)
    selected_project = _required_text(project, "project", maximum=200)
    project_row = _require_binding(conn, selected_project, active_root)
    selected_actor_type = _required_text(actor_type, "actor_type", maximum=32).casefold()
    if selected_actor_type != "operator":
        raise PermissionError("cognition reconciliation requires operator authority")
    selected_observation = _required_text(observation_id, "observation_id", maximum=256)
    selected_receipt = _required_text(receipt_id, "receipt_id", maximum=256)
    selected_action = _required_text(action, "action", maximum=128)
    selected_outcome = _required_text(outcome, "outcome", maximum=32).casefold()
    if selected_outcome not in OBSERVATION_STATUSES:
        raise ValueError("outcome must be an observation status")
    selected_reason = _required_text(reason, "reason", maximum=4096)
    selected_actor = _required_text(actor_id, "actor_id", maximum=300)
    selected_evidence = _canonical_object(evidence, "evidence")
    selected_created, _ = _now(created_at)
    existing_receipt = conn.execute(
        """
        SELECT * FROM cognition_reconciliation_receipts
        WHERE project_id = ? AND receipt_id = ?
        """,
        (int(project_row["id"]), selected_receipt),
    ).fetchone()
    receipt_identity = (
        selected_observation, selected_action, selected_outcome, selected_actor_type,
        selected_actor, selected_reason, selected_evidence,
    )
    if existing_receipt is not None:
        persisted = tuple(
            existing_receipt[key]
            for key in (
                "observation_id", "action", "outcome", "actor_type", "actor_id",
                "reason", "evidence_json",
            )
        )
        if persisted != receipt_identity:
            raise ValueError("receipt_id is already bound to another reconciliation")
        return {
            "status": str(existing_receipt["outcome"]),
            "receipt_id": selected_receipt,
            "observation_id": selected_observation,
            "idempotent_replay": True,
        }
    observation = conn.execute(
        "SELECT id FROM cognition_observations WHERE project_id = ? AND observation_id = ?",
        (int(project_row["id"]), selected_observation),
    ).fetchone()
    if observation is None:
        raise ValueError("observation does not exist")
    with conn:
        conn.execute(
            """
            INSERT INTO cognition_reconciliation_receipts(
                project_id, receipt_id, observation_id, action, outcome, actor_type,
                actor_id, reason, evidence_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                int(project_row["id"]), selected_receipt, selected_observation,
                selected_action, selected_outcome, selected_actor_type, selected_actor,
                selected_reason, selected_evidence, selected_created,
            ),
        )
        conn.execute(
            """
            UPDATE cognition_observations SET status = ?, updated_at = ?
            WHERE project_id = ? AND observation_id = ?
            """,
            (selected_outcome, selected_created, int(project_row["id"]), selected_observation),
        )
    return {
        "status": selected_outcome,
        "receipt_id": selected_receipt,
        "observation_id": selected_observation,
        "idempotent_replay": False,
    }


def _adequate_evidence(row: sqlite3.Row) -> bool:
    provenance = _json(row["provenance_json"], {})
    verified = str(provenance.get("verification_status", "")).casefold() == "verified"
    authority = str(row["authority_class"]).casefold()
    return bool(
        row["polarity"] == "supporting"
        and row["source_hash"]
        and verified
        and authority in {"pratyaksha", "sabda", "validator", "operator"}
    )


def _truth_projection(
    conn: sqlite3.Connection, project_id: int, boundary: datetime
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    claim_total = int(conn.execute(
        "SELECT COUNT(*) AS count FROM truth_claim_versions "
        "WHERE project_id = ? AND recorded_to_sequence IS NULL",
        (project_id,),
    ).fetchone()["count"])
    claims = conn.execute(
        """
        SELECT * FROM truth_claim_versions
        WHERE project_id = ? AND recorded_to_sequence IS NULL
        ORDER BY claim_id LIMIT ?
        """,
        (project_id, MAX_TRUTH_PROJECTION_ROWS + 1),
    ).fetchall()
    claims_truncated = len(claims) > MAX_TRUTH_PROJECTION_ROWS
    claims = claims[:MAX_TRUTH_PROJECTION_ROWS]
    evidence_rows = conn.execute(
        """
        SELECT * FROM truth_evidence
        WHERE project_id = ? AND recorded_to_sequence IS NULL
        ORDER BY claim_id, evidence_id LIMIT ?
        """,
        (project_id, MAX_TRUTH_PROJECTION_ROWS + 1),
    ).fetchall()
    evidence_truncated = len(evidence_rows) > MAX_TRUTH_PROJECTION_ROWS
    evidence_rows = evidence_rows[:MAX_TRUTH_PROJECTION_ROWS]
    evidence: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in evidence_rows:
        evidence[str(row["claim_id"])].append(row)
    contradictions: dict[str, set[str]] = defaultdict(set)
    relation_rows = conn.execute(
        """
        SELECT from_claim_id, to_claim_id FROM truth_relations
        WHERE project_id = ? AND recorded_to_sequence IS NULL
          AND relation_type = 'contradicts'
        ORDER BY relation_id LIMIT ?
        """,
        (project_id, MAX_TRUTH_PROJECTION_ROWS + 1),
    ).fetchall()
    relations_truncated = len(relation_rows) > MAX_TRUTH_PROJECTION_ROWS
    for row in relation_rows[:MAX_TRUTH_PROJECTION_ROWS]:
        left = str(row["from_claim_id"])
        right = str(row["to_claim_id"])
        contradictions[left].add(right)
        contradictions[right].add(left)
    validator_results: dict[str, str] = {}
    validator_rows = conn.execute(
        """
        SELECT r.validator_id, r.claim_id, r.outcome
        FROM truth_validator_results r
        JOIN (
            SELECT validator_id, MAX(evaluated_sequence) AS sequence
            FROM truth_validator_results WHERE project_id = ?
            GROUP BY validator_id
        ) latest
          ON latest.validator_id = r.validator_id
         AND latest.sequence = r.evaluated_sequence
        WHERE r.project_id = ?
        ORDER BY r.validator_id LIMIT ?
        """,
        (project_id, project_id, MAX_TRUTH_PROJECTION_ROWS + 1),
    ).fetchall()
    validators_truncated = len(validator_rows) > MAX_TRUTH_PROJECTION_ROWS
    for row in validator_rows[:MAX_TRUTH_PROJECTION_ROWS]:
        validator_results[str(row["claim_id"])] = str(row["outcome"])

    debt: list[dict[str, Any]] = []
    coverage = {key: 0 for key in ("verified", "known", "stale", "disputed", "blocked", "unknown")}
    truncated_inputs = [
        label for label, truncated in (
            ("claims", claims_truncated),
            ("evidence", evidence_truncated),
            ("relations", relations_truncated),
            ("validators", validators_truncated),
        ) if truncated
    ]
    if truncated_inputs:
        claim_excess = max(0, claim_total - len(claims))
        coverage["blocked"] += claim_excess + sum(
            label != "claims" for label in truncated_inputs
        )
        debt.append({
            "debt_id": "system:truth-projection-budget",
            "source_type": "system",
            "claim_id": "truth-projection-budget",
            "subject": "truth projection input budget",
            "predicate": "boundedness",
            "epistemic_state": "disputed",
            "severity": "critical",
            "severity_points": 10,
            "reasons": [f"{label}_projection_truncated" for label in truncated_inputs],
            "contradicts": [], "supporting_evidence": 0,
            "validator_outcome": None, "blast_radius": claim_excess,
            "repair": "Reduce, archive, or partition truth history before relying on cognition output.",
        })
    for claim in claims:
        claim_id = str(claim["claim_id"])
        state = str(claim["epistemic_state"])
        expires_at = _instant(claim["expires_at"])
        revalidate_at = _instant(claim["revalidate_at"])
        expired = bool(expires_at and expires_at <= boundary)
        revalidation_due = bool(revalidate_at and revalidate_at <= boundary)
        support = any(_adequate_evidence(item) for item in evidence.get(claim_id, []))
        validator = validator_results.get(claim_id)
        passed = validator == "pass"
        failed = validator in {"fail", "error", "unavailable"}
        conflict_ids = sorted(contradictions.get(claim_id, set()))
        if state in {"stale", "superseded", "retracted"} or expired or revalidation_due:
            coverage["stale"] += 1
        elif state in {"disputed", "refuted"} or conflict_ids or failed:
            coverage["disputed"] += 1
        elif state in {"accepted", "corroborated"} and (support or passed):
            coverage["verified"] += 1
        elif state in {"hypothesis", "observed", "corroborated", "accepted"}:
            coverage["known"] += 1
        else:
            coverage["unknown"] += 1

        if state not in {"accepted", "corroborated", "disputed", "stale", "refuted"}:
            continue
        reasons: list[str] = []
        if not support and not passed:
            reasons.append("missing_supporting_evidence")
        if expired:
            reasons.append("expired")
        if revalidation_due:
            reasons.append("revalidation_due")
        if failed:
            reasons.append(f"validator_{validator}")
        if conflict_ids:
            reasons.append("active_contradiction")
        if state in {"disputed", "stale", "refuted"}:
            reasons.append(f"state_{state}")
        if not reasons:
            continue
        severity_points = (
            (4 if expired else 0)
            + (4 if failed else 0)
            + (3 if conflict_ids else 0)
            + (2 if not support and not passed else 0)
            + (2 if state in {"disputed", "refuted"} else 0)
            + (1 if revalidation_due or state == "stale" else 0)
        )
        severity = "critical" if severity_points >= 7 else (
            "high" if severity_points >= 4 else "medium"
        )
        debt.append(
            {
                "debt_id": f"claim:{claim_id}",
                "source_type": "truth_claim",
                "claim_id": claim_id,
                "subject": str(claim["subject_display"]),
                "predicate": str(claim["predicate"]),
                "epistemic_state": state,
                "severity": severity,
                "severity_points": severity_points,
                "reasons": reasons,
                "contradicts": conflict_ids[:20],
                "supporting_evidence": sum(
                    item["polarity"] == "supporting" for item in evidence.get(claim_id, [])
                ),
                "validator_outcome": validator,
                "blast_radius": len(conflict_ids),
                "repair": (
                    "Run or attach reproducible evidence and resolve contradictions; "
                    "supersede the claim if it is no longer valid."
                ),
            }
        )
    debt.sort(
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2}[item["severity"]],
            -int(item["severity_points"]),
            str(item["debt_id"]),
        )
    )
    return debt[:MAX_DEBT_ITEMS], coverage


def _source_coverage(conn: sqlite3.Connection, project_id: int) -> dict[str, int]:
    counts = {key: 0 for key in ("verified", "known", "stale", "disputed", "blocked", "unknown")}
    row = conn.execute(
        """
        SELECT COUNT(*) AS total,
               COALESCE(SUM(
                   CASE
                     WHEN json_valid(metadata_json) = 1
                      AND json_extract(metadata_json, '$.content_indexed') = 0
                     THEN 1 ELSE 0
                   END
               ), 0) AS blocked
        FROM sources WHERE project_id = ?
        """,
        (project_id,),
    ).fetchone()
    total = int(row["total"] or 0)
    blocked = int(row["blocked"] or 0)
    counts["blocked"] = blocked
    counts["known"] = total - blocked
    return counts


def _observation_projection(
    conn: sqlite3.Connection, project_id: int, boundary: datetime
) -> tuple[list[dict[str, Any]], dict[str, int], int]:
    counts = {key: 0 for key in ("verified", "known", "stale", "disputed", "blocked", "unknown")}
    observations: list[dict[str, Any]] = []
    total = int(conn.execute(
        "SELECT COUNT(*) AS count FROM cognition_observations WHERE project_id = ?",
        (project_id,),
    ).fetchone()["count"])
    for row in conn.execute(
        """
        SELECT observation_id, subsystem, entity_key, expected_state,
               observed_state, status, source_identifier, source_hash,
               observed_at, valid_until
        FROM cognition_observations WHERE project_id = ?
        ORDER BY subsystem, entity_key, observation_id LIMIT ?
        """,
        (project_id, MAX_OBSERVATIONS),
    ):
        status = str(row["status"])
        valid_until = _instant(row["valid_until"])
        if valid_until and valid_until <= boundary:
            status = "stale"
        coverage_key = {
            "observed": "known",
            "expected": "unknown",
            "missing": "unknown",
            "stale": "stale",
            "conflicting": "disputed",
            "blocked": "blocked",
            "unknown": "unknown",
        }[status]
        counts[coverage_key] += 1
        observations.append(
            {
                "observation_id": str(row["observation_id"]),
                "subsystem": str(row["subsystem"]),
                "entity_key": str(row["entity_key"]),
                "expected_state": row["expected_state"],
                "observed_state": str(row["observed_state"]),
                "status": status,
                "source_identifier": str(row["source_identifier"]),
                "source_hash": row["source_hash"],
                "observed_at": str(row["observed_at"]),
                "valid_until": row["valid_until"],
            }
        )
    counts["blocked"] += max(0, total - len(observations))
    return observations, counts, total


def _work_state(
    conn: sqlite3.Connection, project_id: int
) -> tuple[list[dict[str, Any]], list[str], int]:
    if not _table_exists(conn, "work_items"):
        return [], [], 0
    items: list[dict[str, Any]] = []
    reasons: list[str] = []
    total = int(conn.execute(
        "SELECT COUNT(*) AS count FROM work_items WHERE project_id = ?",
        (project_id,),
    ).fetchone()["count"])
    for row in conn.execute(
        """
        SELECT item_type, external_id, qa_state, decision, attempt_count,
               fallback, next_action, updated_at
        FROM work_items WHERE project_id = ?
        ORDER BY item_type, external_id LIMIT ?
        """,
        (project_id, MAX_WORK_ITEMS),
    ):
        item = {key: row[key] for key in row.keys()}
        items.append(item)
        if str(row["decision"]).casefold() in {"pending", "blocked", "unknown"}:
            reasons.append("pending_work")
        if str(row["qa_state"]).casefold() in {"failed", "blocked", "unknown"}:
            reasons.append("work_state_unverified")
    if total > len(items):
        reasons.append("work_state_projection_truncated")
    return items, sorted(set(reasons)), total


def _work_debt(work_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    debt: list[dict[str, Any]] = []
    for item in work_items:
        decision = str(item.get("decision") or "unknown").casefold()
        qa_state = str(item.get("qa_state") or "unknown").casefold()
        attempts = max(0, int(item.get("attempt_count") or 0))
        reasons: list[str] = []
        points = 0
        if decision == "blocked":
            reasons.append("blocked_decision")
            points += 5
        elif decision in {"pending", "unknown"}:
            reasons.append("unresolved_decision")
            points += 2
        if qa_state == "failed":
            reasons.append("failed_qa")
            points += 5
        elif qa_state == "blocked":
            reasons.append("blocked_qa")
            points += 4
        elif qa_state in {"pending", "unknown"}:
            reasons.append("unverified_qa")
            points += 1
        if attempts >= 3:
            reasons.append("repeated_attempts")
            points += 2
        next_action = str(item.get("next_action") or "").strip()
        fallback = str(item.get("fallback") or "").strip()
        if reasons and not next_action:
            reasons.append("missing_next_action")
            points += 2
        if not reasons:
            continue
        item_type = str(item.get("item_type") or "work")
        external_id = str(item.get("external_id") or "unknown")
        debt_id = f"work:{item_type}:{external_id}"
        severity = "critical" if points >= 8 else ("high" if points >= 4 else "medium")
        debt.append({
            "debt_id": debt_id,
            "source_type": "work_item",
            "claim_id": debt_id,
            "subject": f"{item_type}: {external_id}",
            "predicate": "work_state",
            "epistemic_state": "disputed" if severity in {"critical", "high"} else "observed",
            "severity": severity,
            "severity_points": points,
            "reasons": reasons,
            "contradicts": [],
            "supporting_evidence": 0,
            "validator_outcome": qa_state,
            "blast_radius": 0,
            "attempt_count": attempts,
            "decision": decision,
            "repair": next_action or fallback or "Define an evidence-backed next action and reconcile this work item.",
        })
    debt.sort(key=lambda item: (
        {"critical": 0, "high": 1, "medium": 2}[item["severity"]],
        -int(item["severity_points"]),
        str(item["debt_id"]),
    ))
    return debt


def _changed_paths(root: Path) -> tuple[str, list[str], str | None]:
    result = run_git_inspection(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        max_output_bytes=512 * 1024,
    )
    if result is None or result.returncode != 0:
        return "unavailable", [], "trusted_git_unavailable"
    records = [item for item in result.stdout.split("\0") if item]
    paths: list[str] = []
    skip_rename_source = False
    for record in records:
        if skip_rename_source:
            skip_rename_source = False
            continue
        if len(record) < 4:
            continue
        status = record[:2]
        path = record[3:].replace("\\", "/")
        if path and path not in paths:
            paths.append(path)
        if "R" in status or "C" in status:
            skip_rename_source = True
        if len(paths) >= MAX_CHANGED_PATHS:
            break
    return ("changed" if paths else "clean"), sorted(paths), None


def _change_impact(
    conn: sqlite3.Connection, project_id: int, root: Path
) -> dict[str, Any]:
    state, paths, reason = _changed_paths(root)
    items: list[dict[str, Any]] = []
    for path in paths:
        file_row = conn.execute(
            """
            SELECT id FROM entities
            WHERE project_id = ? AND type = 'file' AND name = ?
            """,
            (project_id, path),
        ).fetchone()
        symbols: list[str] = []
        tests: list[str] = []
        claims: list[str] = []
        if file_row is not None:
            symbols = [
                str(row["name"])
                for row in conn.execute(
                    """
                    SELECT symbol.name FROM edges edge
                    JOIN entities symbol ON symbol.id = edge.to_entity_id
                    WHERE edge.project_id = ? AND edge.from_entity_id = ?
                      AND edge.relation = 'contains' AND symbol.type = 'symbol'
                    ORDER BY symbol.name LIMIT ?
                    """,
                    (project_id, int(file_row["id"]), MAX_IMPACT_EDGES),
                )
            ]
            tests = [
                str(row["name"])
                for row in conn.execute(
                    """
                    SELECT DISTINCT test_file.name
                    FROM edges containment
                    JOIN edges test_edge
                      ON test_edge.project_id = containment.project_id
                     AND test_edge.to_entity_id = containment.to_entity_id
                     AND test_edge.relation = 'tests'
                    JOIN entities test_file ON test_file.id = test_edge.from_entity_id
                    WHERE containment.project_id = ?
                      AND containment.from_entity_id = ?
                      AND containment.relation = 'contains'
                      AND test_file.type = 'file'
                    ORDER BY test_file.name LIMIT ?
                    """,
                    (project_id, int(file_row["id"]), MAX_IMPACT_EDGES),
                )
            ]
        claims = [
            str(row["claim_id"])
            for row in conn.execute(
                """
                SELECT DISTINCT claim_id FROM truth_evidence
                WHERE project_id = ? AND recorded_to_sequence IS NULL
                  AND source_identifier = ?
                ORDER BY claim_id LIMIT 250
                """,
                (project_id, path),
            )
        ]
        items.append(
            {
                "path": path,
                "symbols": symbols,
                "related_tests": tests,
                "affected_claims": claims,
                "confidence": "direct" if file_row is not None else "approximate",
                "limitations": [] if file_row is not None else ["file_not_in_current_graph"],
            }
        )
    return {
        "state": state,
        "changed_paths": paths,
        "items": items,
        "reason": reason,
        "truncated": len(paths) >= MAX_CHANGED_PATHS,
    }


def _coverage_summary(subsystems: dict[str, dict[str, int]]) -> dict[str, Any]:
    totals = {key: 0 for key in ("verified", "known", "stale", "disputed", "blocked", "unknown")}
    for values in subsystems.values():
        for key in totals:
            totals[key] += int(values.get(key, 0))
    denominator = sum(totals.values())
    return {
        **totals,
        "denominator": denominator,
        "verified_ratio": round(totals["verified"] / denominator, 6) if denominator else 0.0,
        "known_ratio": round((totals["verified"] + totals["known"]) / denominator, 6)
        if denominator
        else 0.0,
        "limitations": [
            "Coverage measures available evidence states, not semantic completeness.",
            "Indexed source bytes count as known, not verified.",
        ],
    }


def _encoded_bytes(value: Any) -> int:
    return len(
        json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )


def _bounded_cognition_core(core: dict[str, Any]) -> dict[str, Any]:
    """Keep the public snapshot bounded while preserving totals and priority order."""

    collections = [
        ("project_twin.observations", core["project_twin"], "observations", 32),
        ("project_twin.conflicts", core["project_twin"], "conflicts", 16),
        ("change_impact.items", core["change_impact"], "items", 64),
        ("change_impact.changed_paths", core["change_impact"], "changed_paths", 64),
        ("project_twin.work_items", core["project_twin"], "work_items", 32),
        ("multimodal.items", core["multimodal"], "items", 32),
        ("decision_debt.items", core["decision_debt"], "items", 32),
    ]
    for _label, parent, key, _floor in collections:
        value = parent.get(key)
        if isinstance(value, list):
            parent.setdefault(
                f"{key[:-1] if key.endswith('s') else key}_count", len(value)
            )
    budget = {
        "maximum_bytes": MAX_COGNITION_OUTPUT_BYTES,
        "truncated": False,
        "omitted": {},
    }
    core["output_budget"] = budget
    target = MAX_COGNITION_OUTPUT_BYTES - COGNITION_OUTPUT_RESERVE_BYTES
    while _encoded_bytes(core) > target:
        changed = False
        for label, parent, key, floor in collections:
            values = parent.get(key)
            if not isinstance(values, list) or len(values) <= floor:
                continue
            keep = max(floor, len(values) // 2)
            omitted = len(values) - keep
            parent[key] = values[:keep]
            budget["omitted"][label] = int(budget["omitted"].get(label, 0)) + omitted
            budget["truncated"] = True
            changed = True
            if _encoded_bytes(core) <= target:
                break
        if not changed:
            break
    if _encoded_bytes(core) > target:
        for label, parent, key, _floor in collections:
            values = parent.get(key)
            while isinstance(values, list) and values and _encoded_bytes(core) > target:
                values.pop()
                budget["omitted"][label] = int(budget["omitted"].get(label, 0)) + 1
                budget["truncated"] = True
    budget["encoded_core_bytes"] = _encoded_bytes(core)
    if budget["encoded_core_bytes"] > target:
        raise RuntimeError("cognition snapshot cannot satisfy its output budget")
    return core


def cognition_snapshot(
    conn: sqlite3.Connection,
    *,
    project: str,
    active_root: str | Path | None = None,
    now: str | None = None,
    include_change_impact: bool = True,
) -> dict[str, Any]:
    """Build one bounded, privacy-safe, mutation-free project cognition snapshot."""

    db.init_schema(conn)
    generated_at, boundary = _now(now)
    project_row = _project(conn, project)
    project_id = int(project_row["id"])
    root = Path(str(project_row["root_path"])).resolve()
    binding = db.project_binding_status(conn, project, active_root or root)
    freshness = db.indexed_freshness(conn, project=project)
    repo = repository_state(root, include_worktree=True)
    debt, truth_coverage = _truth_projection(conn, project_id, boundary)
    observations, observation_coverage, observation_total = _observation_projection(
        conn, project_id, boundary
    )
    work_items, work_reasons, work_total = _work_state(conn, project_id)
    debt.extend(_work_debt(work_items))
    if work_total > len(work_items):
        debt.append({
            "debt_id": "system:work-state-projection-budget",
            "source_type": "system",
            "claim_id": "work-state-projection-budget",
            "subject": "work-state projection input budget",
            "predicate": "boundedness",
            "epistemic_state": "disputed",
            "severity": "critical",
            "severity_points": 10,
            "reasons": ["work_state_projection_truncated"],
            "contradicts": [],
            "supporting_evidence": 0,
            "validator_outcome": None,
            "blast_radius": work_total - len(work_items),
            "repair": (
                "Partition or archive resolved work state before relying on cognition output."
            ),
        })
    debt.sort(key=lambda item: (
        {"critical": 0, "high": 1, "medium": 2}[item["severity"]],
        -int(item["severity_points"]),
        str(item["debt_id"]),
    ))
    debt_total = len(debt)
    debt = debt[:MAX_DEBT_ITEMS]
    source_coverage = _source_coverage(conn, project_id)
    media = list_multimodal_evidence(conn, project=project, limit=250)
    media_coverage = {key: 0 for key in ("verified", "known", "stale", "disputed", "blocked", "unknown")}
    for item in media["items"]:
        if item["verified_derivations"]:
            media_coverage["verified"] += 1
        else:
            media_coverage["known"] += 1
    media_coverage["blocked"] += max(0, int(media["count"]) - len(media["items"]))
    subsystems = {
        "repository": source_coverage,
        "truth": truth_coverage,
        "observations": observation_coverage,
        "multimodal": media_coverage,
    }
    reasons: list[str] = []
    if not binding["ready"]:
        reasons.append("canonical_binding_not_ready")
    if freshness["state"] not in {"fresh", "fresh_with_warnings"}:
        reasons.append("repository_not_fresh")
    checkpoint = conn.execute(
        """
        SELECT id, objective, verified_evidence, remaining_gaps, next_action,
               prohibited_repetition, source, trigger, version, updated_at
        FROM checkpoints WHERE project_id = ? ORDER BY version DESC, id DESC LIMIT 1
        """,
        (project_id,),
    ).fetchone()
    if checkpoint is None:
        reasons.append("no_structured_checkpoint")
        checkpoint_summary = None
    else:
        checkpoint_summary = {
            "id": int(checkpoint["id"]),
            "version": int(checkpoint["version"]),
            "source": str(checkpoint["source"]),
            "trigger": str(checkpoint["trigger"]),
            "has_verified_evidence": bool(str(checkpoint["verified_evidence"]).strip()),
            "has_next_action": bool(str(checkpoint["next_action"]).strip()),
            "updated_at": str(checkpoint["updated_at"]),
        }
        if not checkpoint_summary["has_verified_evidence"]:
            reasons.append("checkpoint_unverified")
    reasons.extend(work_reasons)
    if observation_total > len(observations):
        reasons.append("observation_projection_truncated")
    if media["truncated"]:
        reasons.append("multimodal_projection_truncated")
    if any(item["severity"] == "critical" for item in debt):
        reasons.append("critical_decision_debt")
    reasons = sorted(set(reasons))
    impact = (
        _change_impact(conn, project_id, root)
        if include_change_impact and binding["ready"]
        else {
            "state": "skipped",
            "changed_paths": [],
            "items": [],
            "reason": "disabled" if not include_change_impact else "canonical_binding_not_ready",
            "truncated": False,
        }
    )
    twin_observations = [
        {
            "subsystem": "repository",
            "entity_key": "canonical-checkout",
            "status": "observed" if binding["ready"] else "conflicting",
            "observed_state": binding["state"],
        },
        {
            "subsystem": "repository",
            "entity_key": "indexed-sources",
            "status": "observed" if freshness["state"] in {"fresh", "fresh_with_warnings"} else "stale",
            "observed_state": freshness["state"],
        },
        *observations,
    ][:MAX_OBSERVATIONS]
    core = {
        "contract_version": COGNITION_CONTRACT_VERSION,
        "project": project,
        "identity": {
            "state": binding["state"],
            "canonical_match": bool(binding["ready"]),
            "root_fingerprint": binding.get("root_fingerprint"),
            "repository_fingerprint": binding.get("repository_fingerprint"),
            "checkout_fingerprint": binding.get("checkout_fingerprint"),
        },
        "repository": {
            "freshness": freshness["state"],
            "freshness_mode": freshness.get("mode", "index-snapshot"),
            "freshness_checked_at": freshness.get("checked_at"),
            "fresh": int(freshness.get("fresh", 0)),
            "changed": int(freshness.get("changed", 0)),
            "missing": int(freshness.get("missing", 0)),
            "added": int(freshness.get("added", 0)),
            "blocked": int(freshness.get("uninspectable", 0)),
            "metadata_only": int(freshness.get("metadata_only", 0)),
            "branch": repo.get("branch"),
            "head": repo.get("head"),
            "dirty_count": int(repo.get("dirty_count") or 0),
        },
        "readiness": {
            "database_healthy": True,
            "continuation_ready": not reasons,
            "state": "ready" if not reasons else "operationally_not_ready",
            "reasons": reasons,
            "checkpoint": checkpoint_summary,
        },
        "project_twin": {
            "observations": twin_observations,
            "observation_count": observation_total + 2,
            "work_items": work_items,
            "work_item_count": work_total,
            "conflicts": [
                item for item in twin_observations if item["status"] in {"conflicting", "missing", "blocked"}
            ],
        },
        "decision_debt": {
            "count": debt_total,
            "critical": sum(item["severity"] == "critical" for item in debt),
            "high": sum(item["severity"] == "high" for item in debt),
            "items": debt,
            "truncated": debt_total > len(debt),
        },
        "knowledge_coverage": {
            "subsystems": subsystems,
            "summary": _coverage_summary(subsystems),
        },
        "change_impact": impact,
        "multimodal": media,
        "limitations": [
            "Routine freshness is the latest completed index snapshot; run stale-check for live filesystem verification.",
            "Freshness proves indexed bytes, not semantic correctness.",
            "Approximate parser and graph edges remain labelled as impact hints.",
            "External systems are unknown unless an authorized adapter observed them.",
        ],
    }
    core = _bounded_cognition_core(core)
    digest = hashlib.sha256(
        json.dumps(core, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return {
        "status": "ok",
        "generated_at": generated_at,
        "digest": digest,
        **core,
    }
