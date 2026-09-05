import argparse
import asyncio
import copy
import hmac
import json
import os
import re
import secrets
import stat
import sys
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from . import __version__
from .binding_guard import McpBindingLease
from .capture import (
    bind_session as bind_capture_session,
)
from .capture import (
    close_session_binding,
    control_capture_retention,
    delete_capture_content,
    export_capture_events,
    retire_capture_policy,
    set_capture_source_state,
)
from .capture import (
    register_policy as register_capture_policy,
)
from .capture_control import capture_diagnostics, capture_replay, capture_status_report
from .capture_types import CapturePolicy
from .cognition import cognition_snapshot
from .context import build_context_pack, build_continuation_prompt
from .context_host import compile_context_for_agent, explain_context_for_agent
from .continuity import (
    append_event,
    ingest_codex_session,
    init_continuity_schema,
    list_events,
    operational_readiness,
    reconcile_work_items,
    reject_windows_network_path,
)
from .continuity_daemon import (
    continuity_status,
    public_continuity_status,
    start_continuity,
    stop_continuity,
    validate_codex_session_binding,
)
from .db import (
    connect,
    doctor,
    graph,
    graph_query,
    ingest_repo,
    ingest_thread,
    integrity_diagnostics,
    project_binding_status,
    reflect,
    remember,
    remember_many,
    save_checkpoint,
    search,
    stale_check,
)
from .diagnostics import retrieval_diagnostics
from .governance import (
    build_operational_context,
    create_policy,
    list_policies,
    list_receipts,
    preflight,
    retire_policy,
)
from .ingest import _lexical_root_for_candidate
from .mcp_host_lifecycle import record_server_observed_tool_event
from .multimodal import (
    export_multimodal_manifest,
    list_multimodal_derivations,
    list_multimodal_evidence,
    verify_multimodal_source,
)
from .privacy import redact_sensitive_data, redact_sensitive_text
from .progressive_retrieval import ProgressiveRetriever
from .temporal import (
    append_claim,
    attach_evidence,
    change_claim_state,
    define_validator,
    record_abstention,
    redact_truth_for_operator,
    relate_claims,
    revise_claim,
    run_validator,
    truth_as_of,
    truth_current,
    truth_diff,
    truth_explain,
    truth_history,
)
from .trusted_lifecycle import inspect_lifecycle, lifecycle_review_bundle
from .workspaces import (
    get_workspace,
    list_workspaces,
    search_workspace,
    workspace_health,
)


def tool_schema(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": False,
        },
    }


MCP_PRIVACY_RANKS = {
    "public": 0,
    "internal": 1,
    "sensitive": 2,
    "restricted": 3,
}


def _normalize_privacy_class(value: Any, *, request: bool = False) -> str | None:
    selected = str(value or "").strip().casefold()
    if selected == "private":
        selected = "restricted"
    if selected in MCP_PRIVACY_RANKS:
        return selected
    if request:
        raise ValueError("MCP privacy ceiling is invalid")
    return None


def _effective_privacy_ceiling(
    requested: Any,
    maximum: str,
) -> tuple[str, str, bool]:
    normalized_request = _normalize_privacy_class(requested, request=True)
    assert normalized_request is not None
    effective = min(
        (normalized_request, maximum),
        key=lambda item: MCP_PRIVACY_RANKS[item],
    )
    return (
        normalized_request,
        effective,
        MCP_PRIVACY_RANKS[normalized_request] > MCP_PRIVACY_RANKS[maximum],
    )


def _privacy_class_for_memory(item: dict[str, Any]) -> str | None:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        try:
            metadata = json.loads(item.get("metadata_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            return None
    if not isinstance(metadata, dict):
        return None
    if "privacy_class" not in metadata:
        return None
    return _normalize_privacy_class(metadata.get("privacy_class"))


def _visible_current_claim_ids(
    conn, *, project: str, claim_ids: set[str], ceiling: str
) -> set[str]:
    if not claim_ids:
        return set()
    project_row = conn.execute(
        "SELECT id FROM projects WHERE name = ?", (project,)
    ).fetchone()
    if project_row is None:
        return set()
    visible: set[str] = set()
    ordered_ids = sorted(claim_ids)
    ceiling_rank = MCP_PRIVACY_RANKS[ceiling]
    for offset in range(0, len(ordered_ids), 500):
        batch = ordered_ids[offset : offset + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = conn.execute(
            f"SELECT claim_id, privacy_class FROM truth_claim_versions "
            f"WHERE project_id = ? AND recorded_to_sequence IS NULL "
            f"AND claim_id IN ({placeholders})",
            (int(project_row["id"]), *batch),
        ).fetchall()
        visible.update(
            str(row["claim_id"])
            for row in rows
            if (
                (privacy_class := _normalize_privacy_class(row["privacy_class"]))
                is not None
                and MCP_PRIVACY_RANKS[privacy_class] <= ceiling_rank
            )
        )
    return visible


def _filter_truth_counterparts(
    conn, payload: Any, *, project: str, ceiling: str
) -> Any:
    related_ids: set[str] = set()

    def owner_claim_id(value: dict[str, Any]) -> str | None:
        if value.get("claim_id"):
            return str(value["claim_id"])
        claim = value.get("claim")
        if isinstance(claim, dict) and claim.get("claim_id"):
            return str(claim["claim_id"])
        return None

    def collect(value: Any) -> None:
        if isinstance(value, list):
            for child in value:
                collect(child)
            return
        if not isinstance(value, dict):
            return
        related_ids.update(
            str(claim_id)
            for claim_id in value.get("contradictions", [])
            if claim_id
        )
        owner = owner_claim_id(value)
        for relation in value.get("relations", []):
            if not isinstance(relation, dict):
                continue
            related_ids.update(
                str(relation[key])
                for key in ("from_claim_id", "to_claim_id", "other_claim_id")
                if relation.get(key) and str(relation[key]) != owner
            )
        for child in value.values():
            collect(child)

    collect(payload)
    visible_ids = _visible_current_claim_ids(
        conn, project=project, claim_ids=related_ids, ceiling=ceiling
    )

    def filter_value(value: Any) -> Any:
        if isinstance(value, list):
            return [filter_value(child) for child in value]
        if not isinstance(value, dict):
            return value
        filtered = {key: filter_value(child) for key, child in value.items()}
        if "contradictions" in value and isinstance(value["contradictions"], list):
            filtered["contradictions"] = [
                claim_id
                for claim_id in value["contradictions"]
                if str(claim_id) in visible_ids
            ]
        owner = owner_claim_id(value)
        if "relations" in value and isinstance(value["relations"], list):
            visible_relations = []
            for relation in value["relations"]:
                if not isinstance(relation, dict):
                    continue
                counterparts = {
                    str(relation[key])
                    for key in ("from_claim_id", "to_claim_id", "other_claim_id")
                    if relation.get(key) and str(relation[key]) != owner
                }
                if counterparts and counterparts.issubset(visible_ids):
                    visible_relations.append(filter_value(relation))
            filtered["relations"] = visible_relations
        return filtered

    return filter_value(payload)


def _filter_search_payload(
    conn,
    payload: dict[str, Any],
    *,
    project: str,
    requested_ceiling: str,
    effective_ceiling: str,
    maximum_ceiling: str,
    request_limited: bool,
) -> dict[str, Any]:
    ceiling_rank = MCP_PRIVACY_RANKS[effective_ceiling]
    result = copy.deepcopy(payload)
    filtered_counts: dict[str, int] = {}
    visible: dict[str, list[dict[str, Any]]] = {}
    for collection in ("memories", "chunks", "truth"):
        accepted: list[dict[str, Any]] = []
        filtered = 0
        for item in result.get(collection, []):
            privacy_class = (
                _privacy_class_for_memory(item)
                if collection == "memories"
                else _normalize_privacy_class(
                    item.get("privacy_class")
                )
            )
            if privacy_class is None or MCP_PRIVACY_RANKS[privacy_class] > ceiling_rank:
                filtered += 1
                continue
            accepted.append(item)
        visible[collection] = accepted
        filtered_counts[collection] = filtered
    related_claim_ids = {
        str(related_id)
        for claim in visible["truth"]
        for related_id in claim.get("contradictions", [])
        if related_id
    }
    visible_related_claim_ids = _visible_current_claim_ids(
        conn,
        project=project,
        claim_ids=related_claim_ids,
        ceiling=effective_ceiling,
    )
    for claim in visible["truth"]:
        claim["contradictions"] = [
            related_id
            for related_id in claim.get("contradictions", [])
            if str(related_id) in visible_related_claim_ids
        ]
    result.update(visible)
    result["privacy"] = {
        "requested_ceiling": requested_ceiling,
        "maximum_ceiling": maximum_ceiling,
        "effective_ceiling": effective_ceiling,
        "request_limited": request_limited,
        "filtered_counts": filtered_counts,
        "filtered_total": sum(filtered_counts.values()),
        "unknown_classes": "filtered",
    }
    return result


def gateway_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Require an explicit project when advertising a multi-project gateway tool."""
    advertised = copy.deepcopy(tool)
    schema = advertised["inputSchema"]
    schema["properties"].setdefault(
        "project",
        {"type": "string", "description": "Project memory bank name."},
    )
    required = list(schema.get("required") or [])
    if "project" not in required:
        required.append("project")
    schema["required"] = required
    advertised["description"] = (
        f'{advertised["description"]} An explicit project is required in multi-project gateway mode.'
    )
    return advertised


TOOLS = [
    tool_schema(
        "brain_search",
        "Search Rta-Smriti memories and indexed repository chunks.",
        {
            "query": {"type": "string", "description": "Search query."},
            "project": {"type": "string", "description": "Project memory bank name."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 8},
            "privacy_ceiling": {
                "type": "string",
                "enum": ["public", "internal", "sensitive", "restricted", "private"],
                "default": "internal",
                "description": "Requested ceiling; the server launch ceiling cannot be raised.",
            },
        },
        ["query"],
    ),
    tool_schema(
        "brain_retrieve",
        "Retrieve a snapshot-bound index, timeline, or cited evidence expansion.",
        {
            "project": {"type": "string"},
            "stage": {"type": "string", "enum": ["index", "timeline", "evidence"]},
            "query": {"type": "string", "maxLength": 10000},
            "expansion_handle": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 8},
            "max_tokens": {"type": "integer", "minimum": 64, "maximum": 100000, "default": 4000},
            "privacy_ceiling": {"type": "string", "enum": ["public", "internal", "sensitive", "restricted", "private"], "default": "internal"},
        },
        ["stage"],
    ),
    tool_schema(
        "brain_remember_batch",
        "Atomically store multiple durable, provenance-bearing memories.",
        {
            "project": {"type": "string"},
            "items": {
                "type": "array",
                "minItems": 1,
                "maxItems": 500,
                "items": {"type": "object"},
            },
        },
        ["items"],
    ),
    tool_schema(
        "brain_context_pack",
        "Build a compact task context pack with pramana tags and stale status.",
        {
            "task": {"type": "string", "description": "Task or question to prepare context for."},
            "project": {"type": "string", "description": "Project memory bank name."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 8},
            "max_tokens": {"type": "integer", "minimum": 256, "maximum": 100000, "default": 4000},
        },
        ["task"],
    ),
    tool_schema(
        "brain_context_compile",
        "Compile one operator-authorized context variant for this bound MCP session.",
        {
            "task_contract_id": {"type": "integer", "minimum": 1},
            "variant": {
                "type": "string",
                "enum": [
                    "primary",
                    "mode:minimal",
                    "mode:balanced",
                    "mode:investigative",
                    "mode:handoff",
                ],
                "default": "primary",
            },
        },
        ["task_contract_id"],
    ),
    tool_schema(
        "brain_context_explain",
        "Explain one compilation bound to this MCP server principal and session.",
        {"compilation_id": {"type": "string"}},
        ["compilation_id"],
    ),
    tool_schema(
        "brain_remember",
        "Store one durable memory with a Vedic pramana evidence tag.",
        {
            "text": {"type": "string", "description": "One atomic durable memory."},
            "type": {"type": "string", "description": "Memory type such as fact, decision, constraint, procedure, bug, or evidence."},
            "pramana": {
                "type": "string",
                "enum": ["pratyaksha", "sabda", "anumana", "smriti", "kalpana"],
                "description": "Evidence class: direct observation, trusted instruction, inference, prior memory, or hypothesis.",
            },
            "project": {"type": "string", "description": "Project memory bank name."},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1, "default": 0.75},
            "priority": {"type": "integer", "minimum": 1, "maximum": 10, "default": 5},
            "provenance": {
                "type": "object",
                "properties": {
                    "source_path": {"type": "string"},
                    "source_hash": {"type": "string"},
                    "command": {"type": "string"},
                    "timestamp": {"type": "string"},
                    "verification_status": {"type": "string", "enum": ["unverified", "verified", "failed", "stale"]},
                },
                "additionalProperties": False,
            },
        },
        ["text"],
    ),
    tool_schema(
        "brain_ingest_repo",
        "Index a local repository or folder into the Rta-Smriti brain.",
        {
            "path": {"type": "string", "description": "Local repository or folder path."},
            "project": {"type": "string", "description": "Project memory bank name."},
            "force": {"type": "boolean", "default": False, "description": "Hash every file even when the stat manifest is unchanged."},
            "repair_deep_stale": {"type": "boolean", "default": False, "description": "Hash every eligible file and re-index only content-drifted sources."},
        },
        ["path"],
    ),
    tool_schema(
        "brain_ingest_thread",
        "Index a long thread, transcript, JSONL session, or handoff file and promote durable observations.",
        {
            "path": {"type": "string", "description": "Local transcript, markdown, text, or JSONL session path."},
            "project": {"type": "string", "description": "Project memory bank name."},
            "title": {"type": "string", "description": "Human-readable thread or handoff title."},
        },
        ["path"],
    ),
    tool_schema(
        "brain_repo_map",
        "Return local graph nodes and edges for a project.",
        {
            "project": {"type": "string", "description": "Project memory bank name."},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        },
    ),
    tool_schema(
        "brain_stale_check",
        "Compactly report freshness counts and anomalous files; fresh file rows are omitted by default.",
        {
            "project": {"type": "string", "description": "Project memory bank name."},
            "deep": {"type": "boolean", "default": False, "description": "Hash file contents instead of using the fast stat manifest."},
            "rehash": {"type": "boolean", "default": False, "description": "Bypass the stat-keyed hash cache; implies deep verification."},
            "include_fresh_details": {"type": "boolean", "default": False},
            "detail_limit": {"type": "integer", "minimum": 0, "maximum": 500, "default": 50},
        },
    ),
    tool_schema(
        "brain_integrity_diagnostics",
        "Report privacy-safe schema, canonical checkout, duplicate-root, and migration integrity evidence.",
        {"project": {"type": "string", "description": "Project memory bank name."}},
    ),
    tool_schema(
        "brain_checkpoint",
        "Save a structured continuation checkpoint for the next agent task.",
        {
            "project": {"type": "string"},
            "objective": {"type": "string"},
            "verified_evidence": {"type": "string"},
            "remaining_gaps": {"type": "string"},
            "next_action": {"type": "string"},
            "prohibited_repetition": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
        },
        ["objective"],
    ),
    tool_schema(
        "brain_continuation_prompt",
        "Build a compact new-task prompt from the canonical root, Git state, freshness, and latest checkpoint.",
        {"project": {"type": "string"}},
    ),
    tool_schema(
        "brain_session_event",
        "Append an immutable, provenance-bearing operational event.",
        {
            "project": {"type": "string"},
            "session_id": {"type": "string", "maxLength": 512},
            "cursor": {"type": "string", "maxLength": 1024},
            "event_type": {"type": "string", "maxLength": 128},
            "payload": {"type": "object"},
        },
        ["session_id", "cursor", "event_type", "payload"],
    ),
    tool_schema(
        "brain_session_events",
        "Read append-only operational events for a project or session.",
        {"project": {"type": "string"}, "session_id": {"type": "string", "maxLength": 512}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}},
    ),
    tool_schema(
        "brain_ingest_codex_session",
        "Incrementally capture a local Codex JSONL transcript using a byte cursor.",
        {
            "project": {"type": "string"}, "path": {"type": "string"},
            "max_events": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 5000},
        },
        ["path"],
    ),
    tool_schema(
        "brain_work_item",
        "Create or update a structured asset, job, approval, blocker, or other work-state record.",
        {
            "project": {"type": "string"}, "item_type": {"type": "string"},
            "external_id": {"type": "string"}, "local_path": {"type": "string"},
            "qa_state": {
                "type": "string",
                "enum": ["unknown", "pending", "failed", "blocked"],
            },
            "decision": {
                "type": "string",
                "enum": ["pending", "blocked", "rejected"],
            },
            "attempt_count": {"type": "integer", "minimum": 0}, "fallback": {"type": "string"},
            "next_action": {"type": "string"}, "metadata": {"type": "object"},
        },
        ["item_type", "external_id"],
    ),
    tool_schema("brain_reconcile", "Reconcile structured work state with the local filesystem.", {"project": {"type": "string"}}),
    tool_schema("brain_operational_readiness", "Distinguish database health from task continuation readiness.", {"project": {"type": "string"}}),
    tool_schema("brain_continuity_status", "Report managed Codex transcript capture and checkpoint lifecycle health.", {"project": {"type": "string"}}),
    tool_schema(
        "brain_continuity_control",
        "Start or stop managed Codex transcript capture for the canonical project root.",
        {
            "project": {"type": "string"},
            "action": {"type": "string", "enum": ["start", "stop"]},
            "interval": {"type": "number", "minimum": 0.1, "maximum": 3600},
            "inactivity": {"type": "number", "minimum": 1, "maximum": 604800},
        },
        ["action"],
    ),
    tool_schema(
        "brain_reflect",
        "Consolidate duplicate memories and flag simple contradictions so stale or unsafe context is not recalled as truth.",
        {"project": {"type": "string", "description": "Project memory bank name."}},
    ),
    tool_schema(
        "brain_graph_query",
        "Traverse bounded dependencies, dependents, impact, evidence, or relevance around an entity.",
        {
            "project": {"type": "string"},
            "target": {"type": "string"},
            "query_type": {"type": "string", "enum": ["dependencies", "dependents", "impact", "evidence", "relevance"], "default": "impact"},
            "depth": {"type": "integer", "minimum": 0, "maximum": 4, "default": 2},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        },
        ["target"],
    ),
    tool_schema(
        "brain_retrieval_diagnostics",
        "Explain retrieval mode, index coverage, ranking components, evidence hashes, freshness, and latency.",
        {
            "project": {"type": "string"},
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 8},
        },
        ["query"],
    ),
    tool_schema(
        "brain_cognition_snapshot",
        "Build a deterministic, evidence-aware digital twin, decision-debt, knowledge-coverage, and change-impact snapshot.",
        {
            "project": {"type": "string"},
            "include_change_impact": {"type": "boolean", "default": True},
        },
    ),
    tool_schema(
        "brain_multimodal_list",
        "List bounded provenance-bearing multimodal evidence without returning source payloads or local paths.",
        {
            "project": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 250, "default": 100},
        },
    ),
    tool_schema(
        "brain_multimodal_derivations",
        "List bounded derivation metadata for one multimodal source without returning derived text.",
        {
            "project": {"type": "string"},
            "source_id": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 250, "default": 100},
        },
        ["source_id"],
    ),
    tool_schema(
        "brain_multimodal_verify",
        "Read-only verification of one registered media source against its canonical project file.",
        {"project": {"type": "string"}, "source_id": {"type": "string"}},
        ["source_id"],
    ),
    tool_schema(
        "brain_multimodal_export",
        "Build a bounded metadata-only media manifest; public mode excludes non-public evidence.",
        {
            "project": {"type": "string"},
            "audience": {"type": "string", "enum": ["local", "public"], "default": "local"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 1000},
        },
    ),
    tool_schema(
        "brain_workspace_search",
        "Search every project in an operator-defined multi-repository workspace.",
        {
            "workspace": {"type": "string"},
            "query": {"type": "string"},
            "limit_per_project": {"type": "integer", "minimum": 1, "maximum": 20, "default": 4},
        },
        ["workspace", "query"],
    ),
    tool_schema(
        "brain_workspace_list",
        "List multi-repository workspaces or inspect one workspace.",
        {"workspace": {"type": "string"}},
    ),
    tool_schema(
        "brain_workspace_health",
        "Report member availability for one multi-repository workspace without exposing local database paths.",
        {"workspace": {"type": "string"}},
        ["workspace"],
    ),
    tool_schema(
        "brain_policy_add",
        "Create a typed, provenance-bearing pre-action governance policy.",
        {
            "project": {"type": "string"},
            "kind": {"type": "string", "enum": ["constraint", "failed_approach", "fragile_path", "required_check", "prohibited_repetition"]},
            "statement": {"type": "string"},
            "effect": {"type": "string", "enum": ["warn", "block"], "default": "warn"},
            "action_contains": {"type": "string"},
            "path_glob": {"type": "string"},
            "required_check": {"type": "string"},
            "pramana": {"type": "string", "enum": ["pratyaksha", "sabda", "anumana", "smriti", "kalpana"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "provenance": {"type": "object"},
            "overrideable": {"type": "boolean"},
            "expires_at": {"type": "string"},
        },
        ["kind", "statement"],
    ),
    tool_schema(
        "brain_policy_list",
        "List active or retired governance policies for a project.",
        {"project": {"type": "string"}, "include_retired": {"type": "boolean", "default": False}},
    ),
    tool_schema(
        "brain_policy_retire",
        "Explicitly retire an active governance policy.",
        {"project": {"type": "string"}, "policy_id": {"type": "integer"}, "reason": {"type": "string"}},
        ["policy_id", "reason"],
    ),
    tool_schema(
        "brain_preflight",
        "Return allow, warn, or block before an action; overrides create receipts.",
        {
            "project": {"type": "string"},
            "action": {"type": "string"},
            "path": {"type": "string"},
            "include_operational_context": {"type": "boolean", "default": True},
        },
        ["action"],
    ),
    tool_schema(
        "brain_governance_receipts",
        "List immutable governance override receipts.",
        {"project": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 500}},
    ),
    tool_schema(
        "brain_truth_current",
        "Read one claim from the current bitemporal truth projection.",
        {
            "project": {"type": "string"},
            "claim_id": {"type": "string"},
            "valid_at": {"type": "string"},
        },
        ["claim_id"],
    ),
    tool_schema(
        "brain_truth_as_of",
        "Read one claim at valid time V as known at recorded sequence R.",
        {
            "project": {"type": "string"},
            "claim_id": {"type": "string"},
            "valid_at": {"type": "string"},
            "recorded_sequence": {"type": "integer", "minimum": 1},
        },
        ["claim_id", "valid_at", "recorded_sequence"],
    ),
    tool_schema(
        "brain_truth_history",
        "Read bounded recorded-time history for one truth claim.",
        {
            "project": {"type": "string"},
            "claim_id": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        },
        ["claim_id"],
    ),
    tool_schema(
        "brain_truth_diff",
        "Compare project truth between two recorded sequences at one valid time.",
        {
            "project": {"type": "string"},
            "from_sequence": {"type": "integer", "minimum": 1},
            "to_sequence": {"type": "integer", "minimum": 1},
            "valid_at": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
        },
        ["from_sequence", "to_sequence", "valid_at"],
    ),
    tool_schema(
        "brain_truth_explain",
        "Explain one current claim with typed relations and provenance-bearing evidence.",
        {
            "project": {"type": "string"},
            "claim_id": {"type": "string"},
            "valid_at": {"type": "string"},
        },
        ["claim_id"],
    ),
    tool_schema(
        "brain_truth_assert",
        "Append an agent-authored truth assertion. Agent claims remain hypothesis or observed and cannot self-accept.",
        {
            "project": {"type": "string"},
            "claim_id": {"type": "string"},
            "subject": {"type": "string"},
            "predicate": {"type": "string"},
            "value": {},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
            "valid_from": {"type": "string"},
            "valid_to": {"type": "string"},
            "expires_at": {"type": "string"},
            "epistemic_state": {"type": "string", "enum": ["hypothesis", "observed"], "default": "observed"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 0.75, "default": 0.75},
        },
        ["subject", "predicate", "value", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_state",
        "Append an agent-authorized epistemic state transition. Acceptance is owner-only.",
        {
            "project": {"type": "string"},
            "claim_id": {"type": "string"},
            "state": {
                "type": "string",
                "enum": ["observed", "corroborated", "disputed", "stale", "refuted", "superseded", "retracted"],
            },
            "reason": {"type": "string"},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 1},
        },
        ["claim_id", "state", "reason", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_revise",
        "Append an agent-authored correction while preserving prior recorded belief.",
        {
            "project": {"type": "string"}, "claim_id": {"type": "string"},
            "value": {}, "reason": {"type": "string"},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 1},
            "valid_from": {"type": "string"}, "valid_to": {"type": "string"},
        },
        ["claim_id", "value", "reason", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_relate",
        "Append a typed, unresolved relation between two current claims.",
        {
            "project": {"type": "string"}, "relation_id": {"type": "string"},
            "from_claim_id": {"type": "string"},
            "relation_type": {"type": "string", "enum": [
                "supports", "contradicts", "supersedes", "retracts", "refutes",
                "derived_from", "alternate_of", "specialization_of"
            ]},
            "to_claim_id": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 0.75, "default": 0.7},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
        },
        ["from_claim_id", "relation_type", "to_claim_id", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_evidence",
        "Attach unverified, provenance-bearing agent evidence to a current claim.",
        {
            "project": {"type": "string"}, "claim_id": {"type": "string"},
            "evidence_id": {"type": "string"}, "source_identifier": {"type": "string"},
            "source_hash": {"type": "string"}, "method": {"type": "string"},
            "polarity": {"type": "string", "enum": ["supporting", "weakening", "refuting"]},
            "confidence": {"type": "number", "minimum": 0, "maximum": 0.75},
            "uncertainty": {"type": "string"}, "provenance": {"type": "object"},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
        },
        ["claim_id", "evidence_id", "source_identifier", "method", "polarity", "confidence", "provenance", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_abstain",
        "Record why available evidence cannot support an answer without inventing a claim.",
        {
            "project": {"type": "string"}, "abstention_id": {"type": "string"},
            "query_scope": {"type": "string"},
            "missing_evidence": {"type": "array", "maxItems": 100, "items": {"type": "string"}},
            "unresolved_conflicts": {"type": "array", "maxItems": 100, "items": {"type": "string"}},
            "minimum_revalidation_action": {"type": "string"},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
        },
        ["query_scope", "missing_evidence", "unresolved_conflicts", "minimum_revalidation_action", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_validator_define",
        "Define a bounded deterministic validator. Agent MCP cannot define command validators.",
        {
            "project": {"type": "string"}, "validator_id": {"type": "string"},
            "validator_type": {"type": "string", "enum": [
                "file_exists", "file_sha256", "json_pointer_equals", "sqlite_integrity",
                "git_head_equals", "git_clean_state"
            ]},
            "claim_id": {"type": "string"}, "config": {"type": "object"},
            "failure_effect": {"type": "string", "enum": ["disputed", "stale", "refuted"]},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 0},
        },
        ["validator_id", "validator_type", "claim_id", "config", "failure_effect", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_truth_validator_run",
        "Run one deterministic registered validator. Command validators remain unavailable to agents.",
        {
            "project": {"type": "string"},
            "validator_id": {"type": "string"},
            "idempotency_key": {"type": "string"},
            "expected_version": {"type": "integer", "minimum": 1},
        },
        ["validator_id", "idempotency_key", "expected_version"],
    ),
    tool_schema(
        "brain_capture_status",
        "Read bounded passive-capture daemon, source, policy, and queue status.",
        {"project": {"type": "string"}},
    ),
    tool_schema(
        "brain_capture_events",
        "Read one redacted, payload-free page of capture observations.",
        {
            "project": {"type": "string"},
            "after_sequence": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
            "privacy_ceiling": {
                "type": "string", "enum": ["public", "internal"],
                "default": "internal",
            },
        },
    ),
    tool_schema(
        "brain_capture_replay",
        "Reconstruct a bounded chronological or causal view without executing actions.",
        {
            "project": {"type": "string"},
            "mode": {"type": "string", "enum": ["chronological", "causal"], "default": "chronological"},
            "after_sequence": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
            "privacy_ceiling": {
                "type": "string", "enum": ["public", "internal"],
                "default": "internal",
            },
        },
    ),
    tool_schema(
        "brain_capture_diagnostics",
        "Verify the capture journal and return content-free lifecycle diagnostics.",
        {"project": {"type": "string"}},
    ),
    tool_schema(
        "brain_capture_policy_create",
        "Register one immutable capture policy under an explicit capture-write grant.",
        {
            "project": {"type": "string"},
            "policy_id": {"type": "string"},
            "policy_version": {"type": "integer", "minimum": 1},
            "profile": {"type": "string", "enum": ["metadata-only", "continuity", "forensic"]},
        },
        ["policy_id", "policy_version", "profile"],
    ),
    tool_schema(
        "brain_capture_policy_retire",
        "Retire one unused immutable capture policy under an explicit capture-write grant.",
        {"project": {"type": "string"}, "policy_digest": {"type": "string"}},
        ["policy_digest"],
    ),
    tool_schema(
        "brain_capture_bind_session",
        "Bind only future ordered events from one external session to this canonical project.",
        {
            "project": {"type": "string"}, "source_id": {"type": "string"},
            "external_session_id": {"type": "string"},
            "cursor_kind": {"type": "string", "enum": ["byte-offset", "sequence"]},
            "start_cursor": {"type": "string"},
        },
        ["source_id", "external_session_id", "cursor_kind", "start_cursor"],
    ),
    tool_schema(
        "brain_capture_close_binding",
        "Close one explicit capture session binding receipt.",
        {"project": {"type": "string"}, "binding_id": {"type": "string"}},
        ["binding_id"],
    ),
    tool_schema(
        "brain_capture_source_state",
        "Pause or resume one registered capture source.",
        {
            "project": {"type": "string"}, "source_id": {"type": "string"},
            "state": {"type": "string", "enum": ["active", "paused"]},
        },
        ["source_id", "state"],
    ),
    tool_schema(
        "brain_capture_retain",
        "Preview or confirm one bounded, resumable payload-retention batch.",
        {
            "project": {"type": "string"}, "policy_digest": {"type": "string"},
            "run_id": {"type": "string"},
            "batch_size": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
            "confirm": {"type": "boolean", "default": False},
            "confirmation_token": {"type": "string"},
        },
        ["policy_digest", "run_id"],
    ),
    tool_schema(
        "brain_capture_redact",
        "Preview or confirm logical redaction of capture content while preserving integrity metadata.",
        {
            "project": {"type": "string"},
            "scope": {"type": "string", "enum": ["event-content", "session-content", "source-content", "project-content"]},
            "scope_token": {"type": "string"}, "reason_class": {"type": "string"},
            "policy_digest": {"type": "string"}, "confirm": {"type": "boolean", "default": False},
            "confirmation_token": {"type": "string"},
        },
        ["scope", "scope_token", "reason_class", "policy_digest"],
    ),
    tool_schema(
        "brain_capture_delete",
        "Preview or confirm logical capture-content deletion; journal integrity metadata remains.",
        {
            "project": {"type": "string"},
            "scope": {"type": "string", "enum": ["event-content", "session-content", "source-content", "project-content"]},
            "scope_token": {"type": "string"}, "reason_class": {"type": "string"},
            "policy_digest": {"type": "string"}, "confirm": {"type": "boolean", "default": False},
            "confirmation_token": {"type": "string"},
        },
        ["scope", "scope_token", "reason_class", "policy_digest"],
    ),
    tool_schema(
        "brain_lifecycle_inspect",
        "Inspect independent trusted lifecycle health axes or a path-free receipt review bundle without changing local state.",
        {
            "project": {"type": "string"},
            "mode": {"type": "string", "enum": ["health", "review"], "default": "health"},
            "receipt_limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 200},
        },
    ),
    tool_schema(
        "brain_capabilities",
        "Discover additional MCP capability groups and their effects without enabling them.",
        {"project": {"type": "string"}},
    ),
    tool_schema(
        "brain_doctor",
        "Return Rta-Smriti brain health and count information.",
        {"project": {"type": "string", "description": "Also evaluate task continuation readiness."}},
    ),
]

OWNER_ONLY_GOVERNANCE_TOOLS = {"brain_policy_add", "brain_policy_retire"}
MEMORY_WRITE_TOOLS = {"brain_remember", "brain_remember_batch", "brain_checkpoint", "brain_reflect"}
CONTINUITY_CONTROL_TOOLS = {"brain_continuity_control"}
REPO_INGESTION_TOOLS = {"brain_ingest_repo"}
THREAD_INGESTION_TOOLS = {"brain_ingest_thread"}
TEMPORAL_READ_TOOLS = {
    "brain_truth_current",
    "brain_truth_as_of",
    "brain_truth_history",
    "brain_truth_diff",
    "brain_truth_explain",
}
TEMPORAL_WRITE_TOOLS = {
    "brain_truth_assert", "brain_truth_state", "brain_truth_revise",
    "brain_truth_relate", "brain_truth_evidence", "brain_truth_abstain",
    "brain_truth_validator_define",
}
TEMPORAL_VALIDATOR_RUN_TOOLS = {"brain_truth_validator_run"}
CAPTURE_READ_TOOLS = {
    "brain_capture_status", "brain_capture_events",
    "brain_capture_replay", "brain_capture_diagnostics",
}
CAPTURE_WRITE_TOOLS = {
    "brain_capture_policy_create", "brain_capture_policy_retire",
    "brain_capture_bind_session", "brain_capture_close_binding",
    "brain_capture_source_state",
}
CAPTURE_DESTRUCTIVE_TOOLS = {
    "brain_capture_retain", "brain_capture_redact", "brain_capture_delete"
}
CONTEXT_DELEGATED_TOOLS = {"brain_context_compile", "brain_context_explain"}
PROJECT_BOUND_READ_TOOLS = {
    "brain_capabilities",
    "brain_retrieve",
    "brain_lifecycle_inspect",
    "brain_search",
    "brain_context_pack",
    "brain_context_compile",
    "brain_context_explain",
    "brain_repo_map",
    "brain_stale_check",
    "brain_integrity_diagnostics",
    "brain_continuation_prompt",
    "brain_graph_query",
    "brain_retrieval_diagnostics",
    "brain_policy_list",
    "brain_preflight",
    "brain_governance_receipts",
    "brain_cognition_snapshot",
    "brain_multimodal_list",
    "brain_multimodal_derivations",
    "brain_multimodal_verify",
    "brain_multimodal_export",
    *CAPTURE_READ_TOOLS,
    *TEMPORAL_READ_TOOLS,
}
CORE_READ_TOOLS = frozenset({
    "brain_capabilities",
    "brain_search",
    "brain_retrieve",
    "brain_context_pack",
    "brain_repo_map",
    "brain_stale_check",
    "brain_integrity_diagnostics",
    "brain_continuation_prompt",
    "brain_operational_readiness",
    "brain_continuity_status",
    "brain_lifecycle_inspect",
    "brain_capture_status",
})
CORE_PRIVACY_FILTERED_CONTENT_TOOLS = frozenset({
    "brain_search",
    "brain_retrieve",
})
PUBLIC_PRIVACY_AWARE_READ_TOOLS = frozenset({
    "brain_capabilities",
    "brain_search",
    "brain_retrieve",
    "brain_capture_events",
    "brain_capture_replay",
})
CORE_UNFILTERED_CONTENT_TOOLS = frozenset({
    "brain_context_pack",
    "brain_repo_map",
    "brain_stale_check",
    "brain_continuation_prompt",
    "brain_operational_readiness",
    "brain_lifecycle_inspect",
})
TOOL_BY_NAME = {tool["name"]: tool for tool in TOOLS}

MAX_MCP_FRAME_BYTES = 1_048_576
MAX_MCP_JSON_NESTING = 64
MAX_MCP_OUTSTANDING_REQUESTS = 32
MAX_MCP_OUTSTANDING_BYTES = MAX_MCP_FRAME_BYTES * 4
MAX_MCP_REDACTION_CHARS = MAX_MCP_FRAME_BYTES
MAX_MCP_REDACTION_ITEMS = MAX_MCP_FRAME_BYTES
MAX_AGENT_WORK_ITEM_METADATA_BYTES = 256_000
SUPPORTED_MCP_PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05")


def _upsert_agent_work_item(
    conn,
    *,
    project: str,
    item_type: str,
    external_id: str,
    qa_state: str,
    decision: str,
    attempt_count: int,
    fallback: str,
    next_action: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Authorize and write one MCP-owned work item under one SQLite lock."""

    metadata_json = json.dumps(
        metadata,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(metadata_json.encode("utf-8")) > MAX_AGENT_WORK_ITEM_METADATA_BYTES:
        raise ValueError("work-item metadata exceeds the 256 KB limit")
    init_continuity_schema(conn)
    conn.execute("BEGIN IMMEDIATE")
    try:
        project_row = conn.execute(
            "SELECT id FROM projects WHERE name = ?", (project,)
        ).fetchone()
        if project_row is None:
            raise ValueError(f"unknown project: {project}")
        project_id = int(project_row["id"])
        existing = conn.execute(
            "SELECT metadata_json FROM work_items WHERE project_id = ? "
            "AND item_type = ? AND external_id = ?",
            (project_id, item_type, external_id),
        ).fetchone()
        if existing is not None:
            try:
                existing_metadata = json.loads(existing["metadata_json"] or "{}")
            except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
                existing_metadata = {}
            if not isinstance(existing_metadata, dict) or existing_metadata.get(
                "_rta_authority"
            ) != "mcp-agent":
                raise PermissionError("MCP agents cannot replace an operator work item")
        conn.execute(
            """
            INSERT INTO work_items(
                project_id, item_type, external_id, local_path, qa_state, decision,
                attempt_count, fallback, next_action, metadata_json, updated_at
            )
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            ON CONFLICT(project_id, item_type, external_id) DO UPDATE SET
                local_path=NULL, qa_state=excluded.qa_state,
                decision=excluded.decision, attempt_count=excluded.attempt_count,
                fallback=excluded.fallback, next_action=excluded.next_action,
                metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
            """,
            (
                project_id,
                item_type,
                external_id,
                qa_state,
                decision,
                max(0, int(attempt_count)),
                fallback,
                next_action,
                metadata_json,
            ),
        )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return {
        "status": "ok",
        "project": project,
        "item_type": item_type,
        "external_id": external_id,
    }


def _tool_contract(name: str) -> dict[str, str]:
    schema = TOOL_BY_NAME[name]["inputSchema"]
    properties = schema.get("properties", {})
    if name in CAPTURE_DESTRUCTIVE_TOOLS:
        effect = "destructive"
    elif name in (
        MEMORY_WRITE_TOOLS
        | CONTINUITY_CONTROL_TOOLS
        | REPO_INGESTION_TOOLS
        | THREAD_INGESTION_TOOLS
        | TEMPORAL_WRITE_TOOLS
        | TEMPORAL_VALIDATOR_RUN_TOOLS
        | CAPTURE_WRITE_TOOLS
        | OWNER_ONLY_GOVERNANCE_TOOLS
    ):
        effect = "write"
    else:
        effect = "read"
    if effect == "read":
        idempotency = "safe_repeat"
        authority = "server_privacy_ceiling"
    else:
        idempotency = (
            "idempotency_key_required"
            if "idempotency_key" in properties
            else "operation_specific"
        )
        authority = "startup_capability_and_operator_policy"
    return {
        "effect": effect,
        "idempotency": idempotency,
        "authority": authority,
    }


def _agent_tool_schema(tool: dict[str, Any]) -> dict[str, Any]:
    exposed = copy.deepcopy(tool)
    properties = exposed["inputSchema"]["properties"]
    properties.pop("project", None)
    if exposed["name"] == "brain_ingest_repo":
        properties.pop("path", None)
        exposed["inputSchema"]["required"] = [
            name for name in exposed["inputSchema"].get("required", []) if name != "path"
        ]
        exposed["description"] += " Refreshes only the canonical root already bound to this project."
    if exposed["name"] in {"brain_remember", "brain_remember_batch"}:
        exposed["description"] += " Agent assertions are stored as unverified inference."
    if exposed["name"] == "brain_remember":
        properties["pramana"] = {
            "type": "string",
            "enum": ["anumana"],
            "default": "anumana",
            "description": "Agent inference; MCP cannot assert direct or verified evidence.",
        }
        properties["confidence"]["maximum"] = 0.75
        properties["provenance"] = {
            "type": "object",
            "properties": {
                "timestamp": {"type": "string"},
                "metadata": {"type": "object"},
                "verification_status": {
                    "type": "string",
                    "enum": ["unverified"],
                    "default": "unverified",
                },
            },
            "additionalProperties": False,
            "description": "Unverified agent provenance; source authority cannot be asserted over MCP.",
        }
    return exposed


def _path_is_link_or_reparse(path: Path) -> bool:
    details = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = int(getattr(details, "st_file_attributes", 0))
    return stat.S_ISLNK(details.st_mode) or bool(reparse_flag and file_attributes & reparse_flag)


def _canonical_thread_root(path: Path) -> Path:
    reject_windows_network_path(path)
    candidate = path.expanduser().absolute()
    if _path_is_link_or_reparse(candidate):
        raise ValueError(f"thread root contains a link or reparse point: {candidate}")
    resolved = candidate.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"thread root is not a directory: {resolved}")
    return resolved


def _confined_thread_path(path: Path, allowed_roots: tuple[Path, ...]) -> tuple[Path, Path]:
    reject_windows_network_path(path)
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise ValueError("thread path must be absolute")
    lexical = candidate.absolute()
    if _path_is_link_or_reparse(lexical):
        raise ValueError(f"thread path contains a link or reparse point: {lexical}")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"thread path does not exist or cannot be resolved: {lexical}") from exc
    matched_root = next(
        (root for root in allowed_roots if resolved == root or resolved.is_relative_to(root)),
        None,
    )
    if matched_root is None:
        raise ValueError(f"thread path is outside configured thread roots: {resolved}")
    try:
        _lexical_root_for_candidate(matched_root, lexical)
    except (OSError, ValueError) as exc:
        raise ValueError(f"thread path contains a link or reparse point: {lexical}") from exc
    details = resolved.lstat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"thread path is not a regular file: {resolved}")
    if int(getattr(details, "st_nlink", 1)) != 1:
        raise ValueError(f"thread path is a hardlink and cannot be ingested: {resolved}")
    return resolved, matched_root


def _agent_memory_provenance(value: Any) -> dict[str, Any]:
    if value is not None and not isinstance(value, dict):
        raise ValueError("memory provenance must be an object")
    supplied = value or {}
    metadata = supplied.get("metadata") if isinstance(supplied.get("metadata"), dict) else {}
    return {
        "command": supplied.get("command"),
        "timestamp": supplied.get("timestamp"),
        "verification_status": "unverified",
        "metadata": metadata,
    }


def _agent_memory_item(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("each memory batch item must be an object")
    item = dict(value)
    item["pramana"] = "anumana"
    item["confidence"] = min(0.75, float(item.get("confidence", 0.75)))
    item["provenance"] = _agent_memory_provenance(item.get("provenance"))
    return item


def _json_nesting_exceeds(frame: bytes, maximum: int = MAX_MCP_JSON_NESTING) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for byte in frame:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > maximum:
                return True
        elif byte in (0x5D, 0x7D):
            depth = max(0, depth - 1)
    return False


def parse_request_frame(frame: bytes) -> Any:
    if _json_nesting_exceeds(frame):
        raise ValueError(f"JSON nesting exceeds the {MAX_MCP_JSON_NESTING} level limit")
    try:
        return json.loads(frame)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds parser limits") from exc


def text_result(text: str, structured: Any | None = None) -> dict[str, Any]:
    result = {"content": [{"type": "text", "text": text}], "isError": False}
    if structured is not None:
        result["structuredContent"] = structured
    return result


def json_text(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True)


def _capture_read_privacy_ceiling(args: dict[str, Any], *, maximum: str) -> str:
    ceiling = str(args.get("privacy_ceiling", "internal")).strip().lower()
    if ceiling not in {"public", "internal"}:
        raise PermissionError(
            "MCP capture reads are limited to public or internal observations"
        )
    return _effective_privacy_ceiling(ceiling, maximum)[1]


_PRIVACY_FILTERED = object()
_MCP_REDACTION_MARKER = "[REDACTED:MCP_LOCAL_OR_SECRET]"
_MCP_CHECKPOINT_FIELDS = frozenset(
    {
        "objective",
        "verified_evidence",
        "remaining_gaps",
        "next_action",
        "prohibited_repetition",
    }
)
_MCP_JSON_STRING_FIELDS = frozenset(
    {"metadata_json", "provenance_metadata_json", "provenance_json"}
)
_MCP_CHECKPOINT_LINE = re.compile(
    r"^(\s*(?:-\s*)?(?:Objective|Verified evidence|Remaining gaps|Next action|Do not repeat):\s*).*$",
    re.IGNORECASE,
)


def _redact_mcp_continuation_prompt(value: str) -> str:
    lines = []
    for line in str(value).splitlines():
        match = _MCP_CHECKPOINT_LINE.match(line)
        lines.append(
            f"{match.group(1)}{_MCP_REDACTION_MARKER}" if match else line
        )
    return "\n".join(lines) + ("\n" if str(value).endswith("\n") else "")


def _redact_mcp_checkpoint_fields(value: Any) -> tuple[Any, int]:
    if isinstance(value, dict):
        redacted = {}
        replacements = 0
        for key, child in value.items():
            if str(key).casefold() in _MCP_CHECKPOINT_FIELDS and not isinstance(
                child, dict
            ):
                redacted[key] = _MCP_REDACTION_MARKER
                replacements += 1
            else:
                redacted[key], count = _redact_mcp_checkpoint_fields(child)
                replacements += count
        return redacted, replacements
    if isinstance(value, list):
        redacted = []
        replacements = 0
        for child in value:
            item, count = _redact_mcp_checkpoint_fields(child)
            redacted.append(item)
            replacements += count
        return redacted, replacements
    if isinstance(value, str):
        redacted = _redact_mcp_continuation_prompt(value)
        return redacted, int(redacted != value)
    return value, 0


def _redact_mcp_checkpoint_payload(
    value: Any, *, tool_name: str
) -> tuple[Any, int]:
    if not isinstance(value, dict):
        return value, 0
    container_name = {
        "brain_context_compile": "context_pack",
        "brain_operational_readiness": "latest_checkpoint",
    }.get(tool_name)
    if container_name is None or container_name not in value:
        return value, 0
    redacted = dict(value)
    redacted[container_name], replacements = _redact_mcp_checkpoint_fields(
        value[container_name]
    )
    return redacted, replacements


def _redact_mcp_json_string_fields(value: Any) -> tuple[Any, int]:
    if isinstance(value, dict):
        redacted = {}
        replacements = 0
        for key, child in value.items():
            if str(key).casefold() in _MCP_JSON_STRING_FIELDS and isinstance(
                child, str
            ):
                try:
                    decoded = json.loads(child)
                except (TypeError, json.JSONDecodeError, RecursionError):
                    decoded = None
                if isinstance(decoded, (dict, list)):
                    decoded, nested_count = _redact_mcp_json_string_fields(decoded)
                    decoded, sensitive_count = redact_sensitive_data(
                        decoded,
                        replacement=_MCP_REDACTION_MARKER,
                        max_chars=MAX_MCP_REDACTION_CHARS,
                        max_items=MAX_MCP_REDACTION_ITEMS,
                    )
                    redacted[key] = json.dumps(
                        decoded, sort_keys=True, separators=(",", ":")
                    )
                    replacements += nested_count + sensitive_count
                    continue
            redacted[key], count = _redact_mcp_json_string_fields(child)
            replacements += count
        return redacted, replacements
    if isinstance(value, list):
        redacted = []
        replacements = 0
        for child in value:
            item, count = _redact_mcp_json_string_fields(child)
            redacted.append(item)
            replacements += count
        return redacted, replacements
    return value, 0


def _declared_privacy_class(item: dict[str, Any]) -> tuple[bool, str | None]:
    if "privacy_class" in item:
        return True, _normalize_privacy_class(item.get("privacy_class"))
    metadata = item.get("metadata")
    if isinstance(metadata, dict) and "privacy_class" in metadata:
        return True, _normalize_privacy_class(metadata.get("privacy_class"))
    if "metadata_json" in item:
        try:
            metadata = json.loads(item.get("metadata_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            return True, None
        if not isinstance(metadata, dict):
            return True, None
        if "privacy_class" in metadata:
            return True, _normalize_privacy_class(metadata.get("privacy_class"))
    return False, None


def _filter_classified_value(value: Any, *, ceiling: str) -> Any:
    if isinstance(value, dict):
        declared, classification = _declared_privacy_class(value)
        if declared and (
            classification is None
            or MCP_PRIVACY_RANKS[classification] > MCP_PRIVACY_RANKS[ceiling]
        ):
            return _PRIVACY_FILTERED
        filtered = {}
        for key, child in value.items():
            visible = _filter_classified_value(child, ceiling=ceiling)
            if visible is not _PRIVACY_FILTERED:
                filtered[key] = visible
        return filtered
    if isinstance(value, list):
        filtered = []
        for child in value:
            visible = _filter_classified_value(child, ceiling=ceiling)
            if visible is not _PRIVACY_FILTERED:
                filtered.append(visible)
        return filtered
    return value


def _filter_read_result(
    result: dict[str, Any], *, ceiling: str, tool_name: str
) -> dict[str, Any]:
    if "structuredContent" not in result:
        filtered = copy.deepcopy(result)
        for item in filtered.get("content", []):
            if item.get("type") == "text":
                text = str(item.get("text", ""))
                if tool_name in {
                    "brain_context_pack",
                    "brain_continuation_prompt",
                }:
                    text = _redact_mcp_continuation_prompt(text)
                redacted, _count = redact_sensitive_text(
                    text,
                    _MCP_REDACTION_MARKER,
                    max_chars=MAX_MCP_REDACTION_CHARS,
                )
                item["text"] = redacted
        return filtered
    original = result["structuredContent"]
    structured = _filter_classified_value(original, ceiling=ceiling)
    if structured is _PRIVACY_FILTERED:
        raise PermissionError("MCP read result exceeds the server privacy ceiling")
    privacy_redacted = structured != original
    structured, checkpoint_redactions = _redact_mcp_checkpoint_payload(
        structured, tool_name=tool_name
    )
    structured, json_string_redactions = _redact_mcp_json_string_fields(structured)
    structured, secret_redactions = redact_sensitive_data(
        structured,
        replacement=_MCP_REDACTION_MARKER,
        max_chars=MAX_MCP_REDACTION_CHARS,
        max_items=MAX_MCP_REDACTION_ITEMS,
    )
    if (
        privacy_redacted
        or checkpoint_redactions
        or json_string_redactions
        or secret_redactions
    ) and isinstance(structured, dict):
        structured = {**structured, "redacted": True}
    filtered = copy.deepcopy(result)
    filtered["structuredContent"] = structured
    for item in filtered.get("content", []):
        if item.get("type") == "text":
            item["text"] = json_text(structured)
    return filtered


class RtaBrainMcpServer:
    def __init__(
        self,
        db_path: Path | None = None,
        default_project: str | None = None,
        *,
        brain_dir: Path | None = None,
        expected_root: Path | None = None,
        allow_memory_writes: bool = False,
        allow_continuity_control: bool = False,
        allow_repo_ingestion: bool = False,
        allow_thread_ingestion: bool = False,
        allow_truth_writes: bool = False,
        allow_validator_run: bool = False,
        allow_capture_writes: bool = False,
        allow_capture_destructive: bool = False,
        allowed_thread_roots: tuple[Path, ...] = (),
        context_contract_delegations: dict[int, str] | None = None,
        tool_profile: str = "full",
        maximum_privacy_ceiling: str = "internal",
        host_proof_receipt: Path | None = None,
        host_proof_challenge_token: str | None = None,
    ):
        if (db_path is None) == (brain_dir is None):
            raise ValueError("configure exactly one of db_path or brain_dir")
        self.db_path = db_path.expanduser().resolve() if db_path else None
        self.brain_dir = brain_dir.expanduser().resolve() if brain_dir else None
        self.default_project = str(default_project or "default").strip() if self.db_path else default_project
        if self.db_path is not None and not self.default_project:
            raise ValueError("default project must not be empty")
        if expected_root is not None and self.db_path is None:
            raise ValueError("an expected root is valid only in single-database MCP mode")
        if context_contract_delegations and self.db_path is None:
            raise ValueError("context contract delegation is valid only in single-database MCP mode")
        if tool_profile not in {"core", "full"}:
            raise ValueError("tool profile must be core or full")
        self.tool_profile = tool_profile
        normalized_maximum = _normalize_privacy_class(
            maximum_privacy_ceiling, request=True
        )
        assert normalized_maximum is not None
        self._maximum_privacy_ceiling = normalized_maximum
        if (host_proof_receipt is None) != (host_proof_challenge_token is None):
            raise ValueError(
                "host proof receipt and challenge token must be configured together"
            )
        if host_proof_receipt is not None and self.db_path is None:
            raise ValueError("fresh-session host proof requires single-project MCP mode")
        self._host_proof_receipt = (
            host_proof_receipt.expanduser().resolve()
            if host_proof_receipt is not None
            else None
        )
        self._host_proof_challenge_token = host_proof_challenge_token
        self._host_proof_protocol_version: str | None = None
        self._host_proof_catalog_observed = False
        self.context_contract_delegations: dict[int, str] = {}
        for raw_id, raw_digest in (context_contract_delegations or {}).items():
            if isinstance(raw_id, bool) or not isinstance(raw_id, int) or raw_id < 1:
                raise ValueError("context contract delegation IDs must be positive integers")
            digest = str(raw_digest).strip().casefold()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("context contract delegation digests must be a 64-character SHA-256")
            self.context_contract_delegations[raw_id] = digest
        self.expected_root = expected_root.expanduser().resolve() if expected_root else None
        self.context_principal_id = "mcp-agent"
        self.context_session_id = f"mcp-{secrets.token_hex(16)}"
        self.progressive_retriever = ProgressiveRetriever(secrets.token_bytes(32))
        self.expected_binding_token: tuple[str, str, str] | None = None
        if self.db_path is not None:
            conn = connect(self.db_path)
            try:
                binding = project_binding_status(conn, self.default_project, self.expected_root)
                row = conn.execute(
                    "SELECT root_path, repository_identity, checkout_identity FROM projects WHERE name = ?",
                    (self.default_project,),
                ).fetchone()
            finally:
                conn.close()
            if not binding["ready"] or not row or not all(
                row[key] for key in ("root_path", "repository_identity", "checkout_identity")
            ):
                raise ValueError(
                    f"active checkout mismatch ({binding['state']}); regenerate the MCP configuration after verifying the canonical root"
                )
            bound_root = Path(str(row["root_path"])).expanduser().resolve()
            if self.expected_root is None:
                self.expected_root = bound_root
            self.expected_binding_token = (
                str(bound_root), str(row["repository_identity"]), str(row["checkout_identity"]),
            )
        self.allowed_thread_roots = tuple(_canonical_thread_root(root) for root in allowed_thread_roots)
        if allow_thread_ingestion and not self.allowed_thread_roots:
            raise ValueError("thread ingestion requires at least one configured thread root")
        if self.brain_dir is not None:
            enabled = set(PROJECT_BOUND_READ_TOOLS) - CONTEXT_DELEGATED_TOOLS
        else:
            enabled = set(PROJECT_BOUND_READ_TOOLS)
            enabled.update({"brain_session_events", "brain_reconcile", "brain_operational_readiness", "brain_continuity_status"})
            if not self.context_contract_delegations:
                enabled.difference_update(CONTEXT_DELEGATED_TOOLS)
        if allow_memory_writes:
            enabled.update(MEMORY_WRITE_TOOLS)
            enabled.update({"brain_session_event", "brain_work_item"})
        if allow_continuity_control:
            if self.db_path is None:
                raise ValueError("continuity control requires a single-project MCP binding")
            enabled.update(CONTINUITY_CONTROL_TOOLS)
        if allow_repo_ingestion:
            enabled.update(REPO_INGESTION_TOOLS)
        if allow_thread_ingestion:
            enabled.update(THREAD_INGESTION_TOOLS)
            enabled.add("brain_ingest_codex_session")
        if allow_truth_writes:
            enabled.update(TEMPORAL_WRITE_TOOLS)
        if allow_validator_run:
            if not allow_truth_writes:
                raise ValueError("validator execution requires truth writes to be enabled")
            enabled.update(TEMPORAL_VALIDATOR_RUN_TOOLS)
        if allow_capture_writes:
            if self.db_path is None:
                raise ValueError("capture writes require a single-project MCP binding")
            enabled.update(CAPTURE_WRITE_TOOLS)
        if allow_capture_destructive:
            if self.db_path is None:
                raise ValueError("destructive capture controls require a single-project MCP binding")
            enabled.update(CAPTURE_DESTRUCTIVE_TOOLS)
        if self.tool_profile == "core":
            enabled.intersection_update(CORE_READ_TOOLS)
            enabled.add("brain_capabilities")
        self.enabled_tools = frozenset(enabled)
        self.agent_tools = [
            (gateway_tool_schema(TOOL_BY_NAME[name]) if self.brain_dir is not None else _agent_tool_schema(TOOL_BY_NAME[name]))
            for name in TOOL_BY_NAME if name in enabled
        ]

    def _record_host_proof_event(
        self,
        *,
        tool_name: str,
        status: str,
        project: str,
        capability: str | None = None,
    ) -> None:
        if self._host_proof_receipt is None:
            return
        if not self._host_proof_protocol_version or not self._host_proof_catalog_observed:
            raise PermissionError(
                "functional MCP proof requires initialize and tools/list before tool calls"
            )
        observed_capability = capability
        if (
            tool_name == "brain_capabilities"
            and status == "ok"
            and not (set(self.enabled_tools) & MUTATING_TOOLS)
        ):
            observed_capability = "mutating-tools-disabled"
        record_server_observed_tool_event(
            self._host_proof_receipt,
            str(self._host_proof_challenge_token),
            {
                "fresh_session_id": self.context_session_id,
                "host_version": f"mcp-protocol:{self._host_proof_protocol_version}",
                "proof_semantics": "functional_protocol_observation",
                "host_identity_attested": False,
                "tool_names": sorted(self.enabled_tools),
                "tool_name": tool_name,
                "status": status,
                "project": project,
                "capability": observed_capability,
            },
        )

    @property
    def maximum_privacy_ceiling(self) -> str:
        return self._maximum_privacy_ceiling

    def _require_context_contract_delegation(self, conn, task_contract_id: int) -> None:
        delegated_digest = self.context_contract_delegations.get(int(task_contract_id))
        if delegated_digest is None:
            raise PermissionError("context contract is not delegated to this MCP server process")
        row = conn.execute(
            """
            SELECT tc.digest
            FROM task_contracts tc
            JOIN projects p ON p.id = tc.project_id
            WHERE tc.id = ? AND p.name = ? AND tc.authorization_state = 'operator_authorized'
            """,
            (int(task_contract_id), self.default_project),
        ).fetchone()
        if row is None or not hmac.compare_digest(str(row["digest"]), delegated_digest):
            raise PermissionError("delegated context contract does not match the authorized project contract")

    def _context_compilation_contract_id(self, conn, compilation_id: str) -> int:
        row = conn.execute(
            """
            SELECT c.task_contract_id
            FROM context_compilations c
            JOIN projects p ON p.id = c.project_id
            WHERE c.compilation_id = ? AND p.name = ?
            """,
            (str(compilation_id).strip(), self.default_project),
        ).fetchone()
        if row is None:
            raise ValueError("unknown project context compilation")
        return int(row["task_contract_id"])

    def _bound_project(self, args: dict[str, Any]) -> str:
        requested = args.get("project")
        if requested is not None and str(requested).strip() != self.default_project:
            raise ValueError(
                f"MCP server is bound to project '{self.default_project}'; client project overrides are rejected"
            )
        return self.default_project

    def _bound_repository_root(self, conn, args: dict[str, Any], project: str | None = None) -> Path:
        project_name = project or self.default_project
        row = conn.execute(
            "SELECT root_path FROM projects WHERE name = ?", (project_name,),
        ).fetchone()
        if not row or not row["root_path"]:
            raise ValueError(
                f"project '{project_name}' has no canonical repository root; bootstrap it before MCP ingestion"
            )
        root = Path(str(row["root_path"])).expanduser().resolve()
        requested = args.get("path")
        if requested is not None and Path(str(requested)).expanduser().resolve() != root:
            raise ValueError(
                f"repository ingestion is confined to the canonical project root: {root}"
            )
        return root

    def _open_project(self, project: str | None):
        if self.db_path is not None:
            if not self.default_project:
                raise ValueError("single-database MCP mode requires a default project")
            requested = str(project or self.default_project).strip()
            if requested != self.default_project:
                raise ValueError(
                    f"MCP server is bound to project '{self.default_project}'; client project overrides are rejected"
                )
            conn = connect(self.db_path)
            binding = project_binding_status(conn, self.default_project, self.expected_root)
            row = conn.execute(
                "SELECT root_path, repository_identity, checkout_identity FROM projects WHERE name = ?",
                (self.default_project,),
            ).fetchone()
            token = (
                str(Path(str(row["root_path"])).expanduser().resolve()),
                str(row["repository_identity"]),
                str(row["checkout_identity"]),
            ) if row and all(row[key] for key in ("root_path", "repository_identity", "checkout_identity")) else None
            if not binding["ready"] or token != self.expected_binding_token:
                conn.close()
                raise ValueError(
                    f"active checkout mismatch ({binding['state']}); regenerate the MCP configuration after verifying the canonical root"
                )
            return conn, self.db_path, self.default_project
        if not project:
            raise ValueError("project is required when using the multi-project brain gateway")
        if not self.brain_dir or not self.brain_dir.is_dir() or self.brain_dir.is_symlink():
            raise ValueError("brain directory is not a safe directory")
        matches = []
        for candidate in self.brain_dir.glob("*.sqlite"):
            if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_nlink > 1:
                continue
            before = candidate.stat()
            conn = connect(candidate)
            after = candidate.stat()
            if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
                conn.close()
                raise ValueError("brain database changed identity while routing the MCP call")
            if conn.execute("SELECT 1 FROM projects WHERE name = ?", (str(project),)).fetchone():
                matches.append((conn, candidate.resolve()))
            else:
                conn.close()
        if not matches:
            raise ValueError(f"unknown project in brain directory: {project}")
        if len(matches) > 1:
            for conn, _path in matches:
                conn.close()
            raise ValueError(f"project name is ambiguous across brain databases: {project}")
        conn, path = matches[0]
        return conn, path, str(project)

    def call_tool(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        args = arguments or {}
        if name not in TOOL_BY_NAME:
            raise KeyError(f"unknown tool: {name}")
        if name not in self.enabled_tools:
            raise ValueError(f"MCP tool '{name}' is not enabled by server startup capabilities")
        guard = (
            McpBindingLease(self.db_path, self.default_project)
            if self.db_path is not None else nullcontext()
        )
        with guard:
            conn, db_path, project = self._open_project(args.get("project") or self.default_project)
            try:
                result = self._call_tool_with_connection(
                    conn, name, args, db_path=db_path, resolved_project=project
                )
                if _tool_contract(name)["effect"] == "read":
                    return _filter_read_result(
                        result,
                        ceiling=self.maximum_privacy_ceiling,
                        tool_name=name,
                    )
                return result
            finally:
                conn.close()

    def _call_tool_with_connection(
        self, conn, name: str, args: dict[str, Any], *, db_path: Path, resolved_project: str
    ) -> dict[str, Any]:
        project = resolved_project
        if (
            _tool_contract(name)["effect"] == "read"
            and MCP_PRIVACY_RANKS[self.maximum_privacy_ceiling]
            < MCP_PRIVACY_RANKS["internal"]
            and name not in PUBLIC_PRIVACY_AWARE_READ_TOOLS
        ):
            raise PermissionError(
                f"MCP tool '{name}' requires an internal-or-higher server privacy ceiling"
            )
        if (
            name in CORE_UNFILTERED_CONTENT_TOOLS
            and MCP_PRIVACY_RANKS[self.maximum_privacy_ceiling]
            < MCP_PRIVACY_RANKS["internal"]
        ):
            raise PermissionError(
                f"MCP tool '{name}' requires an internal-or-higher server privacy ceiling"
            )
        if name in OWNER_ONLY_GOVERNANCE_TOOLS:
            raise ValueError("governance policy mutation requires an owner-controlled CLI or dashboard session")
        if name == "brain_preflight" and args.get("override_reason"):
            raise ValueError("governance override requires an owner-controlled CLI or dashboard session")
        if name == "brain_preflight" and args.get("completed_checks"):
            raise ValueError("governance check attestation requires an owner-controlled CLI or dashboard session")
        if name == "brain_capabilities":
            groups = {
                "core_read": {
                    "effect": "read",
                    "approval_required": False,
                    "tools": sorted(CORE_READ_TOOLS),
                },
                "extended_read": {
                    "effect": "read",
                    "approval_required": True,
                    "tools": sorted(
                        PROJECT_BOUND_READ_TOOLS - CORE_READ_TOOLS - TEMPORAL_READ_TOOLS
                    ),
                },
                "temporal_read": {
                    "effect": "read",
                    "approval_required": True,
                    "tools": sorted(TEMPORAL_READ_TOOLS - CORE_READ_TOOLS),
                },
                "memory_write": {
                    "effect": "write",
                    "approval_required": True,
                    "tools": sorted(MEMORY_WRITE_TOOLS),
                },
                "repository_ingestion": {
                    "effect": "write",
                    "approval_required": True,
                    "tools": sorted(REPO_INGESTION_TOOLS | THREAD_INGESTION_TOOLS),
                },
                "temporal_write": {
                    "effect": "write",
                    "approval_required": True,
                    "tools": sorted(TEMPORAL_WRITE_TOOLS | TEMPORAL_VALIDATOR_RUN_TOOLS),
                },
                "capture_write": {
                    "effect": "write",
                    "approval_required": True,
                    "tools": sorted(CAPTURE_WRITE_TOOLS),
                },
                "capture_destructive": {
                    "effect": "destructive",
                    "approval_required": True,
                    "tools": sorted(CAPTURE_DESTRUCTIVE_TOOLS),
                },
            }
            payload = {
                "status": "ok",
                "active_profile": self.tool_profile,
                "enabled_tool_count": len(self.enabled_tools),
                "maximum_privacy_ceiling": self.maximum_privacy_ceiling,
                "capability_groups": groups,
                "tool_contracts": {
                    tool_name: _tool_contract(tool_name)
                    for tool_name in sorted(self.enabled_tools)
                },
                "activation": "restart_or_host_tool_refresh_required",
            }
            return text_result(json_text(payload), payload)
        if name == "brain_search":
            requested, effective, limited = _effective_privacy_ceiling(
                args.get("privacy_ceiling", "internal"),
                self.maximum_privacy_ceiling,
            )
            payload = search(
                conn,
                str(args["query"]),
                project=project,
                limit=int(args.get("limit", 8)),
            )
            payload = _filter_search_payload(
                conn,
                payload,
                project=project,
                requested_ceiling=requested,
                effective_ceiling=effective,
                maximum_ceiling=self.maximum_privacy_ceiling,
                request_limited=limited,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_retrieve":
            requested, effective, limited = _effective_privacy_ceiling(
                args.get("privacy_ceiling", "internal"),
                self.maximum_privacy_ceiling,
            )
            payload = self.progressive_retriever.retrieve(
                conn,
                project=project,
                stage=str(args["stage"]),
                query=args.get("query"),
                expansion_handle=args.get("expansion_handle"),
                limit=int(args.get("limit", 8)),
                max_tokens=int(args.get("max_tokens", 4_000)),
                privacy_ceiling=effective,
            )
            payload["privacy"] = {
                "requested_ceiling": requested,
                "maximum_ceiling": self.maximum_privacy_ceiling,
                "effective_ceiling": effective,
                "request_limited": limited,
                "unknown_classes": "filtered",
            }
            return text_result(json_text(payload), payload)
        if name == "brain_context_pack":
            text = build_context_pack(
                conn, str(args["task"]), project=project, limit=int(args.get("limit", 8)),
                max_tokens=int(args.get("max_tokens", 4_000)),
                privacy_ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(text)
        if name == "brain_context_compile":
            task_contract_id = int(args["task_contract_id"])
            self._require_context_contract_delegation(conn, task_contract_id)
            payload = compile_context_for_agent(
                conn,
                db_path=db_path,
                project=project,
                active_root=self._bound_repository_root(conn, {}, project),
                task_contract_id=task_contract_id,
                principal_id=self.context_principal_id,
                session_id=self.context_session_id,
                variant_id=str(args.get("variant", "primary")),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_context_explain":
            self._require_context_contract_delegation(
                conn,
                self._context_compilation_contract_id(conn, str(args["compilation_id"])),
            )
            payload = explain_context_for_agent(
                conn,
                db_path=db_path,
                project=project,
                compilation_id=str(args["compilation_id"]),
                principal_id=self.context_principal_id,
                session_id=self.context_session_id,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_remember":
            payload = remember(
                conn,
                str(args["text"]),
                project=project,
                memory_type=str(args.get("type", "fact")),
                pramana="anumana",
                confidence=min(0.75, float(args.get("confidence", 0.75))),
                priority=int(args.get("priority", 5)),
                provenance=_agent_memory_provenance(args.get("provenance")),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_remember_batch":
            payload = remember_many(conn, [_agent_memory_item(item) for item in args["items"]], project=project)
            return text_result(json_text(payload), payload)
        if name == "brain_ingest_repo":
            root = self._bound_repository_root(conn, args, project)
            force = bool(args.get("force", False))
            repair_deep_stale = bool(args.get("repair_deep_stale", False))
            if not force and not repair_deep_stale:
                freshness = stale_check(conn, project=project, detail_limit=0)
                if freshness.get("state") in {"fresh", "fresh_with_warnings"}:
                    payload = {
                        "status": "ok",
                        "project": project,
                        "root": str(root),
                        "state": freshness.get("state"),
                        "indexed_files": int(freshness.get("fresh") or 0),
                        "updated_files": 0,
                        "unchanged_files": int(freshness.get("fresh") or 0),
                        "removed_files": 0,
                        "skipped_files": 0,
                        "blocked_files": int(freshness.get("uninspectable") or 0),
                        "metadata_only_files": int(freshness.get("metadata_only") or 0),
                        "manifest_unchanged": True,
                        "mcp_short_circuit": True,
                        "freshness": freshness,
                    }
                    return text_result(json_text(payload), payload)
            payload = ingest_repo(
                conn,
                root,
                project=project,
                force=force,
                repair_deep_stale=repair_deep_stale,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_ingest_thread":
            if not self.allowed_thread_roots:
                raise ValueError("thread ingestion roots are not configured for this MCP server")
            thread_path, thread_root = _confined_thread_path(
                Path(str(args["path"])), self.allowed_thread_roots,
            )
            payload = ingest_thread(
                conn, thread_path, project=project, title=args.get("title"), root=thread_root,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_repo_map":
            payload = graph(conn, project=project, limit=int(args.get("limit", 100)))
            return text_result(json_text(payload), payload)
        if name == "brain_graph_query":
            payload = graph_query(
                conn, project=project, query_type=str(args.get("query_type", "impact")),
                target=str(args["target"]), depth=int(args.get("depth", 2)), limit=int(args.get("limit", 100)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_retrieval_diagnostics":
            payload = retrieval_diagnostics(
                conn, str(args["query"]), project=project, limit=int(args.get("limit", 8)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_cognition_snapshot":
            payload = cognition_snapshot(
                conn, project=project, active_root=self.expected_root,
                include_change_impact=bool(args.get("include_change_impact", True)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_multimodal_list":
            payload = list_multimodal_evidence(
                conn, project=project, limit=int(args.get("limit", 100)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_multimodal_derivations":
            payload = list_multimodal_derivations(
                conn, project=project, source_id=str(args["source_id"]),
                include_text=False, limit=int(args.get("limit", 100)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_multimodal_verify":
            payload = verify_multimodal_source(
                conn,
                project=project,
                active_root=self._bound_repository_root(conn, {}, project),
                source_id=str(args["source_id"]),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_multimodal_export":
            payload = export_multimodal_manifest(
                conn,
                project=project,
                audience=str(args.get("audience", "local")),
                limit=int(args.get("limit", 1000)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_workspace_search":
            payload = search_workspace(
                conn, workspace=str(args["workspace"]), query=str(args["query"]),
                limit_per_project=int(args.get("limit_per_project", 4)),
                privacy_ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_workspace_list":
            payload = get_workspace(conn, str(args["workspace"])) if args.get("workspace") else list_workspaces(conn)
            return text_result(json_text(payload), payload)
        if name == "brain_workspace_health":
            payload = workspace_health(conn, str(args["workspace"]))
            return text_result(json_text(payload), payload)
        if name == "brain_stale_check":
            if self.brain_dir is not None and bool(args.get("rehash", False)):
                raise ValueError(
                    "hash-cache mutation is disabled in the read-only gateway"
                )
            payload = stale_check(
                conn,
                project=project,
                deep=bool(args.get("deep", False) or args.get("rehash", False)),
                refresh_hashes=bool(args.get("rehash", False)),
                detail_limit=int(args.get("detail_limit", 50)),
                include_fresh_details=bool(args.get("include_fresh_details", False)),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_integrity_diagnostics":
            payload = integrity_diagnostics(
                conn, project=project, active_root=self.expected_root,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_checkpoint":
            payload = save_checkpoint(
                conn,
                project=project,
                objective=str(args["objective"]),
                verified_evidence=str(args.get("verified_evidence", "")),
                remaining_gaps=str(args.get("remaining_gaps", "")),
                next_action=str(args.get("next_action", "")),
                prohibited_repetition=str(args.get("prohibited_repetition", "")),
                expected_version=args.get("expected_version"),
                source="agent",
                trigger="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_continuation_prompt":
            return text_result(_redact_mcp_continuation_prompt(
                build_continuation_prompt(conn, project=project)
            ))
        if name == "brain_session_event":
            payload = append_event(
                conn, project, str(args["session_id"]), str(args["cursor"]),
                str(args["event_type"]), dict(args["payload"]),
                source="mcp-agent", verification_status="unverified",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_session_events":
            payload = list_events(conn, project, session_id=args.get("session_id"), limit=int(args.get("limit", 100)))
            return text_result(json_text(payload), payload)
        if name == "brain_ingest_codex_session":
            row = conn.execute("SELECT root_path FROM projects WHERE name = ?", (project,)).fetchone()
            if not row or not row["root_path"]:
                raise ValueError("project has no canonical root for transcript ingestion")
            session_path = Path(str(args["path"]))
            session_id = validate_codex_session_binding(
                session_path, Path.home() / ".codex" / "sessions", Path(row["root_path"]),
            )
            payload = ingest_codex_session(
                conn, session_path, project,
                session_id=session_id, max_events=int(args.get("max_events", 5000)),
                expected_project_root=Path(row["root_path"]),
                expected_sessions_root=Path.home() / ".codex" / "sessions",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_work_item":
            qa_state = str(args.get("qa_state", "unknown")).strip().casefold()
            decision = str(args.get("decision", "pending")).strip().casefold()
            if str(args.get("local_path") or "").strip():
                raise ValueError(
                    "agent work-item local paths require separate operator authority"
                )
            if qa_state not in {"unknown", "pending", "failed", "blocked"}:
                raise ValueError("agent work-item QA state is not permitted")
            if decision not in {"pending", "blocked", "rejected"}:
                raise ValueError("agent work-item decision is not permitted")
            item_type = str(args["item_type"])
            external_id = str(args["external_id"])
            supplied_metadata = args.get("metadata")
            if supplied_metadata is not None and not isinstance(supplied_metadata, dict):
                raise ValueError("agent work-item metadata must be an object")
            metadata = dict(supplied_metadata or {})
            metadata["_rta_authority"] = "mcp-agent"
            metadata["_rta_verification_status"] = "unverified"
            payload = _upsert_agent_work_item(
                conn,
                project=project,
                item_type=item_type,
                external_id=external_id,
                qa_state=qa_state,
                decision=decision,
                attempt_count=int(args.get("attempt_count", 0)),
                fallback=str(args.get("fallback", "")),
                next_action=str(args.get("next_action", "")),
                metadata=metadata,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_reconcile":
            payload = reconcile_work_items(conn, project)
            return text_result(json_text(payload), payload)
        if name == "brain_operational_readiness":
            lifecycle = public_continuity_status(continuity_status(db_path, project))
            payload = operational_readiness(
                conn, project, lifecycle=lifecycle,
                active_root=self.expected_root,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_continuity_status":
            payload = public_continuity_status(continuity_status(db_path, project))
            return text_result(json_text(payload), payload)
        if name == "brain_lifecycle_inspect":
            row = conn.execute(
                "SELECT root_path FROM projects WHERE name = ?",
                (project,),
            ).fetchone()
            if not row or not row["root_path"]:
                raise ValueError("project has no canonical root for lifecycle inspection")
            request = {
                "tool_root": Path(__file__).resolve().parents[1],
                "brain_dir": db_path.parent,
                "db_path": db_path,
                "project": project,
                "root": self.expected_root or Path(str(row["root_path"])),
                "sessions_root": Path.home() / ".codex" / "sessions",
            }
            payload = (
                lifecycle_review_bundle(
                    request, receipt_limit=int(args.get("receipt_limit", 200))
                )
                if str(args.get("mode") or "health") == "review"
                else inspect_lifecycle(request)
            )
            return text_result(json_text(payload), payload)
        if name == "brain_continuity_control":
            action = str(args["action"])
            if action == "stop":
                payload = stop_continuity(db_path, project)
            elif action == "start":
                row = conn.execute("SELECT root_path FROM projects WHERE name = ?", (project,)).fetchone()
                if not row or not row["root_path"]:
                    raise ValueError("project has no canonical root for continuity capture")
                payload = start_continuity(
                    db_path,
                    Path(row["root_path"]),
                    project,
                    Path.home() / ".codex" / "sessions",
                    interval_seconds=float(args.get("interval", 5.0)),
                    inactivity_seconds=float(args.get("inactivity", 900.0)),
                )
            else:
                raise ValueError("continuity action must be start or stop")
            payload = public_continuity_status(payload)
            return text_result(json_text(payload), payload)
        if name == "brain_reflect":
            payload = reflect(conn, project=project)
            return text_result(json_text(payload), payload)
        if name == "brain_policy_add":
            payload = create_policy(
                conn,
                project=project,
                kind=str(args["kind"]),
                statement=str(args["statement"]),
                effect=str(args.get("effect", "warn")),
                action_contains=str(args.get("action_contains", "")),
                path_glob=str(args.get("path_glob", "")),
                required_check=str(args.get("required_check", "")),
                pramana=str(args.get("pramana", "smriti")),
                confidence=float(args.get("confidence", 0.75)),
                provenance=args.get("provenance"),
                overrideable=bool(args.get("overrideable", True)),
                expires_at=args.get("expires_at"),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_policy_list":
            payload = list_policies(conn, project=project, include_retired=bool(args.get("include_retired", False)))
            return text_result(json_text(payload), payload)
        if name == "brain_policy_retire":
            payload = retire_policy(
                conn, project=project, policy_id=int(args["policy_id"]), reason=str(args["reason"]),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_preflight":
            payload = preflight(
                conn,
                project=project,
                action=str(args["action"]),
                path=args.get("path"),
                completed_checks=[],
                override_reason=None,
                actor="agent",
                operational_context=(
                    build_operational_context(conn, project, db_path=db_path)
                    if bool(args.get("include_operational_context", True)) else None
                ),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_governance_receipts":
            payload = list_receipts(conn, project=project, limit=int(args.get("limit", 100)))
            return text_result(json_text(payload), payload)
        if name in CAPTURE_READ_TOOLS | CAPTURE_WRITE_TOOLS | CAPTURE_DESTRUCTIVE_TOOLS:
            active_root = self._bound_repository_root(conn, {}, project)
        if name == "brain_capture_status":
            payload = capture_status_report(
                conn, database=db_path, project=project,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_events":
            payload = export_capture_events(
                conn, project=project, active_root=active_root,
                after_sequence=int(args.get("after_sequence", 0)),
                limit=int(args.get("limit", 100)),
                privacy_ceiling=_capture_read_privacy_ceiling(
                    args, maximum=self.maximum_privacy_ceiling
                ),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_replay":
            payload = capture_replay(
                conn, project=project, active_root=active_root,
                mode=str(args.get("mode", "chronological")),
                after_sequence=int(args.get("after_sequence", 0)),
                limit=int(args.get("limit", 100)),
                privacy_ceiling=_capture_read_privacy_ceiling(
                    args, maximum=self.maximum_privacy_ceiling
                ),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_diagnostics":
            payload = capture_diagnostics(
                conn, database=db_path, project=project, active_root=active_root,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_policy_create":
            profile = str(args["profile"])
            policy = (
                CapturePolicy.metadata_only()
                if profile == "metadata-only"
                else CapturePolicy.continuity()
                if profile == "continuity"
                else CapturePolicy(profile="forensic")
            )
            payload = register_capture_policy(
                conn, project=project, active_root=active_root,
                policy_id=str(args["policy_id"]),
                policy_version=int(args["policy_version"]), policy=policy,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_policy_retire":
            payload = retire_capture_policy(
                conn, project=project, active_root=active_root,
                policy_digest=str(args["policy_digest"]),
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_bind_session":
            payload = bind_capture_session(
                conn, database=db_path, project=project, active_root=active_root,
                source_id=str(args["source_id"]),
                external_session_id=str(args["external_session_id"]),
                cursor_kind=str(args["cursor_kind"]),
                start_cursor=str(args["start_cursor"]),
                operator_id="mcp-delegated-operator",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_close_binding":
            payload = close_session_binding(
                conn, database=db_path, project=project, active_root=active_root,
                binding_id=str(args["binding_id"]),
                operator_id="mcp-delegated-operator",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_source_state":
            selected_state = str(args["state"]).lower()
            if selected_state not in {"active", "paused"}:
                raise ValueError("MCP capture sources can only be active or paused")
            payload = set_capture_source_state(
                conn, project=project, active_root=active_root,
                source_id=str(args["source_id"]), state=selected_state,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_capture_retain":
            payload = control_capture_retention(
                conn, project=project, active_root=active_root,
                policy_digest=str(args["policy_digest"]), run_id=str(args["run_id"]),
                batch_size=int(args.get("batch_size", 100)),
                actor_id="mcp-delegated-operator",
                confirm=bool(args.get("confirm", False)),
                confirmation_token=args.get("confirmation_token"),
            )
            return text_result(json_text(payload), payload)
        if name in {"brain_capture_redact", "brain_capture_delete"}:
            payload = delete_capture_content(
                conn, project=project, active_root=active_root,
                scope=str(args["scope"]), scope_token=str(args["scope_token"]),
                reason_class=str(args["reason_class"]),
                actor_id="mcp-delegated-operator",
                policy_digest=str(args["policy_digest"]),
                confirm=bool(args.get("confirm", False)),
                confirmation_token=args.get("confirmation_token"),
                secure_compact=False,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_current":
            payload = _filter_truth_counterparts(
                conn,
                redact_truth_for_operator(truth_current(
                    conn,
                    project=project,
                    claim_id=str(args["claim_id"]),
                    valid_at=args.get("valid_at"),
                )),
                project=project,
                ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_as_of":
            payload = _filter_truth_counterparts(
                conn,
                redact_truth_for_operator(truth_as_of(
                    conn,
                    project=project,
                    claim_id=str(args["claim_id"]),
                    valid_at=str(args["valid_at"]),
                    recorded_sequence=int(args["recorded_sequence"]),
                )),
                project=project,
                ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_history":
            payload = _filter_truth_counterparts(
                conn,
                redact_truth_for_operator(truth_history(
                    conn,
                    project=project,
                    claim_id=str(args["claim_id"]),
                    limit=int(args.get("limit", 100)),
                )),
                project=project,
                ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_diff":
            payload = _filter_truth_counterparts(
                conn,
                redact_truth_for_operator(truth_diff(
                    conn,
                    project=project,
                    from_sequence=int(args["from_sequence"]),
                    to_sequence=int(args["to_sequence"]),
                    valid_at=str(args["valid_at"]),
                    limit=int(args.get("limit", 100)),
                )),
                project=project,
                ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_explain":
            payload = _filter_truth_counterparts(
                conn,
                redact_truth_for_operator(truth_explain(
                    conn,
                    project=project,
                    claim_id=str(args["claim_id"]),
                    valid_at=args.get("valid_at"),
                )),
                project=project,
                ceiling=self.maximum_privacy_ceiling,
            )
            return text_result(json_text(payload), payload)
        if (
            name in TEMPORAL_WRITE_TOOLS | TEMPORAL_VALIDATOR_RUN_TOOLS
            and self.expected_root is None
        ):
            raise ValueError("temporal writes require a single-project canonical root binding")
        if name == "brain_truth_assert":
            selected_state = str(args.get("epistemic_state", "observed")).strip().lower()
            if selected_state not in {"hypothesis", "observed"}:
                raise ValueError("agent truth assertions may only be hypothesis or observed, never accepted")
            payload = append_claim(
                conn,
                project=project,
                active_root=self.expected_root,
                claim_id=args.get("claim_id"),
                subject=str(args["subject"]),
                predicate=str(args["predicate"]),
                value=args["value"],
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                valid_from=args.get("valid_from"),
                valid_to=args.get("valid_to"),
                expires_at=args.get("expires_at"),
                epistemic_state=selected_state,
                authority_class="agent-proposal",
                confidence=min(0.75, float(args.get("confidence", 0.75))),
                verification_status="unverified",
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_state":
            selected_state = str(args["state"]).strip().lower()
            if selected_state == "accepted":
                raise ValueError("accepted truth requires an owner-controlled CLI or dashboard session")
            payload = change_claim_state(
                conn,
                project=project,
                active_root=self.expected_root,
                claim_id=str(args["claim_id"]),
                new_state=selected_state,
                reason=str(args["reason"]),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_revise":
            payload = revise_claim(
                conn,
                project=project,
                active_root=self.expected_root,
                claim_id=str(args["claim_id"]),
                value=args["value"],
                reason=str(args["reason"]),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                valid_from=args.get("valid_from"),
                valid_to=args.get("valid_to"),
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_relate":
            payload = relate_claims(
                conn,
                project=project,
                active_root=self.expected_root,
                relation_id=args.get("relation_id"),
                from_claim_id=str(args["from_claim_id"]),
                relation_type=str(args["relation_type"]),
                to_claim_id=str(args["to_claim_id"]),
                confidence=min(0.75, float(args.get("confidence", 0.7))),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_evidence":
            payload = attach_evidence(
                conn,
                project=project,
                active_root=self.expected_root,
                claim_id=str(args["claim_id"]),
                evidence_id=str(args["evidence_id"]),
                source_identifier=str(args["source_identifier"]),
                source_hash=args.get("source_hash"),
                method=str(args["method"]),
                polarity=str(args["polarity"]),
                authority_class="agent-observation",
                confidence=min(0.75, float(args["confidence"])),
                uncertainty=str(args.get("uncertainty", "")),
                provenance=dict(args["provenance"]),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                verification_status="unverified",
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_abstain":
            payload = record_abstention(
                conn,
                project=project,
                active_root=self.expected_root,
                abstention_id=args.get("abstention_id"),
                query_scope=str(args["query_scope"]),
                missing_evidence=list(args["missing_evidence"]),
                unresolved_conflicts=list(args["unresolved_conflicts"]),
                minimum_revalidation_action=str(args["minimum_revalidation_action"]),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_validator_define":
            selected_type = str(args["validator_type"]).strip().lower()
            if selected_type == "command_exit":
                raise ValueError("agents cannot define command validators")
            payload = define_validator(
                conn,
                project=project,
                active_root=self.expected_root,
                validator_id=str(args["validator_id"]),
                validator_type=selected_type,
                claim_id=str(args["claim_id"]),
                config=dict(args["config"]),
                failure_effect=str(args["failure_effect"]),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_truth_validator_run":
            payload = run_validator(
                conn,
                project=project,
                active_root=self.expected_root,
                validator_id=str(args["validator_id"]),
                idempotency_key=str(args["idempotency_key"]),
                expected_stream_version=int(args["expected_version"]),
                allow_command=False,
                trusted_executables=(),
                actor_type="agent",
                actor_id="mcp-agent",
                source="mcp",
            )
            return text_result(json_text(payload), payload)
        if name == "brain_doctor":
            payload = doctor(conn)
            if project:
                lifecycle = public_continuity_status(continuity_status(db_path, project))
                payload["operational"] = operational_readiness(
                    conn, project, lifecycle=lifecycle,
                    active_root=self.expected_root,
                )
            return text_result(json_text(payload), payload)
        raise KeyError(f"unknown tool: {name}")

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return self.error(None, -32600, "invalid request: JSON-RPC frame must be an object")
        method = request.get("method")
        request_id = request.get("id")
        notification = "id" not in request
        respond = lambda payload: None if notification else payload
        if request.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return respond(self.error(request_id, -32600, "invalid request: jsonrpc must be '2.0' and method must be a string"))
        try:
            if method == "initialize":
                params = request.get("params") or {}
                if not isinstance(params, dict):
                    raise ValueError("initialize params must be an object")
                requested_version = params.get("protocolVersion")
                negotiated_version = (
                    requested_version
                    if requested_version in SUPPORTED_MCP_PROTOCOL_VERSIONS
                    else SUPPORTED_MCP_PROTOCOL_VERSIONS[0]
                )
                if self._host_proof_receipt is not None:
                    self._host_proof_protocol_version = negotiated_version
                return respond({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": negotiated_version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "rta-smriti-brain", "version": __version__},
                    },
                })
            if method == "tools/list":
                if self._host_proof_receipt is not None:
                    if not self._host_proof_protocol_version:
                        raise PermissionError(
                            "functional MCP proof requires initialize before tools/list"
                        )
                    self._host_proof_catalog_observed = True
                return respond({"jsonrpc": "2.0", "id": request_id, "result": {"tools": self.agent_tools}})
            if method == "tools/call":
                params = request.get("params") or {}
                if not isinstance(params, dict):
                    raise ValueError("tools/call params must be an object")
                name = params.get("name")
                if not name:
                    raise ValueError("tools/call requires params.name")
                arguments = params.get("arguments") or {}
                if not isinstance(arguments, dict):
                    raise ValueError("tools/call arguments must be an object")
                selected_name = str(name)
                proof_project = str(
                    arguments.get("project") or self.default_project or ""
                )
                try:
                    result = self.call_tool(selected_name, arguments)
                except Exception:
                    denied = (
                        selected_name in TOOL_BY_NAME
                        and selected_name not in self.enabled_tools
                    )
                    self._record_host_proof_event(
                        tool_name=selected_name,
                        status="denied" if denied else "error",
                        project=proof_project,
                        capability=selected_name if denied else None,
                    )
                    raise
                self._record_host_proof_event(
                    tool_name=selected_name,
                    status="ok",
                    project=proof_project,
                )
                return respond({"jsonrpc": "2.0", "id": request_id, "result": result})
            if method == "ping":
                return respond({"jsonrpc": "2.0", "id": request_id, "result": {}})
            return respond(self.error(request_id, -32601, f"method not found: {method}"))
        except KeyError as exc:
            return respond(self.error(request_id, -32601, str(exc).strip("'")))
        except Exception as exc:  # noqa: BLE001 - JSON-RPC boundary serializes tool failures
            return respond(self.error(request_id, -32000, str(exc), {"type": exc.__class__.__name__}))

    async def handle_async(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Keep stdio responsive while SQLite, parsing, hashing, or embedding work runs."""
        if isinstance(request, dict) and request.get("method") == "tools/call":
            return await asyncio.to_thread(self.handle, request)
        return self.handle(request)

    @staticmethod
    def error(request_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
        if data is not None:
            payload["error"]["data"] = data
        return payload


MUTATING_TOOLS = {
    "brain_remember",
    "brain_remember_batch",
    "brain_ingest_repo",
    "brain_ingest_thread",
    "brain_checkpoint",
    "brain_session_event",
    "brain_ingest_codex_session",
    "brain_work_item",
    "brain_continuity_control",
    "brain_reflect",
    "brain_context_compile",
    "brain_context_explain",
    *CAPTURE_WRITE_TOOLS,
    *CAPTURE_DESTRUCTIVE_TOOLS,
    *TEMPORAL_WRITE_TOOLS,
    *TEMPORAL_VALIDATOR_RUN_TOOLS,
}


def _tool_name(request: dict[str, Any]) -> str | None:
    if not isinstance(request, dict) or request.get("method") != "tools/call":
        return None
    params = request.get("params")
    return str(params.get("name")) if isinstance(params, dict) and params.get("name") else None


class McpRequestScheduler:
    """Run blocking tool calls concurrently while preserving mutation causality."""

    def __init__(
        self,
        server: RtaBrainMcpServer,
        emit: Callable[[dict[str, Any]], Awaitable[None]],
        max_concurrency: int = 4,
        max_outstanding: int = MAX_MCP_OUTSTANDING_REQUESTS,
        max_outstanding_bytes: int = MAX_MCP_OUTSTANDING_BYTES,
    ) -> None:
        self.server = server
        self.emit = emit
        self.capacity = asyncio.Semaphore(max(1, int(max_concurrency)))
        self.max_outstanding = max(1, int(max_outstanding))
        self.max_outstanding_bytes = max(1, int(max_outstanding_bytes))
        self._admission = asyncio.Condition()
        self._outstanding = 0
        self._outstanding_bytes = 0
        self.peak_outstanding = 0
        self.peak_outstanding_bytes = 0
        self.pending: set[asyncio.Task] = set()
        self.latest_mutation: asyncio.Task | None = None

    async def _process(self, request: Any, dependency: asyncio.Task | None) -> None:
        if dependency is not None:
            await dependency
        async with self.capacity:
            response = await self.server.handle_async(request)
        if response is not None:
            await self.emit(response)

    async def _release(self, frame_bytes: int) -> None:
        async with self._admission:
            self._outstanding -= 1
            self._outstanding_bytes -= frame_bytes
            self._admission.notify_all()

    async def _process_and_release(
        self, request: Any, dependency: asyncio.Task | None, frame_bytes: int
    ) -> None:
        try:
            await self._process(request, dependency)
        finally:
            await self._release(frame_bytes)

    async def submit(self, request: Any, frame_bytes: int = 0) -> None:
        frame_bytes = max(0, int(frame_bytes))
        if frame_bytes > self.max_outstanding_bytes:
            raise ValueError("request exceeds the scheduler byte limit")
        async with self._admission:
            await self._admission.wait_for(
                lambda: self._outstanding < self.max_outstanding
                and self._outstanding_bytes + frame_bytes <= self.max_outstanding_bytes
            )
            self._outstanding += 1
            self._outstanding_bytes += frame_bytes
            self.peak_outstanding = max(self.peak_outstanding, self._outstanding)
            self.peak_outstanding_bytes = max(self.peak_outstanding_bytes, self._outstanding_bytes)
        tool_name = _tool_name(request)
        is_mutation = tool_name in MUTATING_TOOLS
        is_tool_call = isinstance(request, dict) and request.get("method") == "tools/call"
        dependency = self.latest_mutation if (is_mutation or is_tool_call) else None
        task = asyncio.create_task(self._process_and_release(request, dependency, frame_bytes))
        if is_mutation:
            self.latest_mutation = task
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)

    async def close(self) -> None:
        if self.pending:
            await asyncio.gather(*tuple(self.pending))


async def serve_stdio_async(
    db_path: Path | None,
    default_project: str | None,
    *,
    brain_dir: Path | None = None,
    expected_root: Path | None = None,
    allow_memory_writes: bool = False,
    allow_continuity_control: bool = False,
    allow_repo_ingestion: bool = False,
    allow_thread_ingestion: bool = False,
    allow_truth_writes: bool = False,
    allow_validator_run: bool = False,
    allow_capture_writes: bool = False,
    allow_capture_destructive: bool = False,
    allowed_thread_roots: tuple[Path, ...] = (),
    context_contract_delegations: dict[int, str] | None = None,
    tool_profile: str = "core",
    maximum_privacy_ceiling: str = "internal",
    host_proof_receipt: Path | None = None,
    host_proof_challenge_token: str | None = None,
) -> int:
    server = RtaBrainMcpServer(
        db_path=db_path,
        default_project=default_project,
        brain_dir=brain_dir,
        expected_root=expected_root,
        allow_memory_writes=allow_memory_writes,
        allow_continuity_control=allow_continuity_control,
        allow_repo_ingestion=allow_repo_ingestion,
        allow_thread_ingestion=allow_thread_ingestion,
        allow_truth_writes=allow_truth_writes,
        allow_validator_run=allow_validator_run,
        allow_capture_writes=allow_capture_writes,
        allow_capture_destructive=allow_capture_destructive,
        allowed_thread_roots=allowed_thread_roots,
        context_contract_delegations=context_contract_delegations,
        tool_profile=tool_profile,
        maximum_privacy_ceiling=maximum_privacy_ceiling,
        host_proof_receipt=host_proof_receipt,
        host_proof_challenge_token=host_proof_challenge_token,
    )
    stream = sys.stdin.buffer
    write_lock = asyncio.Lock()

    async def emit(response: dict[str, Any]) -> None:
        async with write_lock:
            print(json.dumps(response, separators=(",", ":")), flush=True)

    scheduler = McpRequestScheduler(server, emit, max_concurrency=4)

    lease = McpBindingLease(server.db_path, server.default_project) if server.db_path is not None else nullcontext()
    with lease:
        if server.db_path is not None:
            startup_conn, _startup_path, _startup_project = server._open_project(server.default_project)
            startup_conn.close()
        while True:
            line = await asyncio.to_thread(stream.readline, MAX_MCP_FRAME_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MCP_FRAME_BYTES:
                while line and not line.endswith(b"\n"):
                    line = await asyncio.to_thread(stream.readline, MAX_MCP_FRAME_BYTES + 1)
                response = RtaBrainMcpServer.error(None, -32600, f"request frame exceeds {MAX_MCP_FRAME_BYTES} bytes")
                await emit(response)
                continue
            if not line.strip():
                continue
            try:
                request = parse_request_frame(line)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError, MemoryError) as exc:
                response = RtaBrainMcpServer.error(None, -32700, f"parse error: {exc}")
                await emit(response)
            else:
                await scheduler.submit(request, frame_bytes=len(line))
        await scheduler.close()
    return 0


def serve_stdio(
    db_path: Path | None,
    default_project: str | None,
    *,
    brain_dir: Path | None = None,
    expected_root: Path | None = None,
    allow_memory_writes: bool = False,
    allow_continuity_control: bool = False,
    allow_repo_ingestion: bool = False,
    allow_thread_ingestion: bool = False,
    allow_truth_writes: bool = False,
    allow_validator_run: bool = False,
    allow_capture_writes: bool = False,
    allow_capture_destructive: bool = False,
    allowed_thread_roots: tuple[Path, ...] = (),
    context_contract_delegations: dict[int, str] | None = None,
    tool_profile: str = "core",
    maximum_privacy_ceiling: str = "internal",
    host_proof_receipt: Path | None = None,
    host_proof_challenge_token: str | None = None,
) -> int:
    return asyncio.run(serve_stdio_async(
        db_path,
        default_project,
        brain_dir=brain_dir,
        expected_root=expected_root,
        allow_memory_writes=allow_memory_writes,
        allow_continuity_control=allow_continuity_control,
        allow_repo_ingestion=allow_repo_ingestion,
        allow_thread_ingestion=allow_thread_ingestion,
        allow_truth_writes=allow_truth_writes,
        allow_validator_run=allow_validator_run,
        allow_capture_writes=allow_capture_writes,
        allow_capture_destructive=allow_capture_destructive,
        allowed_thread_roots=allowed_thread_roots,
        context_contract_delegations=context_contract_delegations,
        tool_profile=tool_profile,
        maximum_privacy_ceiling=maximum_privacy_ceiling,
        host_proof_receipt=host_proof_receipt,
        host_proof_challenge_token=host_proof_challenge_token,
    ))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rta-brain-mcp", description="Rta-Smriti Brain MCP stdio server")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--db", help="Path to one SQLite brain file")
    source.add_argument("--brain-dir", help="Directory of project-scoped SQLite brain files")
    parser.add_argument("--project", help="Default project memory bank for single-database mode")
    parser.add_argument("--root", help="Expected canonical checkout root pinned by the generated MCP configuration")
    parser.add_argument(
        "--tool-profile",
        choices=("core", "full"),
        default=None,
        help=(
            "Expose the bounded progressive core or the complete permitted tool catalog; "
            "defaults to core unless an explicit capability flag is supplied"
        ),
    )
    parser.add_argument(
        "--maximum-privacy-ceiling",
        choices=("public", "internal", "sensitive", "restricted", "private"),
        default="internal",
        help="Immutable maximum privacy class available to this server process",
    )
    parser.add_argument(
        "--allow-memory-writes", action="store_true",
        help="Allow agent-authored memories, checkpoints, and reflection (disabled by default)",
    )
    parser.add_argument(
        "--allow-continuity-control", action="store_true",
        help="Allow starting and stopping the project continuity worker (disabled by default)",
    )
    parser.add_argument(
        "--allow-repo-ingestion", action="store_true",
        help="Allow repository ingestion (disabled by default)",
    )
    parser.add_argument(
        "--allow-thread-ingestion", action="store_true",
        help="Allow thread ingestion from explicitly configured roots (disabled by default)",
    )
    parser.add_argument(
        "--allow-thread-root", action="append", default=[], metavar="PATH",
        help="Canonical directory allowed for thread ingestion; may be repeated",
    )
    parser.add_argument(
        "--allow-truth-writes", action="store_true",
        help="Allow agent-authored hypothesis/observed temporal truth events (disabled by default)",
    )
    parser.add_argument(
        "--allow-validator-run", action="store_true",
        help="Allow deterministic non-command truth validators; requires --allow-truth-writes",
    )
    parser.add_argument(
        "--allow-capture-writes", action="store_true",
        help="Allow delegated capture policy, binding, lifecycle, and retention controls",
    )
    parser.add_argument(
        "--allow-capture-destructive", action="store_true",
        help="Allow preview-bound capture retention, redaction, and deletion controls",
    )
    parser.add_argument(
        "--context-contract", action="append", default=[], metavar="ID:DIGEST",
        help="Delegate one operator-authorized context contract to this MCP process; may be repeated",
    )
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.brain_dir and (
        args.root or args.allow_memory_writes or args.allow_continuity_control
        or args.allow_repo_ingestion
        or args.allow_thread_ingestion or args.allow_thread_root
        or args.allow_truth_writes or args.allow_validator_run or args.context_contract
        or args.allow_capture_writes or args.allow_capture_destructive
    ):
        parser.error("root and capability flags are only valid with --db single-project mode")
    if args.allow_thread_ingestion and not args.allow_thread_root:
        parser.error("--allow-thread-ingestion requires at least one --allow-thread-root")
    if args.allow_validator_run and not args.allow_truth_writes:
        parser.error("--allow-validator-run requires --allow-truth-writes")
    context_contract_delegations: dict[int, str] = {}
    for value in args.context_contract:
        match = re.fullmatch(r"([1-9][0-9]*):([0-9A-Fa-f]{64})", str(value).strip())
        if match is None:
            parser.error("--context-contract must use ID:DIGEST with a positive ID and 64-character SHA-256")
        contract_id = int(match.group(1))
        if contract_id in context_contract_delegations:
            parser.error(f"--context-contract ID {contract_id} is duplicated")
        context_contract_delegations[contract_id] = match.group(2).casefold()
    capability_requested = any((
        args.allow_memory_writes,
        args.allow_continuity_control,
        args.allow_repo_ingestion,
        args.allow_thread_ingestion,
        args.allow_truth_writes,
        args.allow_validator_run,
        args.allow_capture_writes,
        args.allow_capture_destructive,
        bool(context_contract_delegations),
    ))
    tool_profile = args.tool_profile or ("full" if capability_requested else "core")
    host_proof_receipt_raw = os.environ.get(
        "RTA_SMRITI_HOST_PROOF_RECEIPT", ""
    ).strip()
    host_proof_token = os.environ.get(
        "RTA_SMRITI_HOST_PROOF_CHALLENGE", ""
    ).strip()
    if bool(host_proof_receipt_raw) != bool(host_proof_token):
        parser.error(
            "fresh-session proof environment requires both receipt and challenge"
        )
    return serve_stdio(
        Path(args.db) if args.db else None,
        args.project,
        brain_dir=Path(args.brain_dir) if args.brain_dir else None,
        expected_root=Path(args.root) if args.root else None,
        allow_memory_writes=args.allow_memory_writes,
        allow_continuity_control=args.allow_continuity_control,
        allow_repo_ingestion=args.allow_repo_ingestion,
        allow_thread_ingestion=args.allow_thread_ingestion,
        allow_truth_writes=args.allow_truth_writes,
        allow_validator_run=args.allow_validator_run,
        allow_capture_writes=args.allow_capture_writes,
        allow_capture_destructive=args.allow_capture_destructive,
        allowed_thread_roots=tuple(Path(root) for root in args.allow_thread_root),
        context_contract_delegations=context_contract_delegations,
        tool_profile=tool_profile,
        maximum_privacy_ceiling=args.maximum_privacy_ceiling,
        host_proof_receipt=(
            Path(host_proof_receipt_raw) if host_proof_receipt_raw else None
        ),
        host_proof_challenge_token=host_proof_token or None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
