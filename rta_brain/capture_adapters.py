"""Deterministic vendor-event normalization for the universal capture bus."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import tempfile
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .capture_spool import capture_control_root_path, ensure_capture_control_root
from .capture_types import CapturePolicy, NormalizedEvent, canonical_json
from .privacy import is_sensitive_field_name, redact_sensitive_text
from .runtime_control import (
    is_safe_regular_file,
    prepare_control_dir,
    read_json,
    write_json,
)

_MAX_ATTRIBUTE_DEPTH = 12
_REDACTION_LOOKAHEAD_CHARS = 4_096
_NORMALIZER_SCHEMA_VERSION = "3"


@dataclass(frozen=True)
class AdapterRule:
    event_name: str
    fields: Mapping[str, tuple[str, ...]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_name": self.event_name,
            "fields": {
                name: list(paths) for name, paths in sorted(self.fields.items())
            },
        }


@dataclass(frozen=True)
class AdapterDefinition:
    name: str
    version: str
    rules: Mapping[str, AdapterRule]

    @property
    def schema_fingerprint(self) -> str:
        schema = {
            "name": self.name,
            "version": self.version,
            "normalizer_schema_version": _NORMALIZER_SCHEMA_VERSION,
            "rules": {
                name: rule.as_dict() for name, rule in sorted(self.rules.items())
            },
        }
        return hashlib.sha256(canonical_json(schema).encode("ascii")).hexdigest()


def _vendor_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _field_paths(*names: str) -> tuple[str, ...]:
    return tuple(names)


_STANDARD_FIELDS: dict[str, Mapping[str, tuple[str, ...]]] = {
    "session.started.v1": {
        "status": _field_paths("status"),
        "reason": _field_paths("reason"),
    },
    "session.resumed.v1": {
        "status": _field_paths("status"),
        "reason": _field_paths("reason"),
    },
    "session.ended.v1": {
        "status": _field_paths("status"),
        "reason": _field_paths("reason", "stop_reason"),
        "summary": _field_paths("summary"),
    },
    "turn.started.v1": {"status": _field_paths("status")},
    "turn.completed.v1": {
        "status": _field_paths("status"),
        "summary": _field_paths("summary", "prompt_response", "last_assistant_message"),
    },
    "turn.interrupted.v1": {
        "reason": _field_paths("reason", "error"),
        "summary": _field_paths("summary", "message"),
    },
    "turn.compacted.v1": {"summary": _field_paths("summary", "message")},
    "prompt.submitted.v1": {
        "text": _field_paths("text", "prompt", "content"),
        "role": _field_paths("role"),
    },
    "agent.message.v1": {
        "text": _field_paths("text", "message", "content"),
        "role": _field_paths("role"),
        "event_kind": _field_paths("type"),
    },
    "user.decision.v1": {
        "text": _field_paths("text", "message", "content"),
        "decision": _field_paths("decision"),
    },
    "user.approval.v1": {
        "text": _field_paths("text", "message", "content"),
        "decision": _field_paths("decision", "approved"),
        "scope": _field_paths("scope"),
    },
    "tool.requested.v1": {
        "tool": _field_paths("tool", "tool_name", "toolName", "name"),
        "status": _field_paths("status", "tool_status"),
        "call_id": _field_paths("call_id", "tool_call_id", "tool_use_id", "toolUseId"),
    },
    "tool.started.v1": {
        "tool": _field_paths("tool", "tool_name", "toolName", "name"),
        "status": _field_paths("status", "tool_status"),
        "call_id": _field_paths("call_id", "tool_call_id", "tool_use_id", "toolUseId"),
    },
    "tool.completed.v1": {
        "tool": _field_paths("tool", "tool_name", "toolName", "name"),
        "status": _field_paths(
            "status", "tool_status", "tool_result.result_type", "toolResult.resultType"
        ),
        "summary": _field_paths(
            "summary",
            "tool_response",
            "tool_output",
            "tool_result.text_result_for_llm",
            "toolResult.textResultForLlm",
            "tool_response.llmContent",
            "output",
        ),
        "duration_ms": _field_paths("duration_ms", "duration"),
        "call_id": _field_paths("call_id", "tool_call_id", "tool_use_id", "toolUseId"),
        "metadata": _field_paths("metadata"),
    },
    "tool.failed.v1": {
        "tool": _field_paths("tool", "tool_name", "toolName", "name"),
        "status": _field_paths("status", "tool_status"),
        "error_class": _field_paths(
            "error_class",
            "error_type",
            "failure_type",
            "tool_response.error.type",
            "tool_response.error.name",
        ),
        "summary": _field_paths(
            "summary",
            "error",
            "error_message",
            "tool_response.error.message",
            "tool_response.error",
            "message",
            "output",
        ),
        "duration_ms": _field_paths("duration_ms", "duration"),
        "call_id": _field_paths("call_id", "tool_call_id", "tool_use_id", "toolUseId"),
    },
    "command.started.v1": {
        "command": _field_paths("command", "command_name"),
        "status": _field_paths("status"),
    },
    "command.completed.v1": {
        "command": _field_paths("command", "command_name"),
        "exit_code": _field_paths("exit_code", "exitCode"),
        "summary": _field_paths("summary", "output"),
        "duration_ms": _field_paths("duration_ms", "duration"),
    },
    "file.read.v1": {
        "path": _field_paths("relative_path", "path", "file_path", "filePath")
    },
    "file.edited.v1": {
        "path": _field_paths("relative_path", "path", "file_path", "filePath"),
        "status": _field_paths("status"),
    },
    "mcp.requested.v1": {
        "tool": _field_paths("tool", "tool_name", "name"),
        "server": _field_paths("server", "server_name"),
        "call_id": _field_paths("call_id"),
    },
    "mcp.completed.v1": {
        "tool": _field_paths("tool", "tool_name", "name"),
        "server": _field_paths("server", "server_name"),
        "status": _field_paths("status"),
        "summary": _field_paths("summary", "output"),
        "call_id": _field_paths("call_id"),
    },
    "adapter.error.v1": {
        "error_class": _field_paths("error_class", "error_type"),
        "summary": _field_paths("summary", "error", "message"),
        "status": _field_paths("status"),
    },
}

_METADATA_ONLY_FIELDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "session.started.v1": frozenset({"status", "reason"}),
        "session.resumed.v1": frozenset({"status", "reason"}),
        "session.ended.v1": frozenset({"status", "reason"}),
        "turn.started.v1": frozenset({"status"}),
        "turn.completed.v1": frozenset({"status"}),
        "turn.interrupted.v1": frozenset(),
        "turn.compacted.v1": frozenset(),
        "prompt.submitted.v1": frozenset(),
        "agent.message.v1": frozenset(),
        "user.decision.v1": frozenset(),
        "user.approval.v1": frozenset({"decision"}),
        "tool.requested.v1": frozenset({"tool", "status", "call_id"}),
        "tool.started.v1": frozenset({"tool", "status", "call_id"}),
        "tool.completed.v1": frozenset({"tool", "status", "duration_ms", "call_id"}),
        "tool.failed.v1": frozenset(
            {"tool", "status", "error_class", "duration_ms", "call_id"}
        ),
        "command.started.v1": frozenset({"status"}),
        "command.completed.v1": frozenset({"exit_code", "duration_ms"}),
        "file.read.v1": frozenset(),
        "file.edited.v1": frozenset({"status"}),
        "mcp.requested.v1": frozenset({"tool", "server", "call_id"}),
        "mcp.completed.v1": frozenset({"tool", "server", "status", "call_id"}),
        "adapter.error.v1": frozenset({"error_class", "status"}),
    }
)


def capture_attribute_allowlist(
    policy: CapturePolicy,
    event_name: str,
) -> frozenset[str]:
    """Return the exact normalized attribute keys permitted by one policy."""

    if event_name in policy.field_allowlist:
        return frozenset(policy.field_allowlist[event_name])
    return _METADATA_ONLY_FIELDS.get(event_name, frozenset())


def _rules(aliases: Mapping[str, str]) -> Mapping[str, AdapterRule]:
    return MappingProxyType(
        {
            _vendor_key(vendor_name): AdapterRule(
                event_name,
                MappingProxyType(dict(_STANDARD_FIELDS.get(event_name, {}))),
            )
            for vendor_name, event_name in aliases.items()
        }
    )


_GENERIC_ALIASES = {
    "session_start": "session.started.v1",
    "session_resume": "session.resumed.v1",
    "session_stop": "session.ended.v1",
    "turn_start": "turn.started.v1",
    "turn_complete": "turn.completed.v1",
    "turn_interrupt": "turn.interrupted.v1",
    "turn_compact": "turn.compacted.v1",
    "prompt": "prompt.submitted.v1",
    "agent_message": "agent.message.v1",
    "decision": "user.decision.v1",
    "approval": "user.approval.v1",
    "tool_request": "tool.requested.v1",
    "tool_start": "tool.started.v1",
    "tool_complete": "tool.completed.v1",
    "tool_error": "tool.failed.v1",
    "command_start": "command.started.v1",
    "command_complete": "command.completed.v1",
    "file_read": "file.read.v1",
    "file_edit": "file.edited.v1",
    "mcp_request": "mcp.requested.v1",
    "mcp_complete": "mcp.completed.v1",
    "error": "adapter.error.v1",
}


@lru_cache(maxsize=1)
def adapter_catalog() -> Mapping[str, AdapterDefinition]:
    definitions = {
        "generic": AdapterDefinition("generic", "1", _rules(_GENERIC_ALIASES)),
        "codex-jsonl": AdapterDefinition(
            "codex-jsonl",
            "1",
            _rules(
                {
                    "session_meta": "session.started.v1",
                    "turn_context": "turn.started.v1",
                    "user_message": "prompt.submitted.v1",
                    "assistant_message": "agent.message.v1",
                    "tool_request": "tool.requested.v1",
                    "tool_complete": "tool.completed.v1",
                    "tool_error": "tool.failed.v1",
                    "agent_event": "agent.message.v1",
                }
            ),
        ),
        "claude-code": AdapterDefinition(
            "claude-code",
            "hooks-v1",
            _rules(
                {
                    "SessionStart": "session.started.v1",
                    "UserPromptSubmit": "prompt.submitted.v1",
                    "PreToolUse": "tool.requested.v1",
                    "PostToolUse": "tool.completed.v1",
                    "PostToolUseFailure": "tool.failed.v1",
                    "PreCompact": "turn.compacted.v1",
                    "Stop": "turn.completed.v1",
                    "StopFailure": "turn.interrupted.v1",
                    "SessionEnd": "session.ended.v1",
                    "Notification": "agent.message.v1",
                }
            ),
        ),
        "cursor": AdapterDefinition(
            "cursor",
            "hooks-v1",
            _rules(
                {
                    "sessionStart": "session.started.v1",
                    "beforeSubmitPrompt": "prompt.submitted.v1",
                    "sessionEnd": "session.ended.v1",
                    "preCompact": "turn.compacted.v1",
                    "preToolUse": "tool.requested.v1",
                    "postToolUse": "tool.completed.v1",
                    "postToolUseFailure": "tool.failed.v1",
                    "beforeReadFile": "file.read.v1",
                    "beforeShellExecution": "command.started.v1",
                    "afterShellExecution": "command.completed.v1",
                    "beforeMCPExecution": "mcp.requested.v1",
                    "afterMCPExecution": "mcp.completed.v1",
                    "afterFileEdit": "file.edited.v1",
                    "stop": "turn.completed.v1",
                    "afterAgentResponse": "agent.message.v1",
                }
            ),
        ),
        "github-copilot": AdapterDefinition(
            "github-copilot",
            "hooks-v1",
            _rules(
                {
                    "sessionStart": "session.started.v1",
                    "SessionStart": "session.started.v1",
                    "sessionEnd": "session.ended.v1",
                    "SessionEnd": "session.ended.v1",
                    "userPromptSubmitted": "prompt.submitted.v1",
                    "UserPromptSubmit": "prompt.submitted.v1",
                    "preToolUse": "tool.requested.v1",
                    "PreToolUse": "tool.requested.v1",
                    "postToolUse": "tool.completed.v1",
                    "PostToolUse": "tool.completed.v1",
                    "postToolUseFailure": "tool.failed.v1",
                    "PostToolUseFailure": "tool.failed.v1",
                    "preCompact": "turn.compacted.v1",
                    "PreCompact": "turn.compacted.v1",
                    "agentStop": "turn.completed.v1",
                    "Stop": "turn.completed.v1",
                    "errorOccurred": "adapter.error.v1",
                }
            ),
        ),
        "gemini-cli": AdapterDefinition(
            "gemini-cli",
            "hooks-v1",
            _rules(
                {
                    "SessionStart": "session.started.v1",
                    "BeforeAgent": "turn.started.v1",
                    "BeforeTool": "tool.requested.v1",
                    "AfterTool": "tool.completed.v1",
                    "AfterAgent": "turn.completed.v1",
                    "PreCompress": "turn.compacted.v1",
                    "SessionEnd": "session.ended.v1",
                    "Notification": "agent.message.v1",
                }
            ),
        ),
    }
    return MappingProxyType(definitions)


def _value_at(payload: Mapping[str, Any], dotted_path: str) -> Any:
    value: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _bounded_sanitize(
    value: Any,
    policy: CapturePolicy,
    *,
    key: str | None = None,
    depth: int = 1,
    remaining: list[int] | None = None,
) -> Any:
    if depth > _MAX_ATTRIBUTE_DEPTH:
        raise ValueError("capture adapter attributes exceed the depth limit")
    if key is not None and is_sensitive_field_name(key, include_containers=True):
        return "[REDACTED]"
    budget = remaining if remaining is not None else [policy.max_collection_items]
    if isinstance(value, Mapping):
        sanitized = {}
        iterator = iter(value.items())
        while budget[0] > 0:
            try:
                child_key, child = next(iterator)
            except StopIteration:
                break
            budget[0] -= 1
            raw_key = str(child_key)
            sanitized_key = redact_sensitive_text(raw_key)[0]
            if is_sensitive_field_name(raw_key, include_containers=True):
                sanitized_key = "[REDACTED]"
            if sanitized_key in sanitized:
                raise ValueError("capture adapter key collision after sanitization")
            sanitized[sanitized_key] = _bounded_sanitize(
                child,
                policy,
                key=raw_key,
                depth=depth + 1,
                remaining=budget,
            )
        return sanitized
    if isinstance(value, (list, tuple)):
        sanitized_items = []
        iterator = iter(value)
        while budget[0] > 0:
            try:
                child = next(iterator)
            except StopIteration:
                break
            budget[0] -= 1
            sanitized_items.append(
                _bounded_sanitize(child, policy, depth=depth + 1, remaining=budget)
            )
        return sanitized_items
    if isinstance(value, str):
        scan_limit = policy.max_field_chars + _REDACTION_LOOKAHEAD_CHARS
        redacted = redact_sensitive_text(value[:scan_limit])[0]
        if len(value) > policy.max_field_chars:
            marker = "\n[TRUNCATED]"
            return redacted[: policy.max_field_chars - len(marker)] + marker
        return redacted
    if value is None or type(value) in {bool, int, float}:
        return value
    return redact_sensitive_text(str(value))[0][: policy.max_field_chars]


def _opaque_reference(adapter_name: str, field_name: str, value: Any) -> str | None:
    if value is None:
        return None
    encoded = str(value).encode("utf-8")
    return hashlib.sha256(
        b"rta-smriti-capture-reference-v1\0"
        + adapter_name.encode("ascii")
        + b"\0"
        + field_name.encode("ascii")
        + b"\0"
        + encoded
    ).hexdigest()


def _scoped_relative_path(
    value: Any,
    maximum: int,
    trusted_workspace_roots: tuple[str, ...],
) -> str | None:
    raw = str(value).strip().replace("\\", "/")
    if not raw or "\0" in raw:
        return None
    drive_prefixed = bool(re.match(r"^[A-Za-z]:", raw))
    drive_absolute = bool(re.match(r"^[A-Za-z]:/", raw))
    if (drive_prefixed and not drive_absolute) or ":" in (
        raw[2:] if drive_absolute else raw
    ):
        return None
    is_absolute = raw.startswith("/") or drive_absolute
    if is_absolute:
        relative = None
        for root_value in trusted_workspace_roots[:32]:
            root = str(root_value).strip().replace("\\", "/").rstrip("/")
            if not root:
                continue
            windows_path = drive_absolute or raw.startswith("//")
            compared_raw = raw.casefold() if windows_path else raw
            compared_root = root.casefold() if windows_path else root
            prefix = compared_root + "/"
            if compared_raw.startswith(prefix):
                relative = raw[len(root) + 1 :]
                break
        if relative is None:
            return None
        raw = relative
    parts = [part for part in raw.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    selected = "/".join(parts)[:maximum]
    return redact_sensitive_text(selected)[0]


def _event_kind(
    adapter_name: str,
    payload: Mapping[str, Any],
    configured_event: str | None = None,
) -> str:
    if configured_event is not None:
        return _vendor_key(configured_event)
    if adapter_name == "codex-jsonl":
        outer = _vendor_key(payload.get("type"))
        body = payload.get("payload")
        body = body if isinstance(body, Mapping) else payload
        if outer == "responseitem":
            role = _vendor_key(body.get("role"))
            item_type = _vendor_key(body.get("type"))
            if role == "user":
                return "usermessage"
            if role == "assistant":
                return "assistantmessage"
            if item_type in {"functioncall", "customtoolcall"}:
                return "toolrequest"
            if item_type in {"functioncalloutput", "customtoolcalloutput"}:
                return (
                    "toolerror"
                    if _vendor_key(body.get("status")) == "failed"
                    else "toolcomplete"
                )
        if outer == "eventmsg":
            return "agentevent"
        return outer
    for key in ("hook_event_name", "event_name", "event", "type"):
        if payload.get(key) is not None:
            return _vendor_key(payload[key])
    return ""


def _event_body(adapter_name: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
    if adapter_name == "codex-jsonl" and isinstance(payload.get("payload"), Mapping):
        return payload["payload"]
    return payload


def _specialize_rule(
    adapter_name: str,
    vendor_event: str,
    rule: AdapterRule | None,
    body: Mapping[str, Any],
) -> AdapterRule | None:
    if rule is None:
        return None
    if (
        rule.event_name == "session.started.v1"
        and _vendor_key(body.get("source")) == "resume"
    ):
        return AdapterRule(
            "session.resumed.v1",
            MappingProxyType(dict(_STANDARD_FIELDS["session.resumed.v1"])),
        )
    if (
        adapter_name == "gemini-cli"
        and vendor_event == "aftertool"
        and _value_at(body, "tool_response.error") is not None
    ):
        return AdapterRule(
            "tool.failed.v1",
            MappingProxyType(dict(_STANDARD_FIELDS["tool.failed.v1"])),
        )
    return rule


def normalize_capture_event(
    adapter_name: str,
    payload: Mapping[str, Any],
    *,
    vendor_event: str | None = None,
    trusted_workspace_roots: tuple[str, ...] = (),
    adapter_version: str | None = None,
    source_cursor: str,
    observed_at: str,
    session_id: str,
    policy: CapturePolicy | None = None,
) -> NormalizedEvent | None:
    if not isinstance(payload, Mapping):
        raise TypeError("capture adapter payload must be a mapping")
    if not isinstance(trusted_workspace_roots, tuple):
        raise TypeError("trusted workspace roots must be a tuple")
    if len(trusted_workspace_roots) > 32 or any(
        not isinstance(root, str)
        or not root.strip()
        or len(root) > 4_096
        or "\0" in root
        for root in trusted_workspace_roots
    ):
        raise ValueError(
            "trusted workspace roots are invalid or exceed the configured limit"
        )
    catalog = adapter_catalog()
    if adapter_name not in catalog:
        raise ValueError(f"unsupported capture adapter: {adapter_name}")
    definition = catalog[adapter_name]
    if adapter_version is not None and adapter_version != definition.version:
        raise ValueError(
            f"capture adapter version mismatch: expected {definition.version}"
        )
    selected_policy = policy or CapturePolicy.continuity()
    selected_vendor_event = _event_kind(adapter_name, payload, vendor_event)
    body = _event_body(adapter_name, payload)
    rule = _specialize_rule(
        adapter_name,
        selected_vendor_event,
        definition.rules.get(selected_vendor_event),
        body,
    )
    if rule is None:
        event_name = "vendor.event.v1"
        if event_name not in selected_policy.enabled_event_names:
            return None
        permitted = set(selected_policy.field_allowlist.get(event_name, ()))
        attributes = {}
        if "vendor_event" in permitted:
            attributes["vendor_event"] = selected_vendor_event[:128] or "missing"
    else:
        event_name = rule.event_name
        if event_name not in selected_policy.enabled_event_names:
            return None
        attributes = {}
        remaining = [selected_policy.max_collection_items]
        permitted = set(capture_attribute_allowlist(selected_policy, event_name))
        for field_name, paths in rule.fields.items():
            if field_name not in permitted:
                continue
            for path in paths:
                value = _value_at(body, path)
                if value is not None:
                    if field_name == "call_id":
                        attributes[field_name] = _opaque_reference(
                            adapter_name, field_name, value
                        )
                    elif field_name == "path":
                        selected_path = _scoped_relative_path(
                            value,
                            selected_policy.max_field_chars,
                            trusted_workspace_roots,
                        )
                        if selected_path is None:
                            continue
                        attributes[field_name] = selected_path
                    else:
                        attributes[field_name] = _bounded_sanitize(
                            value,
                            selected_policy,
                            key=field_name,
                            remaining=remaining,
                        )
                    break
    if (
        len(canonical_json(attributes).encode("utf-8"))
        > selected_policy.max_event_bytes
    ):
        raise ValueError("normalized capture event exceeds the byte budget")
    trace_source = _event_body(adapter_name, payload)
    return NormalizedEvent(
        event_name=event_name,
        session_id=session_id,
        source_cursor=source_cursor,
        observed_at=observed_at,
        attributes=attributes,
        occurred_at=payload.get("timestamp")
        if isinstance(payload.get("timestamp"), str)
        else None,
        external_event_id=_opaque_reference(
            adapter_name, "event_id", payload.get("event_id")
        ),
        trace_id=trace_source.get("trace_id"),
        span_id=trace_source.get("span_id"),
        parent_span_id=trace_source.get("parent_span_id"),
        causation_event_id=_opaque_reference(
            adapter_name,
            "causation_event_id",
            trace_source.get("causation_event_id"),
        ),
        correlation_id=_opaque_reference(
            adapter_name,
            "correlation_id",
            trace_source.get("correlation_id"),
        ),
        actor_type=str(trace_source.get("actor_type") or "agent"),
        actor_id=_opaque_reference(
            adapter_name,
            "actor_id",
            trace_source.get("actor_id") or adapter_name,
        ),
    )


_INSTALL_EVENTS = {
    "codex": ("SessionStart", "UserPromptSubmit", "Stop"),
    "claude-code": (
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "PreCompact",
        "Stop",
        "SessionEnd",
    ),
    "cursor": (
        "sessionStart",
        "sessionEnd",
        "beforeSubmitPrompt",
        "preToolUse",
        "postToolUse",
        "postToolUseFailure",
        "beforeShellExecution",
        "afterShellExecution",
        "beforeMCPExecution",
        "afterMCPExecution",
        "afterFileEdit",
        "preCompact",
        "stop",
        "afterAgentResponse",
    ),
    "github-copilot": (
        "sessionStart",
        "userPromptSubmitted",
        "preToolUse",
        "postToolUse",
        "postToolUseFailure",
        "agentStop",
        "errorOccurred",
        "sessionEnd",
    ),
    "gemini-cli": (
        "SessionStart",
        "BeforeAgent",
        "BeforeTool",
        "AfterTool",
        "AfterAgent",
        "PreCompress",
        "SessionEnd",
        "Notification",
    ),
}


@dataclass(frozen=True)
class AdapterInstallPlan:
    adapter: str
    scope: str
    config_path: Path
    brain_path: Path
    installation_id: str
    action: str
    preview: bool
    original_exists: bool
    original_fingerprint: str
    target_fingerprint: str
    managed_fragment: Mapping[str, tuple[Mapping[str, Any], ...]]
    target_document: Mapping[str, Any]
    receipt_path: Path
    backup_path: Path
    allowed_root: Path
    ancestor_guard: tuple[tuple[str, int, int], ...]


def _config_path(adapter: str, scope: str, project_root: Path, home: Path) -> Path:
    if scope not in {"project", "user"}:
        raise ValueError("adapter scope must be project or user")
    paths = {
        ("codex", "user"): home / ".codex" / "hooks.json",
        ("codex", "project"): project_root / ".codex" / "hooks.json",
        ("claude-code", "project"): project_root / ".claude" / "settings.local.json",
        ("claude-code", "user"): home / ".claude" / "settings.json",
        ("cursor", "project"): project_root / ".cursor" / "hooks.json",
        ("cursor", "user"): home / ".cursor" / "hooks.json",
        ("github-copilot", "project"): project_root
        / ".github"
        / "copilot"
        / "settings.local.json",
        ("github-copilot", "user"): home / ".copilot" / "hooks" / "rta-smriti.json",
        ("gemini-cli", "project"): project_root / ".gemini" / "settings.json",
        ("gemini-cli", "user"): home / ".gemini" / "settings.json",
    }
    try:
        return paths[(adapter, scope)]
    except KeyError as exc:
        raise ValueError(
            f"adapter does not support managed hook installation: {adapter}"
        ) from exc


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _path_is_reparse_point(path: Path) -> bool:
    try:
        return bool(int(getattr(path.lstat(), "st_file_attributes", 0)) & 0x400)
    except OSError:
        return False


def _capture_ancestor_guard(
    path: Path,
    allowed_root: Path,
) -> tuple[tuple[str, int, int], ...]:
    target = _absolute_path(path)
    root = _absolute_path(allowed_root)
    if not target.is_relative_to(root):
        raise ValueError("refusing adapter configuration outside the selected scope")
    relative_parent = target.parent.relative_to(root)
    candidates = [root]
    current = root
    for part in relative_parent.parts:
        current = current / part
        candidates.append(current)
    guard: list[tuple[str, int, int]] = []
    for candidate in candidates:
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            break
        if (
            candidate.is_symlink()
            or _path_is_reparse_point(candidate)
            or not stat.S_ISDIR(info.st_mode)
        ):
            raise ValueError("adapter configuration ancestor is linked or unsafe")
        guard.append((str(candidate), int(info.st_dev), int(info.st_ino)))
    if not guard or Path(guard[0][0]) != root:
        raise ValueError("adapter configuration allowed root is unavailable")
    return tuple(guard)


def _validate_ancestor_guard(
    path: Path,
    allowed_root: Path,
    expected: tuple[tuple[str, int, int], ...],
) -> tuple[tuple[str, int, int], ...]:
    current = _capture_ancestor_guard(path, allowed_root)
    current_by_path = {item[0]: item[1:] for item in current}
    if any(current_by_path.get(item[0]) != item[1:] for item in expected):
        raise ValueError("adapter configuration ancestor changed after preview")
    return current


@contextmanager
def _stable_adapter_parent(
    path: Path,
    allowed_root: Path,
    ancestor_guard: tuple[tuple[str, int, int], ...],
):
    """Hold a stable parent capability while committing an adapter config."""

    parent = _absolute_path(path).parent
    expected_parent = next(
        (entry for entry in ancestor_guard if Path(entry[0]) == parent),
        None,
    )
    if expected_parent is None:
        raise ValueError("adapter configuration parent was not captured after creation")
    _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        create_file.restype = wintypes.HANDLE
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL
        handles = []
        invalid = ctypes.c_void_p(-1).value
        try:
            for ancestor, _device, _inode in ancestor_guard:
                handle = create_file(
                    ancestor,
                    0x80000000 | 0x00000001 | 0x00000020 | 0x00000080,
                    # GENERIC_READ | LIST_DIRECTORY | TRAVERSE | READ_ATTRIBUTES
                    0x00000001 | 0x00000002,  # share read/write, never delete
                    None,
                    3,  # OPEN_EXISTING
                    0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
                    None,
                )
                if handle == invalid:
                    raise OSError(
                        ctypes.get_last_error(),
                        "cannot lock adapter configuration ancestor",
                        ancestor,
                    )
                handles.append(handle)
            _validate_ancestor_guard(path, allowed_root, ancestor_guard)
            yield ("windows", handles[-1])
        finally:
            for handle in reversed(handles):
                close_handle(handle)
        return

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(parent, flags)
    try:
        info = os.fstat(descriptor)
        if (int(info.st_dev), int(info.st_ino)) != expected_parent[1:]:
            raise ValueError("adapter configuration parent changed after preview")
        _validate_ancestor_guard(path, allowed_root, ancestor_guard)
        yield ("posix", descriptor)
    finally:
        os.close(descriptor)


def _windows_create_rename_temporary(
    parent: Path,
    *,
    prefix: str,
    suffix: str,
) -> tuple[int, Path]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    path = parent / f"{prefix}{uuid.uuid4().hex}{suffix}"
    handle = create_file(
        str(path),
        0x40000000 | 0x00010000 | 0x00100000,  # WRITE | DELETE | SYNCHRONIZE
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        1,  # CREATE_NEW
        0x00000080 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(
            ctypes.get_last_error(),
            "cannot safely create adapter temporary for rename",
            path,
        )
    try:
        descriptor = msvcrt.open_osfhandle(
            int(handle),
            os.O_WRONLY | getattr(os, "O_BINARY", 0),
        )
    except BaseException:
        _windows_close_handle(handle)
        raise
    return descriptor, path


def _windows_close_handle(handle) -> None:
    import ctypes
    from ctypes import wintypes

    close_handle = ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    close_handle(handle)


def _windows_replace_open_file(handle, parent_handle, target_name: str) -> None:
    import ctypes
    from ctypes import wintypes

    class FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("ReplaceIfExists", wintypes.BOOLEAN),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * (len(target_name) + 1)),
        ]

    info = FileRenameInfo()
    info.ReplaceIfExists = True
    info.RootDirectory = parent_handle
    info.FileNameLength = len(target_name.encode("utf-16-le"))
    info.FileName = target_name
    class IoStatusBlock(ctypes.Structure):
        _fields_ = [
            ("Status", ctypes.c_long),
            ("Information", ctypes.c_size_t),
        ]

    ntdll = ctypes.WinDLL("ntdll")
    set_info = ntdll.NtSetInformationFile
    set_info.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.c_int,
    ]
    set_info.restype = ctypes.c_long
    io_status = IoStatusBlock()
    status = int(
        set_info(
            handle,
            ctypes.byref(io_status),
            ctypes.byref(info),
            ctypes.sizeof(info),
            10,  # FileRenameInformation
        )
    )
    if status < 0:
        to_dos_error = ntdll.RtlNtStatusToDosError
        to_dos_error.argtypes = [ctypes.c_long]
        to_dos_error.restype = wintypes.ULONG
        raise OSError(
            int(to_dos_error(status)),
            "cannot commit adapter configuration through its reviewed parent",
        )


def _windows_dispose_open_file(handle) -> None:
    import ctypes
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

    info = FileDispositionInfo(True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_info = kernel32.SetFileInformationByHandle
    set_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    set_info.restype = wintypes.BOOL
    set_info(handle, 4, ctypes.byref(info), ctypes.sizeof(info))


def _receipt_ancestor_guard(
    receipt: Mapping[str, Any],
    config_path: Path,
) -> tuple[Path, tuple[tuple[str, int, int], ...]]:
    raw_root = receipt.get("allowed_root")
    raw_guard = receipt.get("ancestor_guard")
    if (
        not isinstance(raw_root, str)
        or not Path(raw_root).is_absolute()
        or not isinstance(raw_guard, list)
    ):
        raise ValueError("adapter installation receipt ancestor guard is invalid")
    allowed_root = _absolute_path(Path(raw_root))
    if not _absolute_path(config_path).is_relative_to(allowed_root):
        raise ValueError(
            "adapter installation receipt target is outside its allowed root"
        )
    parsed: list[tuple[str, int, int]] = []
    for item in raw_guard:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or type(item.get("device")) is not int
            or type(item.get("inode")) is not int
        ):
            raise ValueError("adapter installation receipt ancestor guard is invalid")
        guarded_path = _absolute_path(Path(item["path"]))
        if not guarded_path.is_relative_to(allowed_root):
            raise ValueError("adapter installation receipt ancestor guard is invalid")
        parsed.append((str(guarded_path), int(item["device"]), int(item["inode"])))
    if (
        not parsed
        or Path(parsed[0][0]) != allowed_root
        or len({item[0] for item in parsed}) != len(parsed)
    ):
        raise ValueError("adapter installation receipt ancestor guard is invalid")
    return allowed_root, tuple(parsed)


def _bounded_config(path: Path) -> tuple[dict[str, Any], bytes, bool]:
    if not path.exists():
        return {}, b"", False
    if not is_safe_regular_file(path):
        raise ValueError(f"refusing linked or unsafe adapter configuration: {path}")
    before = path.stat()
    if before.st_size > 1_048_576:
        raise ValueError("adapter configuration exceeds the 1 MiB safety limit")
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    after = path.stat()
    if len(raw) > 1_048_576 or (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ValueError("adapter configuration changed during inspection")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("adapter configuration is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise TypeError("adapter configuration must be a JSON object")
    return document, raw, True


def _validate_config(document: Mapping[str, Any], adapter: str) -> None:
    if document.get("allowManagedHooksOnly") is True or document.get("managed") is True:
        raise ValueError("enterprise-managed adapter configuration cannot be edited")
    if adapter in {"cursor", "github-copilot"} and document.get("version", 1) != 1:
        raise ValueError("adapter configuration version is unsupported")
    hooks = document.get("hooks", {})
    if not isinstance(hooks, dict):
        raise TypeError("adapter configuration requires a hooks object")
    for event, entries in hooks.items():
        if not isinstance(event, str) or not isinstance(entries, list):
            raise TypeError("adapter hook events must contain arrays")
        if not all(isinstance(entry, dict) for entry in entries):
            raise ValueError("adapter hook entries must be objects")


def _windows_command(parts: tuple[str, ...]) -> str:
    quoted = []
    for part in parts:
        if any(
            character in part
            for character in ("\0", "\r", "\n", '"', "%", "!", "&", "|", "<", ">", "^")
        ):
            raise ValueError("Windows adapter command contains unsupported characters")
        backslashes = len(part) - len(part.rstrip("\\"))
        quoted.append('"' + part + ("\\" * backslashes) + '"')
    return " ".join(quoted)


def _command(parts: tuple[str, ...], platform_name: str) -> str:
    if not 1 <= len(parts) <= 32 or any(
        not isinstance(part, str) or not part or len(part) > 4_096 or "\0" in part
        for part in parts
    ):
        raise ValueError("adapter command parts are invalid")
    executable = Path(parts[0]).expanduser()
    if not executable.is_absolute() or not is_safe_regular_file(executable.resolve()):
        raise ValueError("adapter executable must be an absolute trusted regular file")
    selected = (str(executable.resolve()), *parts[1:])
    return (
        _windows_command(selected) if platform_name == "win32" else shlex.join(selected)
    )


def _managed_fragment(
    adapter: str, command: str
) -> dict[str, tuple[dict[str, Any], ...]]:
    fragments = {}
    for event in _INSTALL_EVENTS[adapter]:
        if adapter in {"claude-code", "gemini-cli"}:
            entry = {
                "matcher": "",
                "hooks": [
                    {
                        "type": "command",
                        "command": command,
                        "timeout": 5_000 if adapter == "gemini-cli" else 5,
                        "name": "Rta-Smriti capture"
                        if adapter == "gemini-cli"
                        else None,
                    }
                ],
            }
            entry["hooks"][0] = {
                key: value
                for key, value in entry["hooks"][0].items()
                if value is not None
            }
        elif adapter == "github-copilot":
            entry = {"type": "command", "command": command, "timeoutSec": 5}
        else:
            entry = {"command": command, "timeout": 5}
        fragments[event] = (entry,)
    return fragments


def _contains_fragment(
    document: Mapping[str, Any], fragment: Mapping[str, tuple[Mapping[str, Any], ...]]
) -> bool:
    hooks = document.get("hooks", {})
    return all(
        all(entry in hooks.get(event, []) for entry in entries)
        for event, entries in fragment.items()
    )


def _remove_fragment(
    document: dict[str, Any],
    fragment: Mapping[str, tuple[Mapping[str, Any], ...]],
) -> dict[str, Any]:
    result = deepcopy(document)
    hooks = result.get("hooks", {})
    for event, entries in fragment.items():
        current = hooks.get(event)
        if not isinstance(current, list):
            raise TypeError("managed fragment drifted from the installed receipt")
        for entry in entries:
            try:
                current.remove(entry)
            except ValueError as exc:
                raise ValueError(
                    "managed fragment drifted from the installed receipt"
                ) from exc
        if not current:
            hooks.pop(event, None)
    return result


def _merge_fragment(
    document: Mapping[str, Any],
    adapter: str,
    fragment: Mapping[str, tuple[Mapping[str, Any], ...]],
) -> dict[str, Any]:
    result = deepcopy(dict(document))
    if adapter in {"cursor", "github-copilot"}:
        result.setdefault("version", 1)
    hooks = result.setdefault("hooks", {})
    for event, entries in fragment.items():
        current = hooks.setdefault(event, [])
        for entry in entries:
            if entry not in current:
                current.append(deepcopy(entry))
    return result


def _fingerprint(document: Mapping[str, Any] | bytes) -> str:
    encoded = (
        document
        if isinstance(document, bytes)
        else canonical_json(document).encode("ascii")
    )
    return hashlib.sha256(encoded).hexdigest()


def _installation_id(
    brain_path: Path,
    adapter: str,
    scope: str,
    config_path: Path,
) -> str:
    return hashlib.sha256(
        f"{brain_path.resolve()}\0{adapter}\0{scope}\0{config_path.resolve()}".encode()
    ).hexdigest()[:32]


def _installation_paths(brain_path: Path, adapter: str, scope: str, config_path: Path):
    directory = capture_control_root_path(brain_path) / "adapter-installs"
    installation_id = _installation_id(brain_path, adapter, scope, config_path)
    return (
        installation_id,
        directory / f"{installation_id}.json",
        directory / f"{installation_id}.backup",
    )


def plan_adapter_installation(
    adapter: str,
    *,
    scope: str,
    project_root: Path,
    home: Path,
    brain_path: Path,
    command_parts: tuple[str, ...],
    platform_name: str,
    continuity_mode: bool = False,
) -> AdapterInstallPlan:
    if adapter not in _INSTALL_EVENTS:
        raise ValueError(
            f"adapter does not support managed hook installation: {adapter}"
        )
    project = project_root.expanduser().resolve()
    selected_home = home.expanduser().resolve()
    if not project.is_dir() or not selected_home.is_dir():
        raise ValueError("adapter project and home roots must exist")
    config_path = _config_path(adapter, scope, project, selected_home)
    allowed_root = project if scope == "project" else selected_home
    if not config_path.parent.resolve().is_relative_to(allowed_root):
        raise ValueError("refusing adapter configuration outside the selected scope")
    ancestor_guard = _capture_ancestor_guard(config_path, allowed_root)
    document, raw, existed = _bounded_config(config_path)
    _validate_config(document, adapter)
    if adapter == "codex" and not continuity_mode:
        raise ValueError("Codex hooks require the unified agent setup flow")
    if continuity_mode:
        if adapter not in {"codex", "claude-code"}:
            raise ValueError("unsupported continuity host")
        command = _command(command_parts, "posix")
        hook = {"type": "command", "command": command, "timeout": 10}
        if adapter == "claude-code":
            hook.update(command=command_parts[0], args=list(command_parts[1:]))
        elif platform_name == "win32":
            from .continuity_bridge_cli import _powershell_command

            hook["commandWindows"] = _powershell_command(command_parts)
        fragment = {event: ({"hooks": [deepcopy(hook)]},)
                    for event in ("SessionStart", "UserPromptSubmit", "Stop")}
    else:
        command = _command(command_parts, platform_name)
        fragment = _managed_fragment(adapter, command)
    installation_id, receipt_path, backup_path = _installation_paths(
        brain_path.expanduser().resolve(),
        adapter,
        scope,
        config_path,
    )
    base_document = document
    action = "create" if not existed else "merge"
    receipt = read_json(receipt_path)
    if receipt_path.exists() and receipt is None:
        raise ValueError("adapter installation receipt is linked or malformed")
    if receipt is not None:
        if (
            receipt.get("adapter") != adapter
            or receipt.get("scope") != scope
            or receipt.get("config_path") != str(config_path)
        ):
            raise ValueError(
                "adapter installation receipt conflicts with the requested target"
            )
        old_fragment = receipt.get("managed_fragment")
        if not isinstance(old_fragment, dict):
            raise ValueError("adapter installation receipt is malformed")
        if receipt.get("managed_fragment_fingerprint") != _fingerprint(old_fragment):
            raise ValueError("adapter installation receipt fragment is invalid")
        receipt_state = receipt.get("state")
        if receipt_state is None:
            receipt_state = "installed" if receipt.get("installed") else "removed"
        if receipt_state == "prepared":
            original_fingerprint = receipt.get("original_fingerprint")
            target_fingerprint = receipt.get("target_fingerprint")
            if (
                not isinstance(original_fingerprint, str)
                or not isinstance(target_fingerprint, str)
            ):
                raise ValueError("prepared adapter installation receipt is malformed")
            if _fingerprint(document) == target_fingerprint and _contains_fragment(
                document, old_fragment
            ):
                base_document = document
                action = "recover"
            elif _fingerprint(raw) == original_fingerprint:
                action = "reinstall"
            else:
                raise ValueError("prepared adapter installation cannot be recovered safely")
        elif receipt_state == "removed":
            action = "reinstall"
        elif receipt_state == "installed":
            base_document = _remove_fragment(document, old_fragment)
            action = "update"
        else:
            raise ValueError("adapter installation receipt state is invalid")
    elif _contains_fragment(document, fragment):
        raise ValueError(
            "adapter configuration contains an ambiguous unmanaged fragment"
        )
    target = _merge_fragment(base_document, adapter, fragment)
    if target == document and action != "recover":
        action = "current"
    return AdapterInstallPlan(
        adapter=adapter,
        scope=scope,
        config_path=config_path,
        brain_path=brain_path.expanduser().resolve(),
        installation_id=installation_id,
        action=action,
        preview=True,
        original_exists=existed,
        original_fingerprint=_fingerprint(raw),
        target_fingerprint=_fingerprint(target),
        managed_fragment=fragment,
        target_document=target,
        receipt_path=receipt_path,
        backup_path=backup_path,
        allowed_root=allowed_root,
        ancestor_guard=ancestor_guard,
    )


def _atomic_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    allowed_root: Path,
    ancestor_guard: tuple[tuple[str, int, int], ...],
) -> None:
    _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    path.parent.mkdir(parents=True, exist_ok=True)
    current_guard = _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    if path.exists() and not is_safe_regular_file(path):
        raise ValueError(f"refusing linked adapter configuration: {path}")
    with _stable_adapter_parent(path, allowed_root, current_guard) as parent_capability:
        if parent_capability[0] == "windows":
            descriptor, temporary = _windows_create_rename_temporary(
                path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
            )
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
            temporary = Path(temporary_name)
        stream = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
        committed = False
        try:
            json.dump(document, stream, ensure_ascii=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            _validate_ancestor_guard(path, allowed_root, current_guard)
            if parent_capability[0] == "windows":
                import msvcrt

                _windows_replace_open_file(
                    msvcrt.get_osfhandle(stream.fileno()),
                    parent_capability[1],
                    path.name,
                )
            else:
                os.replace(
                    temporary.name,
                    path.name,
                    src_dir_fd=parent_capability[1],
                    dst_dir_fd=parent_capability[1],
                )
            committed = True
            _validate_ancestor_guard(path, allowed_root, current_guard)
        finally:
            if parent_capability[0] == "windows":
                if not committed:
                    import msvcrt

                    _windows_dispose_open_file(msvcrt.get_osfhandle(stream.fileno()))
                stream.close()
            else:
                stream.close()
                try:
                    os.unlink(temporary.name, dir_fd=parent_capability[1])
                except FileNotFoundError:
                    pass


def _json_bytes(document: Mapping[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=True, indent=2) + "\n").encode("utf-8")


def _create_new_config(
    path: Path,
    *,
    raw: bytes,
    allowed_root: Path,
    ancestor_guard: tuple[tuple[str, int, int], ...],
) -> None:
    """Create a reviewed absent config without replacing a concurrent creator."""

    if len(raw) > 1_048_576:
        raise ValueError("adapter configuration exceeds the 1 MiB safety limit")
    _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    path.parent.mkdir(parents=True, exist_ok=True)
    current_guard = _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    with _stable_adapter_parent(path, allowed_root, current_guard) as parent_capability:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        if parent_capability[0] == "posix":
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_capability[1])
        else:
            descriptor = os.open(path, flags, 0o600)
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise OSError("adapter configuration write made no progress")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    _validate_ancestor_guard(path, allowed_root, current_guard)


def _create_backup(path: Path, raw: bytes) -> None:
    if len(raw) > 1_048_576:
        raise ValueError("adapter backup exceeds the 1 MiB safety limit")
    if path.exists():
        if not is_safe_regular_file(path) or path.stat().st_size > 1_048_576:
            raise ValueError("adapter backup already exists with different content")
        with path.open("rb") as stream:
            existing = stream.read(1_048_577)
        if existing != raw:
            raise ValueError("adapter backup already exists with different content")
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _read_backup(path: Path) -> bytes:
    if not is_safe_regular_file(path) or path.stat().st_size > 1_048_576:
        raise ValueError("adapter backup is missing, linked, or oversized")
    with path.open("rb") as stream:
        raw = stream.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("adapter backup exceeds the 1 MiB safety limit")
    return raw


def _restore_bytes(
    path: Path,
    raw: bytes,
    *,
    allowed_root: Path,
    ancestor_guard: tuple[tuple[str, int, int], ...],
) -> None:
    _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    path.parent.mkdir(parents=True, exist_ok=True)
    current_guard = _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    if path.exists() and not is_safe_regular_file(path):
        raise ValueError(f"refusing linked adapter configuration: {path}")
    with _stable_adapter_parent(path, allowed_root, current_guard) as parent_capability:
        if parent_capability[0] == "windows":
            descriptor, temporary = _windows_create_rename_temporary(
                path.parent,
                prefix=f".{path.name}.",
                suffix=".restore",
            )
        else:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".restore",
                dir=path.parent,
            )
            temporary = Path(temporary_name)
        stream = os.fdopen(descriptor, "wb")
        committed = False
        try:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            _validate_ancestor_guard(path, allowed_root, current_guard)
            if parent_capability[0] == "windows":
                import msvcrt

                _windows_replace_open_file(
                    msvcrt.get_osfhandle(stream.fileno()),
                    parent_capability[1],
                    path.name,
                )
            else:
                os.replace(
                    temporary.name,
                    path.name,
                    src_dir_fd=parent_capability[1],
                    dst_dir_fd=parent_capability[1],
                )
            committed = True
            _validate_ancestor_guard(path, allowed_root, current_guard)
        finally:
            if parent_capability[0] == "windows":
                if not committed:
                    import msvcrt

                    _windows_dispose_open_file(msvcrt.get_osfhandle(stream.fileno()))
                stream.close()
            else:
                stream.close()
                try:
                    os.unlink(temporary.name, dir_fd=parent_capability[1])
                except FileNotFoundError:
                    pass


def _overwrite_open_config(
    path: Path,
    *,
    expected_raw: bytes,
    replacement_raw: bytes,
    allowed_root: Path,
    ancestor_guard: tuple[tuple[str, int, int], ...],
    operation: str = "removal",
) -> None:
    """Replace one already-reviewed config through its open file handle.

    Adapter removal must not perform a pathname mutation after validating the
    ancestor chain. An open descriptor keeps the mutation bound to the exact
    file that was inspected even if another process swaps a parent directory.
    """

    if len(expected_raw) > 1_048_576 or len(replacement_raw) > 1_048_576:
        raise ValueError("adapter configuration exceeds the 1 MiB safety limit")
    current_guard = _validate_ancestor_guard(path, allowed_root, ancestor_guard)
    with _stable_adapter_parent(path, allowed_root, current_guard) as parent_capability:
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            if parent_capability[0] == "posix":
                flags |= getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(
                    path.name,
                    flags,
                    dir_fd=parent_capability[1],
                )
            else:
                descriptor = _windows_open_existing_config_no_follow(path, flags)
        except OSError as exc:
            raise ValueError("adapter configuration is linked or unsafe") from exc
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or int(getattr(before, "st_file_attributes", 0)) & 0x400
            ):
                raise ValueError("adapter configuration is linked or unsafe")
            current = b""
            while len(current) <= 1_048_576:
                block = os.read(descriptor, min(65_536, 1_048_577 - len(current)))
                if not block:
                    break
                current += block
            if current != expected_raw:
                raise ValueError(f"adapter configuration changed during {operation}")
            _validate_ancestor_guard(path, allowed_root, current_guard)
            os.lseek(descriptor, 0, os.SEEK_SET)
            written = 0
            while written < len(replacement_raw):
                count = os.write(descriptor, replacement_raw[written:])
                if count <= 0:
                    raise OSError("adapter configuration write made no progress")
                written += count
            os.ftruncate(descriptor, len(replacement_raw))
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ValueError("adapter configuration identity changed during removal")
        finally:
            os.close(descriptor)
        _validate_ancestor_guard(path, allowed_root, current_guard)


def _windows_open_existing_config_no_follow(path: Path, flags: int) -> int:
    if os.name != "nt":  # pragma: no cover - Windows-only helper
        raise OSError("Windows no-follow open is unavailable")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_info = kernel32.GetFileInformationByHandle
    get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    get_info.restype = wintypes.BOOL
    handle = create_file(
        str(path),
        0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
        0x00000001 | 0x00000002,  # share read/write, never delete
        None,
        3,  # OPEN_EXISTING
        0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(ctypes.get_last_error(), "cannot open adapter configuration")
    try:
        info = ByHandleFileInformation()
        if not get_info(handle, ctypes.byref(info)):
            raise OSError(
                ctypes.get_last_error(),
                "cannot inspect adapter configuration",
            )
        if info.dwFileAttributes & (0x00000400 | 0x00000010) or info.nNumberOfLinks != 1:
            raise ValueError("adapter configuration is linked or unsafe")
        descriptor = msvcrt.open_osfhandle(int(handle), flags)
        handle = None
        return descriptor
    finally:
        if handle is not None:
            _windows_close_handle(handle)


def install_adapter(plan: AdapterInstallPlan) -> dict[str, Any]:
    if not isinstance(plan, AdapterInstallPlan) or not plan.preview:
        raise TypeError("adapter installation requires a preview plan")
    _validate_ancestor_guard(plan.config_path, plan.allowed_root, plan.ancestor_guard)
    _, raw, existed = _bounded_config(plan.config_path)
    _validate_ancestor_guard(plan.config_path, plan.allowed_root, plan.ancestor_guard)
    if (
        existed != plan.original_exists
        or _fingerprint(raw) != plan.original_fingerprint
    ):
        raise ValueError("adapter configuration changed after preview")
    existing_receipt = read_json(plan.receipt_path)
    existing_state = None if existing_receipt is None else existing_receipt.get("state")
    if existing_state is None and existing_receipt is not None:
        existing_state = "installed" if existing_receipt.get("installed") else "removed"
    if (
        plan.action == "current"
        and existing_receipt is not None
        and existing_state == "installed"
    ):
        return {**existing_receipt, "installed": True, "idempotent_replay": True}
    ensure_capture_control_root(plan.brain_path)
    prepare_control_dir(plan.receipt_path.parent, label="adapter")
    if existing_receipt is None:
        _create_backup(plan.backup_path, raw)
    prepared_guard = _validate_ancestor_guard(
        plan.config_path,
        plan.allowed_root,
        plan.ancestor_guard,
    )
    original_exists = (
        existing_receipt.get("original_exists", plan.original_exists)
        if existing_receipt is not None
        else plan.original_exists
    )
    prepared = {
        "schema": "rta-smriti.adapter-install/v1",
        "installation_id": plan.installation_id,
        "adapter": plan.adapter,
        "scope": plan.scope,
        "config_path": str(plan.config_path),
        "backup_path": str(plan.backup_path),
        "receipt_path": str(plan.receipt_path),
        "original_exists": original_exists,
        "original_fingerprint": (
            existing_receipt.get("original_fingerprint", plan.original_fingerprint)
            if existing_receipt is not None
            else plan.original_fingerprint
        ),
        "managed_fragment": plan.managed_fragment,
        "managed_fragment_fingerprint": _fingerprint(plan.managed_fragment),
        "target_fingerprint": plan.target_fingerprint,
        "allowed_root": str(plan.allowed_root),
        "ancestor_guard": [
            {"path": path, "device": device, "inode": inode}
            for path, device, inode in prepared_guard
        ],
        "state": "prepared",
        "installed": False,
        "idempotent_replay": False,
    }
    write_json(plan.receipt_path, prepared, label="adapter receipt")
    target_raw = _json_bytes(plan.target_document)
    if plan.action == "recover":
        document, _, current_exists = _bounded_config(plan.config_path)
        if (
            not current_exists
            or _fingerprint(document) != plan.target_fingerprint
            or not _contains_fragment(document, plan.managed_fragment)
        ):
            raise ValueError("prepared adapter installation cannot be recovered safely")
    elif existed:
        _overwrite_open_config(
            plan.config_path,
            expected_raw=raw,
            replacement_raw=target_raw,
            allowed_root=plan.allowed_root,
            ancestor_guard=plan.ancestor_guard,
            operation="installation",
        )
    else:
        _create_new_config(
            plan.config_path,
            raw=target_raw,
            allowed_root=plan.allowed_root,
            ancestor_guard=plan.ancestor_guard,
        )
    installed_guard = _validate_ancestor_guard(
        plan.config_path,
        plan.allowed_root,
        plan.ancestor_guard,
    )
    receipt = {
        **prepared,
        "ancestor_guard": [
            {"path": path, "device": device, "inode": inode}
            for path, device, inode in installed_guard
        ],
        "state": "installed",
        "installed": True,
    }
    write_json(plan.receipt_path, receipt, label="adapter receipt")
    return receipt


def remove_adapter(*, brain_path: Path, installation_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{32}", installation_id):
        raise ValueError("adapter installation ID is invalid")
    control_root = ensure_capture_control_root(brain_path.expanduser().resolve())
    receipt_path = control_root / "adapter-installs" / f"{installation_id}.json"
    receipt = read_json(receipt_path)
    if receipt is None or receipt.get("installation_id") != installation_id:
        raise ValueError("adapter installation receipt is missing or invalid")
    config_path = Path(str(receipt["config_path"]))
    adapter = str(receipt.get("adapter", ""))
    scope = str(receipt.get("scope", ""))
    if _installation_id(brain_path, adapter, scope, config_path) != installation_id:
        raise ValueError("adapter installation receipt target is invalid")
    allowed_root, ancestor_guard = _receipt_ancestor_guard(receipt, config_path)
    _validate_ancestor_guard(config_path, allowed_root, ancestor_guard)
    expected_backup = receipt_path.with_suffix(".backup")
    if Path(str(receipt.get("backup_path", ""))).resolve() != expected_backup.resolve():
        raise ValueError("adapter installation receipt backup target is invalid")
    receipt_state = receipt.get("state")
    if receipt_state is None:
        receipt_state = "installed" if receipt.get("installed") else "removed"
    if receipt_state == "removed":
        return {**receipt, "removed": True, "idempotent_replay": True}
    document, config_raw, existed = _bounded_config(config_path)
    _validate_ancestor_guard(config_path, allowed_root, ancestor_guard)
    if receipt_state == "prepared":
        original_fingerprint = receipt.get("original_fingerprint")
        target_fingerprint = receipt.get("target_fingerprint")
        if not existed and not receipt.get("original_exists"):
            updated = {
                **receipt,
                "state": "removed",
                "installed": False,
                "removed": True,
                "config_file_preserved": False,
                "idempotent_replay": False,
            }
            write_json(receipt_path, updated, label="adapter receipt")
            return updated
        if existed and _fingerprint(config_raw) == original_fingerprint:
            updated = {
                **receipt,
                "state": "removed",
                "installed": False,
                "removed": True,
                "config_file_preserved": True,
                "idempotent_replay": False,
            }
            write_json(receipt_path, updated, label="adapter receipt")
            return updated
        if not (
            existed
            and _fingerprint(document) == target_fingerprint
            and _contains_fragment(document, receipt.get("managed_fragment", {}))
        ):
            raise ValueError("prepared adapter installation cannot be removed safely")
    elif receipt_state != "installed":
        raise ValueError("adapter installation receipt state is invalid")
    if not existed:
        raise ValueError("managed adapter configuration is missing")
    fragment = receipt.get("managed_fragment")
    if (
        not isinstance(fragment, dict)
        or receipt.get("managed_fragment_fingerprint") != _fingerprint(fragment)
        or not _contains_fragment(document, fragment)
    ):
        raise ValueError("managed fragment drifted from the installed receipt")
    cleaned = _remove_fragment(document, fragment)
    backup_raw = _read_backup(expected_backup)
    if receipt.get("original_exists"):
        try:
            original_document = json.loads(backup_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("adapter backup is not valid UTF-8 JSON") from exc
    else:
        original_document = {}
    expected_cleaned = _remove_fragment(
        _merge_fragment(original_document, adapter, fragment),
        fragment,
    )
    if cleaned == expected_cleaned:
        if receipt.get("original_exists"):
            replacement_raw = backup_raw
            config_file_preserved = True
        else:
            replacement_raw = b"{}\n"
            config_file_preserved = True
        _overwrite_open_config(
            config_path,
            expected_raw=config_raw,
            replacement_raw=replacement_raw,
            allowed_root=allowed_root,
            ancestor_guard=ancestor_guard,
        )
    else:
        replacement_raw = (
            json.dumps(cleaned, ensure_ascii=True, indent=2) + "\n"
        ).encode("utf-8")
        _overwrite_open_config(
                config_path,
            expected_raw=config_raw,
            replacement_raw=replacement_raw,
            allowed_root=allowed_root,
            ancestor_guard=ancestor_guard,
        )
        config_file_preserved = True
    updated = {
        **receipt,
        "state": "removed",
        "installed": False,
        "removed": True,
        "config_file_preserved": config_file_preserved,
        "idempotent_replay": False,
    }
    write_json(receipt_path, updated, label="adapter receipt")
    return updated
