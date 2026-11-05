"""One consented two-host setup; capture writes and recall reads stay separate."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tomllib
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from . import db
from .binding_guard import binding_gate
from .capture import register_policy, register_source, verify_capture_project_binding
from .capture_adapters import (
    _bounded_config,
    install_adapter,
    plan_adapter_installation,
    remove_adapter,
)
from .capture_daemon import (
    CAPTURE_INGRESS_FIELDS,
    capture_cycle,
    prepare_capture_spool_record,
)
from .capture_spool import CaptureSpool, ensure_capture_control_root
from .capture_types import CapturePolicy, CaptureSource
from .continuity_bridge import (
    FORMAT,
    HOSTS,
    MAX_INPUT_BYTES,
    _digest,
    _empty,
    _identity,
    _json,
    _read_consent,
    _save_consent,
    _unlinked_path,
    consent_path,
    disable_bridge,
    enable_bridge,
    preview_bridge,
    recall_bridge,
)
from .continuity_bridge_cli import _launcher
from .mcp_host_lifecycle import (
    apply_host_configuration,
    plan_host_configuration,
    validate_installed_configuration,
)
from .runtime_control import (
    database_writer_lease,
    prepare_control_dir,
    runtime_executable,
)

DISCLOSURE = (
    "Local capture stores future user prompts and final assistant replies for this project, "
    "up to 4000 characters each, eligible for recall for seven days. Physical cleanup uses "
    "existing retention maintenance; this is not a secure-erasure promise. "
    "Tool payloads and transcript files are not read. "
    "The latest bounded history can be sent to either selected host and its model provider at "
    "session start. It is unverified history, not a verified decision or instruction. "
    "Known secret patterns are screened, not guaranteed absent. No new background service, "
    "model call or automatic trust approval is created. Settings are user-scoped and project-bound."
)


class SetupPlan(dict):
    """Public preview plus process-local, reconstructable execution arguments."""

    def __init__(self, preview, *, options, hooks, mcp, grant_options):
        super().__init__(preview)
        self.options = options
        self.hooks = hooks
        self.mcp = mcp
        self.grant_options = grant_options


def _path(database, project):
    return consent_path(database, project, "codex").with_name(
        f"setup-{_digest(project)}.json"
    )


def _load(database, project):
    path = _path(database, project)
    if not os.path.lexists(path):
        return None
    value = _read_consent(path)
    if value.get("kind") != "agent-setup" or value.get("project") != project:
        raise ValueError("invalid setup receipt")
    return value


def _save(database, project, value):
    ensure_capture_control_root(database)
    path = _path(database, project)
    prepare_control_dir(path.parent, label="agent setup")
    _save_consent(path, value)


def _policy():
    return replace(
        CapturePolicy.continuity(),
        max_field_chars=4000,
        retention_seconds=7 * 86400,
        enabled_event_names=("prompt.submitted.v1", "agent.message.v1"),
        field_allowlist={
            "prompt.submitted.v1": ("text", "role"),
            "agent.message.v1": ("text", "role"),
        },
    )


def _mcp_target(home, host):
    return home / ".codex" / "config.toml" if host == "codex" else home / ".claude.json"


def plan_setup(database, project, root, *, home=None, hosts=HOSTS):
    database = _unlinked_path(Path(database).expanduser())
    root = _unlinked_path(Path(root).expanduser())
    home = _unlinked_path(Path(home or Path.home()).expanduser())
    hosts = tuple(hosts)
    if not hosts or len(set(hosts)) != len(hosts) or any(h not in HOSTS for h in hosts):
        raise ValueError("select Codex, Claude Code, or both")
    old = _load(database, project)
    if old is None:
        for host in hosts:
            grant = consent_path(database, project, host)
            if os.path.lexists(grant) and _read_consent(grant).get("enabled"):
                raise ValueError(
                    "review and disable the existing bridge before unified setup"
                )
    identity = {
        "database": str(database),
        "database_identity": _identity(database),
        "root": str(root),
        "root_identity": _identity(root),
        "home": str(home),
    }
    if old and any(old.get(key) != value for key, value in identity.items()):
        raise ValueError(
            "setup identity changed; restore or remove the previous setup first"
        )
    if old and old["hosts"] != list(hosts):
        raise ValueError("host selection changed; remove the previous setup first")
    with closing(db.connect_readonly(database)) as conn:
        _require_current_schema(conn)
        binding = verify_capture_project_binding(
            conn, project=project, active_root=root
        )
        project_id = conn.execute(
            "SELECT id FROM projects WHERE name=?", (project,)
        ).fetchone()[0]
        latest = (
            conn.execute(
                "SELECT MAX(project_sequence) FROM capture_events WHERE project_id=?",
                (project_id,),
            ).fetchone()[0]
            or 0
        )
    if old and old["state"] == "removal_partial":
        raise ValueError("finish the interrupted removal before installing again")
    continuing = old is not None and old["state"] not in {"stopped", "removed"}
    epoch = (
        old["epoch"]
        if continuing
        else _digest([identity, project, old and old["epoch"]])[:16]
    )
    sources = {host: f"agent-flow-{host}-{epoch}" for host in hosts}
    selection = {
        "capture_sources": list(sources.values()),
        "capture_after_sequence": old["selection"]["capture_after_sequence"]
        if continuing
        else latest,
    }
    grants = {
        host: {
            "database": database,
            "project": project,
            "root": root,
            "host": host,
            "selection": selection,
            "max_bytes": 8192,
            "max_age_hours": 168,
        }
        for host in hosts
    }
    bridge = {host: preview_bridge(**options) for host, options in grants.items()}
    hooks, mcp, previews = {}, {}, []
    server_name = f"rta-flow-{_digest([str(database), project])[:12]}"
    server = {
        "command": str(runtime_executable()),
        "args": [
            *(["mcp-server"] if getattr(sys, "frozen", False)
              else ["-I", "-m", "rta_brain.mcp_server"]),
            "--db",
            str(database),
            "--project",
            project,
            "--root",
            str(root),
            "--tool-profile",
            "core",
        ],
    }
    for host in hosts:
        command = tuple(
            _launcher()
            + [
                "agent-setup",
                "hook",
                "--db",
                str(database),
                "--project",
                project,
                "--host",
                host,
            ]
        )
        hook = plan_adapter_installation(
            host,
            scope="user",
            project_root=root,
            home=home,
            brain_path=database,
            command_parts=command,
            platform_name=sys.platform,
            continuity_mode=True,
        )
        if hook.action == "update" and not old:
            raise ValueError(
                "existing capture installation needs separate review before replacement"
            )
        previous_mcp = old.get("mcp", {}).get(host) if old else None
        if previous_mcp:
            validate_installed_configuration(
                Path(previous_mcp["receipt_path"]), allow_unrelated_changes=True
            )
        host_plan = plan_host_configuration(
            host,
            _mcp_target(home, host),
            server_name,
            server,
            replace_existing=bool(previous_mcp),
        )
        original = host_plan._original.decode("utf-8")
        configuration = (
            tomllib.loads(original) if host == "codex" else json.loads(original or "{}")
        )
        for name, entry in configuration.get(
            "mcp_servers" if host == "codex" else "mcpServers", {}
        ).items():
            encoded = _json(entry)
            if name != server_name and any(
                marker in encoded
                for marker in (
                    "rta_brain.mcp_server",
                    "rta-brain-mcp",
                    "rta-brain.py",
                    "rta-brain.exe",
                    "rta-brain.cmd",
                )
            ):
                raise ValueError(
                    "review the existing Rta-Smriti MCP registration before adding another server"
                )
        if previous_mcp and previous_mcp.get("spec_digest") != _digest(
            host_plan["effective_configuration_change"]
        ):
            raise ValueError(
                "installed MCP configuration needs a separate upgrade review"
            )
        hooks[host], mcp[host] = hook, host_plan
        previews.append(
            {
                "host": host,
                "hooks_action": hook.action,
                "hooks_before": hook.original_fingerprint,
                "hooks_after": hook.target_fingerprint,
                "hooks_target": str(hook.config_path),
                "hooks": hook.managed_fragment,
                "mcp": dict(host_plan),
                "mcp_target": str(_mcp_target(home, host)),
                "recall_preview": bridge[host]["context"],
                "recall_revision": bridge[host]["revision"],
            }
        )
    preview = {
        "state": "preview",
        "format": FORMAT,
        "kind": "agent-setup",
        "project": project,
        **identity,
        "repository_identity": binding["repository_identity"],
        "checkout_identity": binding["checkout_identity"],
        "hosts": list(hosts),
        "epoch": epoch,
        "sources": sources,
        "selection": selection,
        "policy_digest": _policy().digest,
        "disclosure": DISCLOSURE,
        "changes": previews,
        "background_services_added": 0,
        "native_host_verified": False,
        "model_use_verified": False,
    }
    preview["plan_digest"] = _digest(preview)
    return SetupPlan(
        preview,
        options={
            "database": database,
            "project": project,
            "root": root,
            "home": home,
            "hosts": hosts,
        },
        hooks=hooks,
        mcp=mcp,
        grant_options=grants,
    )


def apply_setup(
    plan, *, expected_digest, allow_capture=False, allow_model_context=False
):
    if not isinstance(plan, SetupPlan):
        raise TypeError("setup requires a reconstructed local preview")
    if allow_capture is not True or allow_model_context is not True:
        raise ValueError("explicit capture and model-context consent are both required")
    current = plan_setup(**plan.options)
    if expected_digest != current["plan_digest"] or dict(plan) != dict(current):
        raise ValueError("setup changed; review a fresh preview")
    database, project = current.options["database"], current.options["project"]
    with binding_gate(database, project):
        old = _load(database, project)
        if old and old["state"] == "installed":
            # A repeat apply is not permission to silently re-enable a revoked bridge.
            for host in current["hosts"]:
                if (
                    _read_consent(consent_path(database, project, host)).get("enabled")
                    is not True
                ):
                    raise ValueError("bridge revoked; stop and review setup again")
            return {
                "state": "installed",
                "idempotent": True,
                "native_host_verified": False,
            }
        receipt = {
            key: current[key]
            for key in (
                "format",
                "kind",
                "project",
                "database",
                "database_identity",
                "root",
                "root_identity",
                "home",
                "repository_identity",
                "checkout_identity",
                "hosts",
                "epoch",
                "sources",
                "selection",
                "plan_digest",
            )
        }
        receipt.update(
            state="prepared",
            capture_allowed=True,
            mcp=(old or {}).get("mcp", {}),
            hooks={},
        )
        _save(database, project, receipt)
        try:
            for host in current["hosts"]:
                if host not in receipt["mcp"]:
                    host_plan = current.mcp[host]
                    result = apply_host_configuration(
                        host_plan,
                        {"approved": True, "plan_digest": host_plan["plan_digest"]},
                    )
                    receipt["mcp"][host] = {
                        "receipt_path": result["receipt_path"],
                        "spec_digest": _digest(
                            host_plan["effective_configuration_change"]
                        ),
                    }
                    _save(database, project, receipt)
                install_adapter(current.hooks[host])
                receipt["hooks"][host] = current.hooks[host].installation_id
                _save(database, project, receipt)
            with (
                database_writer_lease(database, timeout_seconds=2),
                closing(db.connect(database)) as conn,
            ):
                policy = _policy()
                register_policy(
                    conn,
                    project=project,
                    active_root=current.options["root"],
                    policy_id="agent-flow-seven-day-text",
                    policy_version=1,
                    policy=policy,
                )
                for host, source_id in current["sources"].items():
                    register_source(
                        conn,
                        project=project,
                        active_root=current.options["root"],
                        source=CaptureSource(
                            source_id=source_id,
                            adapter="generic",
                            adapter_version="1",
                            installation_scope="api",
                            config_fingerprint=current.hooks[host].target_fingerprint,
                        ),
                        policy_digest=policy.digest,
                    )
            for host, options in current.grant_options.items():
                preview = preview_bridge(**options)
                enable_bridge(
                    **options,
                    expected_digest=preview["plan_digest"],
                    allow_model_context=True,
                )
            receipt["state"] = "installed"
            _save(database, project, receipt)
        except Exception:
            for host in current["hosts"]:
                disable_bridge(database, project, host)
            receipt["state"] = "partial"
            _save(database, project, receipt)
            raise
    return {
        "state": "installed",
        "idempotent": False,
        "native_host_verified": False,
        "activation": "Review native hook trust, restart each host and use a fresh session. Run agent-setup status to inspect evidence.",
        "capture_state": "waiting_for_capture",
        "background_services_added": 0,
    }


def stop_setup(database, project):
    database = Path(database)
    with binding_gate(database, project):
        receipt = _load(database, project)
        if receipt is None:
            return {"state": "not_enabled"}
        receipt["state"] = "stopped"
        receipt["capture_allowed"] = False
        _save(database, project, receipt)
        for host in receipt["hosts"]:
            disable_bridge(database, project, host)
    return {"state": "stopped", "settings_removed": False, "history_deleted": False}


def setup_status(database, project):
    database = Path(database)
    receipt = _load(database, project)
    result = {
        "state": "not_enabled",
        "capture_events": 0,
        "native_host_verified": False,
        "model_use_verified": False,
    }
    if receipt is None:
        return result
    result["state"] = receipt["state"]
    if receipt["state"] != "installed":
        return result
    # Rebuild the read-only preview to verify owned settings and identities.
    plan = plan_setup(
        database,
        project,
        Path(receipt["root"]),
        home=Path(receipt["home"]),
        hosts=receipt["hosts"],
    )
    with closing(db.connect_readonly(database)) as conn:
        project_id = conn.execute(
            "SELECT id FROM projects WHERE name=?", (project,)
        ).fetchone()[0]
        result["hosts"] = {}
        for host, source in receipt["sources"].items():
            count = conn.execute(
                "SELECT COUNT(*) FROM capture_events WHERE project_id=? AND source_id=?",
                (project_id, source),
            ).fetchone()[0]
            grant_enabled = (
                _read_consent(consent_path(database, project, host)).get("enabled")
                is True
            )
            result["hosts"][host] = {
                "capture_events": count,
                "recall_enabled": grant_enabled,
            }
            result["capture_events"] += count
    available = any(change["recall_preview"] for change in plan["changes"])
    result["state"] = "recall_available" if available else "waiting_for_capture"
    if not all(host["recall_enabled"] for host in result["hosts"].values()):
        result["state"] = "recall_disabled"
    return result


def plan_removal(database, project):
    database = _unlinked_path(Path(database))
    receipt = _load(database, project)
    changes = []
    if receipt:
        if _identity(database) != receipt["database_identity"]:
            raise ValueError("setup database identity changed")
        home = _unlinked_path(Path(receipt["home"]))
        name = f"rta-flow-{_digest([str(database), project])[:12]}"
        for host in receipt["hosts"]:
            target = home / (
                ".codex/hooks.json" if host == "codex" else ".claude/settings.json"
            )
            if host in receipt.get("hooks", {}) and host not in receipt.get(
                "removed_hooks", []
            ):
                _document, raw, _exists = _bounded_config(target)
                changes.append(
                    {
                        "host": host,
                        "component": "hooks",
                        "target": str(target),
                        "before": _digest(raw.hex()),
                    }
                )
            if host in receipt.get("mcp", {}) and host not in receipt.get(
                "removed_mcp", []
            ):
                plan = plan_host_configuration(
                    host,
                    _mcp_target(home, host),
                    name,
                    {},
                    action="remove",
                    owned_configuration_receipt=Path(
                        receipt["mcp"][host]["receipt_path"]
                    ),
                )
                changes.append({"host": host, "component": "mcp", "plan": dict(plan)})
    result = {
        "state": "removal_preview",
        "changes": changes,
        "receipt_digest": _digest(receipt),
        "history_deleted": False,
        "consent_will_be_revoked": True,
    }
    result["plan_digest"] = _digest(result)
    return result


def remove_setup(database, project, *, expected_digest):
    database = Path(database)
    with binding_gate(database, project):
        plan = plan_removal(database, project)
        if plan["plan_digest"] != expected_digest:
            raise ValueError("removal changed; review a fresh preview")
        receipt = _load(database, project)
        if not receipt or receipt["state"] == "removed":
            return {"state": "removed", "idempotent": True}
        receipt.update(state="removal_partial", capture_allowed=False)
        receipt.setdefault("removed_hooks", [])
        receipt.setdefault("removed_mcp", [])
        _save(database, project, receipt)
        for host in receipt["hosts"]:
            disable_bridge(database, project, host)
        for change in plan["changes"]:
            host = change["host"]
            if change["component"] == "hooks":
                _document, raw, _exists = _bounded_config(Path(change["target"]))
                if _digest(raw.hex()) != change["before"]:
                    raise ValueError("hook settings changed during removal")
                remove_adapter(
                    brain_path=database, installation_id=receipt["hooks"][host]
                )
                receipt["removed_hooks"].append(host)
            else:
                prepared = plan_host_configuration(
                    host,
                    _mcp_target(Path(receipt["home"]), host),
                    change["plan"]["server_name"],
                    {},
                    action="remove",
                    owned_configuration_receipt=Path(
                        receipt["mcp"][host]["receipt_path"]
                    ),
                )
                apply_host_configuration(
                    prepared,
                    {"approved": True, "plan_digest": change["plan"]["plan_digest"]},
                )
                receipt["removed_mcp"].append(host)
            _save(database, project, receipt)
        receipt.update(state="removed", mcp={}, hooks={})
        _save(database, project, receipt)
    return {"state": "removed", "idempotent": False, "history_deleted": False}


def _scope(receipt, database, project, host, event, cwd):
    if (
        not receipt
        or receipt.get("state") != "installed"
        or receipt.get("capture_allowed") is not True
    ):
        return "not_enabled"
    if not isinstance(event, dict) or host not in receipt["hosts"]:
        return "invalid_event"
    root = _unlinked_path(Path(receipt["root"]))
    actual = _unlinked_path(Path(cwd))
    event_cwd = event.get("cwd")
    if (
        not isinstance(event_cwd, str)
        or not Path(event_cwd).is_absolute()
        or _unlinked_path(Path(event_cwd)) != actual
        or not actual.is_relative_to(root)
        or _unlinked_path(database) != Path(receipt["database"])
        or _identity(database) != receipt["database_identity"]
        or _identity(root) != receipt["root_identity"]
    ):
        return "scope_mismatch"
    session = event.get("session_id")
    if (
        not isinstance(session, str)
        or not 1 <= len(session) <= 256
        or any(ord(c) < 32 for c in session)
    ):
        return "invalid_event"
    with closing(db.connect_readonly(database)) as conn:
        _require_current_schema(conn)
        binding = verify_capture_project_binding(
            conn, project=project, active_root=root
        )
    if any(
        binding[key] != receipt[key]
        for key in ("repository_identity", "checkout_identity")
    ):
        return "scope_mismatch"
    return None


def _require_current_schema(conn):
    if conn.execute("PRAGMA user_version").fetchone()[0] != db.SCHEMA_VERSION:
        raise ValueError(
            "agent setup needs the current schema; use backup-first lifecycle migration"
        )


def drain_setup(database, project):
    """Best effort; a busy writer leaves the durable queue for a later capture/sync."""
    database = Path(database)
    receipt = _load(database, project)
    if (
        not receipt
        or receipt["state"] != "installed"
        or not receipt.get("capture_allowed")
    ):
        return {"state": "not_enabled"}
    _scope_error = _scope(
        receipt,
        database,
        project,
        receipt["hosts"][0],
        {"session_id": "sync", "cwd": receipt["root"]},
        Path(receipt["root"]),
    )
    if _scope_error:
        return {"state": _scope_error}
    try:
        with binding_gate(database, project):
            if _load(database, project) != receipt:
                return {"state": "consent_changed"}
            with (
                database_writer_lease(database, timeout_seconds=0.25),
                closing(db.connect(database)) as conn,
            ):
                conn.execute("PRAGMA busy_timeout=250")
                _require_current_schema(conn)
                result = capture_cycle(
                    conn,
                    database,
                    max_events=8,
                    max_seconds=0.15,
                    source_filter=frozenset(
                        (project, source) for source in receipt["sources"].values()
                    ),
                )
        return {
            "state": "processed",
            **{
                key: result[key]
                for key in ("events_inserted", "duplicates", "failures", "quarantined")
            },
        }
    except (TimeoutError, sqlite3.OperationalError):
        return {"state": "queued", "events_inserted": 0, "duplicates": 0}


def handle_hook(database, project, host, event, *, cwd):
    database = Path(database)
    try:
        if len(_json(event).encode("utf-8")) > MAX_INPUT_BYTES:
            return _empty("invalid_input")
        receipt = _load(database, project)
        problem = _scope(receipt, database, project, host, event, cwd)
        if problem:
            result = _empty(problem)
            if problem in {"scope_mismatch", "not_enabled"}:
                result["output"] = {}
            return result
        kind = event.get("hook_event_name")
        if kind == "SessionStart":
            result = recall_bridge(database, project, host, event, cwd=cwd)
            if _load(database, project) != receipt:
                return _empty("consent_changed")
            return result
        if kind not in {"UserPromptSubmit", "Stop"}:
            return _empty("unsupported_event")
        text = event.get(
            "prompt" if kind == "UserPromptSubmit" else "last_assistant_message"
        )
        if not isinstance(text, str) or not text.strip():
            return _empty("no_capture_text")
        source_id = receipt["sources"][host]
        session = _digest([host, event["session_id"]])
        # Exact replay suppression. Hosts without a turn ID coalesce repeated
        # identical text in one session instead of inventing a distinct turn.
        cursor = _digest([session, kind, event.get("turn_id"), text])
        record = {
            "session_id": session,
            "source_cursor": cursor,
            "cursor_kind": "opaque",
            "observed_at": datetime.now(UTC).isoformat(),
            "vendor_event": "prompt" if kind == "UserPromptSubmit" else "agent_message",
            "payload": {
                "text": text,
                "role": "user" if kind == "UserPromptSubmit" else "assistant",
            },
        }
        with binding_gate(database, project):
            if _load(database, project) != receipt:
                return _empty("consent_changed")
            with closing(db.connect_readonly(database)) as conn:
                prepared = prepare_capture_spool_record(
                    conn,
                    project=project,
                    active_root=Path(receipt["root"]),
                    source_id=source_id,
                    record=record,
                    original_bytes=len(text.encode("utf-8")),
                )
            result = CaptureSpool(database).publish(
                source_id,
                prepared,
                project=project,
                allowed_fields=CAPTURE_INGRESS_FIELDS,
            )
        if result.status != "stored":
            return _empty("capture_" + result.status)
        drain_setup(database, project)
        with closing(db.connect_readonly(database)) as conn:
            stored = conn.execute(
                "SELECT 1 FROM capture_events e JOIN projects p ON p.id=e.project_id "
                "WHERE p.name=? AND e.source_id=? AND e.source_cursor=? LIMIT 1",
                (project, source_id, cursor),
            ).fetchone()
        state = "captured" if stored else "queued"
        return {
            "state": state,
            "output": {}
            if state == "captured"
            else {
                "systemMessage": "Rta-Smriti capture queued; not available for recall yet. Run agent-setup sync."
            },
            "delivery_verified": False,
            "database_writes": state == "captured",
        }
    except (ValueError, TypeError, OSError, RuntimeError, sqlite3.Error, KeyError):
        return _empty("capture_unavailable")
