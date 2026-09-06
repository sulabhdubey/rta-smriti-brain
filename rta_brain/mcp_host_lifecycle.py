"""Digest-confirmed MCP host configuration lifecycle."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import stat
import sys
import sysconfig
import tomllib
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .platform_paths import canonicalize_system_root_alias
from .runtime_control import (
    create_secret,
    is_safe_regular_file,
    prepare_control_dir,
    read_secret,
)

MAX_HOST_CONFIG_BYTES = 1_048_576
MAX_HOST_RECEIPT_BYTES = 1_048_576
MAX_SESSION_ID_CHARS = 256
MAX_TOOL_NAMES = 256
MAX_TOOL_NAME_CHARS = 128
MAX_HOST_VERSION_CHARS = 128
MAX_OBSERVED_EVENTS = 32
MAX_MANAGED_RECEIPTS = 256
MAX_SERVER_ARGUMENTS = 128
MAX_SERVER_VALUE_CHARS = 4096
MAX_LAUNCHER_BYTES = 536_870_912
FRESH_SESSION_CHALLENGE_TTL_SECONDS = 300
HOST_LIFECYCLE_SCHEMA = "rta-smriti.mcp-host-lifecycle/v1"

_FORBIDDEN_PYTHON_ENVIRONMENT = {"PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"}

_TARGET_POLICIES: dict[str, tuple[tuple[tuple[str, ...], str, str], ...]] = {
    "codex": ((('.codex', 'config.toml'), 'project-or-user', '.codex/config.toml'),),
    "claude-code": (
        ((".mcp.json",), "project", ".mcp.json"),
        ((".claude.json",), "local-or-user", "~/.claude.json"),
    ),
    "cursor": ((('.cursor', 'mcp.json'), 'project', '.cursor/mcp.json'),),
    "zed": (
        ((".config", "zed", "settings.json"), "user", "Zed settings.json"),
        (("zed", "settings.json"), "user", "Zed settings.json"),
    ),
    "opencode": (
        ((".config", "opencode", "opencode.json"), "user", "opencode.json"),
        (("opencode", "opencode.json"), "user", "opencode.json"),
        (("opencode.json",), "project", "opencode.json"),
    ),
    "gemini-cli": ((('.gemini', 'settings.json'), 'project-or-user', '.gemini/settings.json'),),
}

_SECRET_OR_LOCAL_OPTION = re.compile(
    r"(?:token|secret|password|credential|api[-_]?key|brain[-_]?dir|db|database|root|path|session|cwd)",
    re.IGNORECASE,
)

_HOST_PROFILES: dict[str, dict[str, Any]] = {
    "codex": {
        "profile_id": "codex",
        "official_documentation": "https://learn.chatgpt.com/docs/extend/mcp?surface=cli",
        "reviewed_on": "2026-09-05",
        "format": "toml",
        "transports": ["stdio", "streamable-http"],
        "activation_steps": ["save_configuration", "restart_host", "open_fresh_task"],
        "fresh_session_proof": ["server_visible", "tools_visible", "atlas_search_succeeds"],
        "container": "mcp_servers",
        "scope_guidance": {
            "options": ["global", "trusted-project"],
            "default": "trusted-project",
            "configuration_targets": {
                "global": "~/.codex/config.toml",
                "trusted-project": ".codex/config.toml",
            },
        },
        "configuration_guidance": {
            "format": "toml",
            "container": "mcp_servers",
            "registration_command": "codex mcp add",
            "server_fields": [
                "command",
                "args",
                "url",
                "bearer_token_env_var",
                "enabled",
                "enabled_tools",
                "disabled_tools",
                "startup_timeout_sec",
                "tool_timeout_sec",
                "required",
            ],
            "server_alias_pattern": r"[A-Za-z0-9._-]{1,80}",
            "server_alias_error": "MCP server name contains unsupported characters",
        },
        "activation_guidance": {
            "post_write_state": "restart_required",
            "steps": ["save_configuration", "restart_host", "open_fresh_task"],
            "inspection_steps": ["codex_mcp_list", "slash_mcp", "fresh_task_tool_call"],
        },
        "tool_filter_guidance": {
            "controls": [
                "enabled",
                "enabled_tools",
                "disabled_tools",
                "approval_policy",
                "tool_approval_overrides",
            ],
            "default_policy": "least_privilege_explicit_allow_and_deny",
        },
    },
    "claude-code": {
        "profile_id": "claude-code",
        "official_documentation": "https://docs.anthropic.com/en/docs/claude-code/mcp",
        "reviewed_on": "2026-09-05",
        "format": "json",
        "transports": ["stdio", "sse", "streamable-http"],
        "activation_steps": [
            "save_configuration",
            "approve_project_trust_if_required",
            "inspect_mcp_status",
            "open_fresh_session",
        ],
        "fresh_session_proof": ["server_visible", "tools_visible", "atlas_search_succeeds"],
        "container": "mcpServers",
        "scope_guidance": {
            "options": ["local", "project", "user"],
            "default": "local",
            "configuration_targets": {
                "local": "claude mcp --scope local",
                "project": ".mcp.json",
                "user": "claude mcp --scope user",
            },
        },
        "configuration_guidance": {
            "format": "json",
            "container": "mcpServers",
            "registration_command": "claude mcp add",
            "server_fields": ["type", "command", "args", "env", "url", "headers"],
            "server_alias_pattern": r"[A-Za-z0-9._-]{1,80}",
            "server_alias_error": "MCP server name contains unsupported characters",
        },
        "activation_guidance": {
            "post_write_state": "approval_check_required",
            "steps": [
                "save_configuration",
                "approve_project_trust_if_required",
                "inspect_mcp_status",
                "open_fresh_session",
            ],
            "inspection_steps": ["slash_mcp", "fresh_session_tool_call"],
        },
        "tool_filter_guidance": {
            "controls": ["project_trust", "tool_output_limits", "scope_priority"],
            "default_policy": "approve_project_scope_before_tool_discovery",
        },
    },
    "cursor": {
        "profile_id": "cursor",
        "official_documentation": "https://docs.cursor.com/context/model-context-protocol",
        "reviewed_on": "2026-09-05",
        "format": "json",
        "transports": ["stdio", "sse", "streamable-http"],
        "activation_steps": [
            "save_configuration",
            "inspect_server_and_tool_controls",
            "open_fresh_agent_session",
        ],
        "fresh_session_proof": ["server_visible", "tools_visible", "atlas_search_succeeds"],
        "container": "mcpServers",
        "scope_guidance": {
            "options": ["project", "user"],
            "default": "project",
            "configuration_targets": {
                "project": ".cursor/mcp.json",
                "user": "~/.cursor/mcp.json",
            },
        },
        "configuration_guidance": {
            "format": "json",
            "container": "mcpServers",
            "registration_command": None,
            "server_fields": ["command", "args", "env", "url", "headers"],
            "server_alias_pattern": r"[A-Za-z0-9._-]{1,80}",
            "server_alias_error": "MCP server name contains unsupported characters",
        },
        "activation_guidance": {
            "post_write_state": "activation_check_required",
            "steps": [
                "save_configuration",
                "inspect_server_and_tool_controls",
                "open_fresh_agent_session",
            ],
            "inspection_steps": ["server_list", "tool_list", "fresh_agent_tool_call"],
        },
        "tool_filter_guidance": {
            "controls": ["server_enablement", "tool_enablement", "tool_approvals"],
            "default_policy": "approvals_enabled_and_only_required_tools_visible",
        },
    },
    "zed": {
        "profile_id": "zed",
        "official_documentation": "https://zed.dev/docs/ai/mcp",
        "reviewed_on": "2026-09-05",
        "format": "json",
        "transports": ["stdio"],
        "activation_steps": ["save_configuration", "inspect_server_panel", "open_fresh_agent_thread"],
        "fresh_session_proof": ["server_active", "tools_visible", "atlas_search_succeeds"],
        "container": "context_servers",
        "scope_guidance": {
            "options": ["settings"],
            "default": "settings",
            "configuration_targets": {"settings": "settings.json:context_servers"},
        },
        "configuration_guidance": {
            "format": "json",
            "container": "context_servers",
            "registration_command": None,
            "server_fields": ["command", "args", "env"],
            "server_alias_pattern": r"[A-Za-z0-9._-]{1,80}",
            "server_alias_error": "MCP server name contains unsupported characters",
        },
        "activation_guidance": {
            "post_write_state": "server_panel_check_required",
            "steps": [
                "save_configuration",
                "inspect_server_panel",
                "open_fresh_agent_thread",
            ],
            "inspection_steps": [
                "server_panel_status",
                "dynamic_tool_list_refresh",
                "fresh_agent_tool_call",
            ],
        },
        "tool_filter_guidance": {
            "controls": ["tool_confirmation", "mcp_tool_permissions", "agent_profiles"],
            "default_policy": "confirm_tools_and_constrain_with_agent_profile",
        },
    },
    "opencode": {
        "profile_id": "opencode",
        "official_documentation": "https://opencode.ai/docs/mcp-servers/",
        "reviewed_on": "2026-09-05",
        "format": "json",
        "transports": ["stdio", "streamable-http"],
        "activation_steps": ["save_configuration", "enable_server", "open_fresh_session"],
        "fresh_session_proof": ["server_enabled", "tools_visible", "atlas_search_succeeds"],
        "container": "mcp",
        "scope_guidance": {
            "options": ["host-configuration"],
            "default": "host-configuration",
            "configuration_targets": {
                "host-configuration": "opencode.json:mcp.<name>"
            },
        },
        "configuration_guidance": {
            "format": "json",
            "container": "mcp",
            "registration_command": None,
            "server_fields": [
                "type",
                "command",
                "cwd",
                "environment",
                "enabled",
                "url",
                "headers",
                "timeout",
                "code_mode",
            ],
            "server_alias_pattern": r"[A-Za-z0-9._-]{1,80}",
            "server_alias_error": "MCP server name contains unsupported characters",
        },
        "activation_guidance": {
            "post_write_state": "enablement_check_required",
            "steps": ["save_configuration", "enable_server", "open_fresh_session"],
            "inspection_steps": ["server_enabled", "selected_tool_tier_visible"],
        },
        "tool_filter_guidance": {
            "controls": ["enabled", "code_mode", "capability_profile"],
            "default_policy": "enable_only_needed_servers_and_minimal_tool_tier",
        },
    },
    "gemini-cli": {
        "profile_id": "gemini-cli",
        "official_documentation": (
            "https://github.com/google-gemini/gemini-cli/blob/main/"
            "docs/reference/configuration.md"
        ),
        "reviewed_on": "2026-09-05",
        "format": "json",
        "transports": ["stdio", "sse", "http"],
        "activation_steps": [
            "save_configuration",
            "restart_gemini_cli",
            "open_fresh_session",
        ],
        "fresh_session_proof": [
            "server_visible",
            "allow_listed_tools_visible",
            "atlas_search_succeeds",
        ],
        "container": "mcpServers",
        "scope_guidance": {
            "options": ["user", "project"],
            "default": "project",
            "configuration_targets": {
                "user": "~/.gemini/settings.json",
                "project": ".gemini/settings.json",
            },
        },
        "configuration_guidance": {
            "format": "json",
            "container": "mcpServers",
            "registration_command": "gemini mcp add",
            "server_fields": [
                "command",
                "args",
                "env",
                "cwd",
                "url",
                "httpUrl",
                "headers",
                "timeout",
                "trust",
                "description",
                "includeTools",
            ],
            "server_alias_pattern": r"[A-Za-z0-9.-]{1,80}",
            "server_alias_error": (
                "Gemini CLI MCP server aliases must not contain underscores or "
                "unsupported characters"
            ),
        },
        "activation_guidance": {
            "post_write_state": "restart_required",
            "steps": [
                "save_configuration",
                "restart_gemini_cli",
                "open_fresh_session",
            ],
            "inspection_steps": [
                "gemini_mcp_list",
                "allow_listed_tool_discovery",
                "fresh_session_tool_call",
            ],
        },
        "tool_filter_guidance": {
            "controls": ["trust", "includeTools"],
            "default_policy": "untrusted_with_explicit_tool_allow_list",
        },
    },
}


class HostConfigurationPlan(dict[str, Any]):
    """Serializable preview with private execution material excluded from JSON."""

    def __init__(
        self,
        payload: Mapping[str, Any],
        *,
        target: Path,
        proposed: bytes,
        original: bytes,
        path_binding: Mapping[str, Any],
        launcher_binding: Mapping[str, Any] | None = None,
        remove_target_after_apply: bool = False,
    ) -> None:
        super().__init__(payload)
        self._target = target
        self._proposed = proposed
        self._original = original
        self._path_binding = dict(path_binding)
        self._launcher_binding = (
            copy.deepcopy(dict(launcher_binding)) if launcher_binding else None
        )
        self._remove_target_after_apply = remove_target_after_apply
        self._sealed_execution_digest = _host_plan_execution_digest(self)


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_json(value: Mapping[str, Any]) -> str:
    return _digest_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _host_plan_execution_digest(plan: HostConfigurationPlan) -> str:
    public_body = {
        key: copy.deepcopy(value)
        for key, value in plan.items()
        if key not in {"status", "read_only", "plan_digest"}
    }
    private_body = {
        "target": str(plan._target),
        "proposed_digest": _digest_bytes(plan._proposed),
        "original_digest": _digest_bytes(plan._original),
        "path_binding": repr(plan._path_binding),
        "launcher_binding": repr(plan._launcher_binding),
        "remove_target_after_apply": bool(plan._remove_target_after_apply),
    }
    return _digest_json({
        "public_plan_digest": _digest_json(public_body),
        "private_execution": private_body,
    })


def _public_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(receipt)
    payload.pop("target_name", None)
    payload.pop("target_locator", None)
    payload.pop("receipt_authentication", None)
    payload.pop("launcher_binding", None)
    return payload


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _host_authority_root() -> Path:
    return Path.home() / ".rta-smriti" / "host-lifecycle-authority"


def _target_fingerprint(target: Path) -> str:
    canonical = os.path.normcase(
        os.path.abspath(os.path.normpath(str(target.expanduser())))
    )
    return _digest_bytes(canonical.encode("utf-8"))[:16]


def _target_authority_control(target: Path) -> Path:
    return _host_authority_root() / "targets" / _target_fingerprint(target)


@contextmanager
def _target_operation_claim(control: Path, target_fingerprint: str):
    """Hold a crash-releasing, cross-process claim for one host target."""

    claim_path = control / "claims" / f"{target_fingerprint}.lock"
    prepare_control_dir(claim_path.parent, label="MCP host operation claim")
    descriptor = os.open(claim_path, os.O_CREAT | os.O_RDWR, 0o600)
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("MCP host operation claim is unsafe")
        if os.name == "nt":
            import msvcrt

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise PermissionError(
                    "MCP host configuration operation is already in progress"
                ) from exc
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise PermissionError(
                    "MCP host configuration operation is already in progress"
                ) from exc
        locked = True
        yield
    finally:
        if locked:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _host_authority_secret() -> bytes:
    root = _host_authority_root().expanduser().resolve()
    prepare_control_dir(root, label="MCP host authority")
    secret_path = root / "receipt-authentication.secret"
    if not secret_path.exists():
        try:
            create_secret(
                secret_path,
                secrets.token_hex(32),
                label="MCP host receipt authority",
            )
        except FileExistsError:
            pass
    secret = read_secret(secret_path, label="MCP host receipt authority")
    if not re.fullmatch(r"[0-9a-f]{64}", secret):
        raise ValueError("MCP host receipt authority is invalid")
    return bytes.fromhex(secret)


def _receipt_authentication(receipt: Mapping[str, Any]) -> dict[str, str]:
    unsigned = dict(receipt)
    unsigned.pop("receipt_authentication", None)
    secret = _host_authority_secret()
    message = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "algorithm": "hmac-sha256",
        "authority_fingerprint": _digest_bytes(secret)[:16],
        "mac": hmac.new(secret, message, hashlib.sha256).hexdigest(),
    }


def _authenticate_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    authenticated = copy.deepcopy(dict(receipt))
    authenticated["receipt_authentication"] = _receipt_authentication(authenticated)
    return authenticated


def _verify_receipt_authentication(receipt: Mapping[str, Any]) -> None:
    authentication = receipt.get("receipt_authentication")
    if not isinstance(authentication, Mapping):
        raise ValueError("MCP host receipt authentication is missing")
    expected = _receipt_authentication(receipt)
    if (
        authentication.get("algorithm") != expected["algorithm"]
        or authentication.get("authority_fingerprint")
        != expected["authority_fingerprint"]
        or not hmac.compare_digest(
            str(authentication.get("mac") or ""), expected["mac"]
        )
    ):
        raise ValueError("MCP host receipt authentication is invalid")


def host_profile(profile_id: str) -> dict[str, Any]:
    key = str(profile_id).strip().casefold()
    if key not in _HOST_PROFILES:
        raise ValueError(f"unsupported MCP host profile: {profile_id}")
    return copy.deepcopy(_HOST_PROFILES[key])


def host_profiles() -> dict[str, dict[str, Any]]:
    return copy.deepcopy(_HOST_PROFILES)


def _path_parts(path: Path) -> tuple[str, ...]:
    return tuple(part.casefold() for part in path.parts)


def _classify_target(profile: Mapping[str, Any], target: Path) -> dict[str, str]:
    profile_id = str(profile["profile_id"])
    parts = _path_parts(target)
    for suffix, classification, policy in _TARGET_POLICIES[profile_id]:
        folded = tuple(part.casefold() for part in suffix)
        if len(parts) >= len(folded) and parts[-len(folded) :] == folded:
            if (
                profile_id == "claude-code"
                and folded == (".claude.json",)
                and target != Path.home() / ".claude.json"
            ):
                continue
            resolved_classification = classification
            home_target = Path.home().joinpath(*suffix)
            if classification == "project-or-user":
                resolved_classification = "user" if target == home_target else "project"
            if profile_id == "cursor" and target == Path.home() / ".cursor" / "mcp.json":
                resolved_classification = "user"
            return {
                "classification": resolved_classification,
                "policy": policy,
                "format": str(profile["format"]),
                "file_name": target.name,
            }
    display_name = {
        "codex": "Codex",
        "claude-code": "Claude Code",
        "cursor": "Cursor",
        "zed": "Zed",
        "opencode": "OpenCode",
        "gemini-cli": "Gemini CLI",
    }[profile_id]
    policies = ", ".join(item[2] for item in _TARGET_POLICIES[profile_id])
    raise ValueError(
        f"MCP host target does not match the documented {display_name} policy: {policies}"
    )


def _identity(path: Path, *, directory: bool = False) -> tuple[int, int, int]:
    try:
        observed = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise PermissionError("MCP host path identity is unavailable") from exc
    attributes = int(getattr(observed, "st_file_attributes", 0))
    linked = stat.S_ISLNK(observed.st_mode) or bool(attributes & 0x400)
    expected_type = stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode)
    if linked or not expected_type or (not directory and observed.st_nlink != 1):
        raise ValueError("MCP host path identity is linked or unsafe")
    return (int(observed.st_dev), int(observed.st_ino), stat.S_IFMT(observed.st_mode))


def _capture_path_binding(target: Path) -> dict[str, Any]:
    parent = target.parent
    ancestor = parent
    while not ancestor.exists():
        if ancestor == ancestor.parent:
            raise ValueError("MCP host configuration has no stable parent ancestor")
        ancestor = ancestor.parent
    ancestor_identity = _identity(ancestor, directory=True)
    parent_identity = _identity(parent, directory=True) if parent.exists() else None
    target_identity = _identity(target) if target.exists() else None
    return {
        "ancestor": ancestor,
        "ancestor_identity": ancestor_identity,
        "parent_identity": parent_identity,
        "target_identity": target_identity,
    }


def _assert_path_binding(
    target: Path,
    binding: Mapping[str, Any],
    *,
    runtime_parent_identity: tuple[int, int, int] | None = None,
) -> None:
    ancestor = binding["ancestor"]
    if _identity(ancestor, directory=True) != binding["ancestor_identity"]:
        raise PermissionError("MCP host parent identity changed after preview")
    expected_parent = binding["parent_identity"]
    if expected_parent is None:
        if runtime_parent_identity is None:
            if target.parent.exists():
                raise PermissionError("MCP host parent identity changed after preview")
        elif _identity(target.parent, directory=True) != runtime_parent_identity:
            raise PermissionError("MCP host parent identity changed after preview")
    elif _identity(target.parent, directory=True) != expected_parent:
        raise PermissionError("MCP host parent identity changed after preview")
    expected_target = binding["target_identity"]
    if expected_target is None:
        if target.exists():
            raise PermissionError("MCP host target identity changed after preview")
    elif not target.exists() or _identity(target) != expected_target:
        raise PermissionError("MCP host target identity changed after preview")


def _read_target(target: Path) -> bytes:
    if not target.exists():
        return b""
    if not is_safe_regular_file(target):
        raise ValueError("MCP host configuration must be a private regular file")
    if target.stat().st_size > MAX_HOST_CONFIG_BYTES:
        raise ValueError("MCP host configuration exceeds the size limit")
    return target.read_bytes()


def _read_target_stable(target: Path) -> tuple[bytes, tuple[int, int, int] | None]:
    if not target.exists():
        return b"", None
    before = _identity(target)
    observed = target.stat(follow_symlinks=False)
    content = _read_target(target)
    after = _identity(target)
    final = target.stat(follow_symlinks=False)
    if (
        before != after
        or observed.st_size != final.st_size
        or observed.st_mtime_ns != final.st_mtime_ns
    ):
        raise PermissionError("MCP host target changed while being inspected")
    return content, before


def _read_json_file(path: Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    if not is_safe_regular_file(path):
        raise ValueError(f"{label} is missing or unsafe")
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{label} exceeds the size limit")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} root must be an object")  # noqa: TRY004
    return payload


def _bounded_server_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"MCP host {label} must be a non-empty string")
    if len(value) > MAX_SERVER_VALUE_CHARS:
        raise ValueError(f"MCP host {label} exceeds the size limit")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"MCP host {label} contains a control character")
    return value


def _is_python_launcher(command: str, arguments: list[str]) -> bool:
    executable = Path(command).name.casefold()
    python_name = executable in {
        "python", "python.exe", "python3", "python3.exe", "py", "py.exe",
    } or re.fullmatch(r"python\d+(?:\.\d+)*(?:\.exe)?", executable)
    if not python_name:
        return False
    normalized = [item.casefold() for item in arguments]
    for index, item in enumerate(normalized[:-1]):
        if item == "-m" and normalized[index + 1] == "rta_brain.mcp_server":
            return True
    return False


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _trusted_launcher_roots() -> tuple[Path, ...]:
    candidates = {
        Path(sys.executable).resolve().parent,
    }
    scripts = sysconfig.get_path("scripts")
    if scripts:
        candidates.add(Path(scripts).resolve())
    return tuple(sorted(candidates, key=str))


def _stable_file_binding(path: Path, *, label: str) -> dict[str, Any]:
    try:
        canonical = path.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{label} is missing") from exc
    before_identity = _identity(canonical)
    before = canonical.stat(follow_symlinks=False)
    if before.st_size > MAX_LAUNCHER_BYTES:
        raise ValueError(f"{label} exceeds the size limit")
    digest = hashlib.sha256()
    with canonical.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    after_identity = _identity(canonical)
    after = canonical.stat(follow_symlinks=False)
    if (
        before_identity != after_identity
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise PermissionError(f"{label} changed while being inspected")
    identity_fingerprint = _digest_json(
        {
            "device": before_identity[0],
            "inode": before_identity[1],
            "type": before_identity[2],
        }
    )
    return {
        "canonical_path": str(canonical),
        "path_fingerprint": _digest_bytes(
            os.path.normcase(str(canonical)).encode("utf-8")
        ),
        "content_sha256": digest.hexdigest(),
        "identity_fingerprint": identity_fingerprint,
        "size": int(before.st_size),
    }


def _public_file_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: binding[key]
        for key in (
            "path_fingerprint",
            "content_sha256",
            "identity_fingerprint",
            "size",
        )
    }


def _canonicalize_launcher(
    command: str,
    arguments: list[str],
    environment: Any,
) -> tuple[str, list[str], str]:
    executable = Path(command).name.casefold()
    python_launch = _is_python_launcher(command, arguments)
    if python_launch:
        module_indices = [
            index
            for index, item in enumerate(arguments[:-1])
            if item.casefold() == "-m"
            and arguments[index + 1].casefold() == "rta_brain.mcp_server"
        ]
        if len(module_indices) != 1:
            raise ValueError("MCP host Python module launch shape is invalid")
        module_index = module_indices[0]
        interpreter_prefix = arguments[:module_index]
        if interpreter_prefix not in ([], ["-I"]):
            raise ValueError(
                "MCP host Python launcher permits only isolated mode before -m"
            )
        if Path(command).is_absolute():
            try:
                if not os.path.samefile(Path(command), Path(sys.executable)):
                    raise ValueError(
                        "MCP host Python launcher must be the current authenticated runtime"
                    )
            except OSError as exc:
                raise ValueError("MCP host Python launcher is missing") from exc
        if isinstance(environment, Mapping):
            forbidden = sorted(
                key
                for key in environment
                if str(key).upper() in _FORBIDDEN_PYTHON_ENVIRONMENT
            )
            if forbidden:
                raise ValueError(
                    "MCP host Python launcher rejects import-path environment overrides"
                )
        isolated_arguments = list(arguments)
        if not interpreter_prefix:
            isolated_arguments.insert(module_index, "-I")
        return str(Path(sys.executable).resolve()), isolated_arguments, "python"

    direct_launchers = {
        "rta-brain",
        "rta-brain.exe",
        "rta-brain.cmd",
        "rta-brain-mcp",
        "rta-brain-mcp.exe",
        "rta-brain-mcp.cmd",
        "rta-brain-mcp.py",
    }
    if executable not in direct_launchers:
        raise ValueError("MCP host launcher must execute the Rta-Smriti MCP server")
    discovered = Path(command) if Path(command).is_absolute() else None
    if discovered is None:
        located = shutil.which(command)
        if not located:
            raise ValueError("MCP host launcher is not installed")
        discovered = Path(located)
    try:
        canonical = discovered.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ValueError("MCP host launcher is missing") from exc
    if not any(
        _path_is_within(canonical, root) for root in _trusted_launcher_roots()
    ):
        raise ValueError("MCP host launcher is outside a trusted runtime root")
    if executable == "rta-brain-mcp.py" and arguments:
        raise ValueError(
            "Rta-Smriti MCP script launcher does not accept embedded host arguments"
        )
    return str(canonical), list(arguments), "direct"


def _launcher_parts(server: Mapping[str, Any]) -> tuple[str, list[str]]:
    command = server.get("command")
    if isinstance(command, list):
        if not command:
            raise ValueError("MCP host launcher command is missing")
        return str(command[0]), [str(item) for item in command[1:]]
    return str(command), [str(item) for item in server.get("args", [])]


def _capture_launcher_binding(server: Mapping[str, Any]) -> dict[str, Any]:
    command, arguments = _launcher_parts(server)
    executable = _stable_file_binding(Path(command), label="MCP host launcher")
    binding: dict[str, Any] = {
        "kind": "python" if _is_python_launcher(command, arguments) else "direct",
        "executable": executable,
    }
    if binding["kind"] == "python":
        module = _stable_file_binding(
            Path(__file__).with_name("mcp_server.py"),
            label="Rta-Smriti MCP module",
        )
        binding["module"] = module
    return binding


def _public_launcher_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    payload = {
        "kind": binding["kind"],
        "executable": _public_file_binding(binding["executable"]),
    }
    if "module" in binding:
        payload["module"] = _public_file_binding(binding["module"])
    return payload


def _assert_launcher_binding(binding: Mapping[str, Any]) -> None:
    current = _stable_file_binding(
        Path(str(binding["executable"]["canonical_path"])),
        label="MCP host launcher",
    )
    if _public_file_binding(current) != _public_file_binding(binding["executable"]):
        raise PermissionError("MCP host launcher identity changed after preview")
    if "module" in binding:
        module = _stable_file_binding(
            Path(str(binding["module"]["canonical_path"])),
            label="Rta-Smriti MCP module",
        )
        if _public_file_binding(module) != _public_file_binding(binding["module"]):
            raise PermissionError("Rta-Smriti MCP module identity changed after preview")


def _normalize_server_configuration(
    profile: Mapping[str, Any],
    server: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(server, Mapping):
        raise ValueError("MCP host server configuration must be an object")  # noqa: TRY004
    allowed = set(profile["configuration_guidance"]["server_fields"])
    accepted_input = allowed | ({"args"} if profile["profile_id"] == "opencode" else set())
    unsupported = sorted(str(key) for key in server if key not in accepted_input)
    if unsupported:
        raise ValueError(
            "MCP host configuration contains an unsupported server field: "
            + ", ".join(unsupported)
        )
    command = _bounded_server_text(server.get("command"), label="command")
    raw_arguments = server.get("args", [])
    if not isinstance(raw_arguments, list) or len(raw_arguments) > MAX_SERVER_ARGUMENTS:
        raise ValueError("MCP host arguments must be a bounded list")
    arguments = [
        _bounded_server_text(item, label="argument") for item in raw_arguments
    ]
    for remote_field in ("url", "httpUrl"):
        if server.get(remote_field):
            raise ValueError(
                "MCP host lifecycle supports only the local Rta-Smriti launcher"
            )
    for mapping_field in ("env", "environment", "headers"):
        value = server.get(mapping_field)
        if value is None:
            continue
        if not isinstance(value, Mapping) or len(value) > 128:
            raise ValueError(f"MCP host {mapping_field} must be a bounded object")
        for key, item in value.items():
            _bounded_server_text(key, label=f"{mapping_field} key")
            _bounded_server_text(item, label=f"{mapping_field} value")
    for boolean_field in ("enabled", "trust", "required", "code_mode"):
        if boolean_field in server and not isinstance(server[boolean_field], bool):
            raise ValueError(f"MCP host {boolean_field} must be a boolean")
    for list_field in ("enabled_tools", "disabled_tools", "includeTools"):
        value = server.get(list_field)
        if value is None:
            continue
        if not isinstance(value, list) or len(value) > MAX_TOOL_NAMES:
            raise ValueError(f"MCP host {list_field} must be a bounded list")
        for item in value:
            _bounded_server_text(item, label=f"{list_field} item")
    for number_field in ("startup_timeout_sec", "tool_timeout_sec", "timeout"):
        value = server.get(number_field)
        if value is not None and (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(value)
            or value <= 0
            or value > 86_400
        ):
            raise ValueError(f"MCP host {number_field} must be a positive bounded number")
    if "cwd" in server:
        cwd = _bounded_server_text(server["cwd"], label="cwd")
        if not Path(cwd).is_absolute():
            raise ValueError("MCP host cwd must be an absolute path")
    token_env = server.get("bearer_token_env_var")
    if token_env is not None and not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,127}",
        _bounded_server_text(token_env, label="bearer token environment variable"),
    ):
        raise ValueError("MCP host bearer token environment variable is invalid")
    if server.get("type") not in {None, "local", "stdio"}:
        raise ValueError("MCP host type must describe a local STDIO server")
    command, arguments, _launcher_kind = _canonicalize_launcher(
        command,
        arguments,
        server.get("env", server.get("environment")),
    )

    normalized = dict(server)
    if profile["profile_id"] == "opencode":
        normalized = {
            key: value
            for key, value in normalized.items()
            if key not in {"type", "command", "args"}
        } | {
            "type": "local",
            "command": [command, *arguments],
            "enabled": bool(server.get("enabled", True)),
        }
    else:
        normalized["command"] = command
        normalized["args"] = arguments
    return normalized


def _redacted_value(value: str, *, previous_option: str | None = None) -> str:
    if value.startswith("-") and "=" in value:
        option, option_value = value.split("=", 1)
        if _SECRET_OR_LOCAL_OPTION.search(option):
            digest = _digest_bytes(option_value.encode("utf-8"))[:12]
            return f"{option}=<redacted-local-value:{digest}>"
    local_or_secret = bool(previous_option and _SECRET_OR_LOCAL_OPTION.search(previous_option))
    local_or_secret = local_or_secret or Path(value).is_absolute() or bool(
        re.match(r"^(?:~[/\\]|[A-Za-z]:[/\\])", value)
    )
    local_or_secret = local_or_secret or bool(
        re.search(
            r"(?:token|secret|password|credential|api[-_]?key)=",
            value,
            re.IGNORECASE,
        )
    )
    if local_or_secret:
        return f"<redacted-local-value:{_digest_bytes(value.encode('utf-8'))[:12]}>"
    return value


def _redacted_server_preview(server: Mapping[str, Any]) -> dict[str, Any]:
    preview = copy.deepcopy(dict(server))
    command = preview.get("command")
    if isinstance(command, list):
        parts = [_bounded_server_text(item, label="command") for item in command]
        executable = Path(parts[0]).name
        redacted = ["<canonical-launcher>"]
        previous_option = None
        for value in parts[1:]:
            redacted.append(_redacted_value(value, previous_option=previous_option))
            previous_option = value if value.startswith("-") else None
        preview["command"] = redacted
    elif isinstance(command, str):
        preview["command"] = "<canonical-launcher>"
        arguments = preview.get("args", [])
        redacted_arguments: list[str] = []
        previous_option = None
        for value in arguments:
            redacted_arguments.append(
                _redacted_value(value, previous_option=previous_option)
            )
            previous_option = value if value.startswith("-") else None
        preview["args"] = redacted_arguments
    for key in tuple(preview):
        if key in {"env", "environment", "headers"} and isinstance(preview[key], Mapping):
            preview[key] = {
                "keys": sorted(str(item) for item in preview[key]),
                "values": "<redacted>",
            }
        elif _SECRET_OR_LOCAL_OPTION.search(str(key)) and key not in {"command", "args"}:
            preview[key] = "<redacted>"
    return preview


def _launcher_preview(binding: Mapping[str, Any]) -> dict[str, Any]:
    executable = binding["executable"]
    return {
        "executable": "python" if binding["kind"] == "python" else "rta-brain",
        "source": "canonical-absolute-path",
        **_public_file_binding(executable),
        "module": (
            _public_file_binding(binding["module"])
            if "module" in binding
            else None
        ),
    }


def _json_update(
    original: bytes,
    profile: Mapping[str, Any],
    server_name: str,
    server: Mapping[str, Any],
    action: str,
) -> bytes:
    if original.strip():
        try:
            payload = json.loads(original.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("MCP host configuration is not valid UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("MCP host configuration root must be an object")
    else:
        payload = {}
    container_name = str(profile["container"])
    container = payload.setdefault(container_name, {})
    if not isinstance(container, dict):
        raise ValueError(  # noqa: TRY004
            "MCP host configuration server container must be an object"
        )
    if action == "install":
        container[server_name] = dict(server)
    else:
        container.pop(server_name, None)
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _json_server_entry(
    original: bytes,
    profile: Mapping[str, Any],
    server_name: str,
) -> tuple[bool, Any]:
    if not original.strip():
        return False, None
    try:
        payload = json.loads(original.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("MCP host configuration is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise TypeError("MCP host configuration root must be an object")
    container_name = str(profile["container"])
    container = payload.get(container_name, {})
    if not isinstance(container, dict):
        raise TypeError("MCP host configuration server container must be an object")
    return server_name in container, container.get(server_name)


def _parse_toml(original: bytes) -> dict[str, Any]:
    try:
        text = original.decode("utf-8")
        payload = tomllib.loads(text) if text.strip() else {}
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("MCP host configuration is not valid UTF-8 TOML") from exc
    if not isinstance(payload, dict):
        raise TypeError("MCP host configuration root must be a table")
    return payload


def _toml_server_entry(original: bytes, server_name: str) -> tuple[bool, Any]:
    payload = _parse_toml(original)
    container = payload.get("mcp_servers", {})
    if not isinstance(container, dict):
        raise TypeError("MCP host configuration mcp_servers field must be a table")
    return server_name in container, container.get(server_name)


def _toml_header_path(line: str) -> tuple[str, ...] | None:
    stripped = line.strip()
    if not stripped.startswith("["):
        return None
    marker = "__rta_smriti_table_marker__"
    try:
        parsed = tomllib.loads(f"{stripped}\n{marker} = true\n")
    except tomllib.TOMLDecodeError:
        return None

    def locate(value: Any, path: tuple[str, ...]) -> tuple[str, ...] | None:
        if isinstance(value, dict):
            if value.get(marker) is True:
                return path
            for key, child in value.items():
                located = locate(child, (*path, str(key)))
                if located is not None:
                    return located
        elif isinstance(value, list):
            for child in value:
                located = locate(child, path)
                if located is not None:
                    return located
        return None

    return locate(parsed, ())


def _toml_value(value: Any) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Codex MCP server contains a non-finite number")
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, Mapping):
        encoded = ", ".join(
            f"{json.dumps(str(key), ensure_ascii=True)} = {_toml_value(item)}"
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        )
        return "{ " + encoded + " }"
    raise ValueError("Codex MCP server contains an unsupported TOML value")


def _remove_toml_server_tables(text: str, server_name: str) -> tuple[str, bool]:
    target = ("mcp_servers", server_name)
    output: list[str] = []
    skipping = False
    removed = False
    multiline_delimiter: str | None = None
    for line in text.splitlines(keepends=True):
        header = (
            _toml_header_path(line)
            if multiline_delimiter is None
            else None
        )
        if header is not None:
            skipping = len(header) >= 2 and header[:2] == target
            removed = removed or skipping
        if not skipping:
            output.append(line)
        multiline_delimiter = _toml_multiline_delimiter_after(
            line, multiline_delimiter
        )
    return "".join(output), removed


def _toml_multiline_delimiter_after(
    line: str, active: str | None
) -> str | None:
    """Track TOML multiline strings so their contents are never table headers."""

    index = 0
    quote: str | None = None
    while index < len(line):
        if active is not None:
            found = line.find(active, index)
            if found < 0:
                return active
            if active == '"""':
                backslashes = 0
                cursor = found - 1
                while cursor >= 0 and line[cursor] == "\\":
                    backslashes += 1
                    cursor -= 1
                if backslashes % 2:
                    index = found + 3
                    continue
            active = None
            index = found + 3
            continue

        character = line[index]
        if quote is not None:
            if quote == '"' and character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if character == "#":
            return None
        delimiter = line[index : index + 3]
        if delimiter in {'"""', "'''"}:
            active = delimiter
            index += 3
            continue
        if character in {'"', "'"}:
            quote = character
        index += 1
    return active


def _toml_update(
    original: bytes,
    server_name: str,
    server: Mapping[str, Any],
    action: str,
) -> bytes:
    _parse_toml(original)
    text = original.decode("utf-8")
    cleaned, removed = _remove_toml_server_tables(text, server_name)
    cleaned = cleaned.rstrip()
    if action == "remove":
        return (cleaned + ("\n" if cleaned else "")).encode("utf-8")
    command = server.get("command")
    args = server.get("args", [])
    if not isinstance(command, str) or not command or not isinstance(args, list):
        raise ValueError("Codex MCP server requires a command and argument list")
    if _toml_server_entry(original, server_name)[0] and not removed:
        raise ValueError("Codex MCP server collision cannot be replaced safely")
    fields = "".join(
        f"{key} = {_toml_value(value)}\n"
        for key, value in sorted(server.items(), key=lambda pair: str(pair[0]))
    )
    block = (
        f"# >>> rta-smriti managed {server_name}\n"
        f"[mcp_servers.{json.dumps(server_name)}]\n"
        f"{fields}"
        f"# <<< rta-smriti managed {server_name}\n"
    )
    proposed = ((cleaned + "\n\n" if cleaned else "") + block).encode("utf-8")
    parsed = _parse_toml(proposed)
    if parsed.get("mcp_servers", {}).get(server_name) != dict(server):
        raise ValueError("generated Codex MCP server configuration failed validation")
    return proposed


def _validate_configuration_bytes(
    profile: Mapping[str, Any],
    content: bytes,
    *,
    allow_empty: bool = False,
) -> None:
    if allow_empty and not content:
        return
    if profile["format"] == "json":
        try:
            payload = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("generated MCP host configuration is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("generated MCP host configuration root must be an object")
    else:
        _parse_toml(content)


def _managed_restore(
    target: Path,
    profile_id: str,
    server_name: str,
    current: bytes,
) -> tuple[bytes, str] | None:
    target_fingerprint = _target_fingerprint(target)
    receipt_roots = [
        _target_authority_control(target) / "receipts",
        target.parent / ".rta-smriti-host-lifecycle" / "receipts",
    ]
    candidates = sorted(
        (
            path
            for receipts in receipt_roots
            if receipts.is_dir()
            for path in receipts.glob("*.json")
        ),
        key=lambda path: str(path),
        reverse=True,
    )
    if len(candidates) > MAX_MANAGED_RECEIPTS:
        raise ValueError("MCP host receipt inventory exceeds the size limit")
    authenticated: list[tuple[Path, dict[str, Any]]] = []
    for path in candidates:
        receipt = _read_json_file(
            path,
            label="MCP host receipt",
            max_bytes=MAX_HOST_RECEIPT_BYTES,
        )
        _verify_receipt_authentication(receipt)
        if (
            receipt.get("state") == "installed"
            and receipt.get("profile_id") == profile_id
            and receipt.get("server_name") == server_name
            and receipt.get("target_name") == target.name
            and receipt.get("target_fingerprint") == target_fingerprint
        ):
            authenticated.append((path, receipt))

    current_digest = _digest_bytes(current)
    matching = [
        item for item in authenticated if item[1].get("after_digest") == current_digest
    ]
    if not matching:
        return None
    if len(matching) != 1:
        raise ValueError("MCP host receipt restore head is ambiguous")
    head_plan_digest = str(matching[0][1].get("plan_digest") or "")
    seen_after_digests: set[str] = set()
    path, receipt = matching[0]
    while True:
        after_digest = str(receipt.get("after_digest") or "")
        if after_digest in seen_after_digests:
            raise ValueError("MCP host receipt restore chain contains a cycle")
        seen_after_digests.add(after_digest)
        before_digest = str(receipt.get("before_digest") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", before_digest):
            raise ValueError("MCP host receipt restore binding is invalid")
        if before_digest == _digest_bytes(b""):
            return b"", head_plan_digest
        predecessors = [
            item
            for item in authenticated
            if item[1].get("after_digest") == before_digest
        ]
        if predecessors:
            predecessor_states = {
                str(item[1].get("before_digest") or "") for item in predecessors
            }
            if len(predecessor_states) != 1:
                raise ValueError("MCP host receipt restore chain is ambiguous")
            path, receipt = predecessors[0]
            continue
        control = path.parent.parent
        backup = control / "backups" / f"{before_digest}.bak"
        legacy_backup = control / "backups" / f"{target.name}.{before_digest[:16]}.bak"
        if not backup.exists() and legacy_backup.exists():
            backup = legacy_backup
        restored = _read_target(backup)
        if _digest_bytes(restored) != before_digest:
            raise ValueError("MCP host backup restore binding is invalid")
        return restored, head_plan_digest


def plan_host_configuration(
    profile_id: str,
    target: Path,
    server_name: str,
    server: Mapping[str, Any],
    *,
    action: str = "install",
    replace_existing: bool = False,
) -> HostConfigurationPlan:
    """Create a deterministic host config preview without changing the target."""

    profile = host_profile(profile_id)
    if action not in {"install", "remove"}:
        raise ValueError("MCP host action must be install or remove")
    name = str(server_name).strip()
    configuration_guidance = profile["configuration_guidance"]
    alias_pattern = str(configuration_guidance["server_alias_pattern"])
    if not name or not re.fullmatch(alias_pattern, name):
        raise ValueError(str(configuration_guidance["server_alias_error"]))
    selected_target = canonicalize_system_root_alias(target)
    target_classification = _classify_target(profile, selected_target)
    path_binding = _capture_path_binding(selected_target)
    if selected_target.exists() and selected_target.stat().st_size > MAX_HOST_CONFIG_BYTES:
        raise ValueError("MCP host configuration exceeds the size limit")
    if selected_target.parent.exists() and selected_target.parent.resolve() != selected_target.parent.absolute():
        raise ValueError("MCP host configuration parent must not be linked")
    original, observed_identity = _read_target_stable(selected_target)
    if observed_identity != path_binding["target_identity"]:
        raise PermissionError("MCP host target identity changed during preview")
    _assert_path_binding(selected_target, path_binding)
    effective_server = (
        _normalize_server_configuration(profile, server)
        if action == "install"
        else {}
    )
    launcher_binding = (
        _capture_launcher_binding(effective_server) if action == "install" else None
    )
    existing, _existing_value = (
        _json_server_entry(original, profile, name)
        if profile["format"] == "json"
        else _toml_server_entry(original, name)
    )
    restore_mode = "none"
    restore_receipt_digest = None
    remove_target_after_apply = False
    if action == "install":
        if existing and not replace_existing:
            raise ValueError("unmanaged MCP server collision requires explicit replacement")
        proposed = (
            _json_update(original, profile, name, effective_server, action)
            if profile["format"] == "json"
            else _toml_update(original, name, effective_server, action)
        )
    else:
        managed = _managed_restore(
            selected_target,
            str(profile["profile_id"]),
            name,
            original,
        )
        if managed is not None:
            proposed, restore_receipt_digest = managed
            restore_mode = "managed_backup_exact"
            remove_target_after_apply = not proposed
        elif existing:
            raise ValueError("unmanaged MCP server removal is not allowed")
        else:
            proposed = original
            restore_mode = "already_absent"
    if len(proposed) > MAX_HOST_CONFIG_BYTES:
        raise ValueError("generated MCP host configuration exceeds the size limit")
    _validate_configuration_bytes(
        profile,
        proposed,
        allow_empty=remove_target_after_apply,
    )
    body = {
        "schema": HOST_LIFECYCLE_SCHEMA,
        "profile_id": profile["profile_id"],
        "action": action,
        "server_name": name,
        "target_fingerprint": _target_fingerprint(selected_target),
        "target": {
            **target_classification,
            "fingerprint": _target_fingerprint(selected_target),
        },
        "effective_configuration_change": {
            "operation": action,
            "container": profile["container"],
            "server_name": name,
            "server": (
                _redacted_server_preview(effective_server)
                if action == "install"
                else None
            ),
            "launcher": (
                _launcher_preview(launcher_binding)
                if launcher_binding is not None
                else None
            ),
        },
        "before_digest": _digest_bytes(original),
        "after_digest": _digest_bytes(proposed),
        "backup_required": bool(original),
        "collision_state": (
            "explicit_replace_required" if action == "install" and existing else "none"
        ),
        "restore_mode": restore_mode,
        "restore_receipt_digest": restore_receipt_digest,
        "format": profile["format"],
        "activation_steps": profile["activation_steps"],
        "fresh_session_proof": profile["fresh_session_proof"],
        "scope_guidance": profile["scope_guidance"],
        "configuration_guidance": profile["configuration_guidance"],
        "activation_guidance": profile["activation_guidance"],
        "tool_filter_guidance": profile["tool_filter_guidance"],
    }
    return HostConfigurationPlan(
        {**body, "status": "ok", "read_only": True, "plan_digest": _digest_json(body)},
        target=selected_target,
        proposed=proposed,
        original=original,
        path_binding=path_binding,
        launcher_binding=launcher_binding,
        remove_target_after_apply=remove_target_after_apply,
    )


def _atomic_write(
    path: Path,
    content: bytes,
    *,
    final_guard: Callable[[], None] | None = None,
) -> None:
    prepare_control_dir(path.parent, label="MCP host configuration")
    temporary = path.parent / f".{path.name}.{_digest_bytes(content)[:12]}.tmp"
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if final_guard is not None:
            final_guard()
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def apply_host_configuration(
    plan: HostConfigurationPlan,
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Apply an unchanged host preview after an exact digest confirmation."""

    if not isinstance(plan, HostConfigurationPlan):
        raise ValueError("MCP host plan execution context is unavailable")  # noqa: TRY004
    target_fingerprint = _target_fingerprint(plan._target)
    control = _target_authority_control(plan._target)
    with _target_operation_claim(control, target_fingerprint):
        return _apply_host_configuration_locked(plan, confirmation, control)


def _apply_host_configuration_locked(
    plan: HostConfigurationPlan,
    confirmation: Mapping[str, Any],
    control: Path,
) -> dict[str, Any]:
    """Apply one host preview while its target-scoped authority claim is held."""

    if not isinstance(plan, HostConfigurationPlan):
        raise ValueError("MCP host plan execution context is unavailable")  # noqa: TRY004
    if (
        _host_plan_execution_digest(plan)
        != getattr(plan, "_sealed_execution_digest", None)
    ):
        raise PermissionError("MCP host plan changed after approval")
    public_body = {
        key: copy.deepcopy(value)
        for key, value in plan.items()
        if key not in {"status", "read_only", "plan_digest"}
    }
    if _digest_json(public_body) != plan.get("plan_digest"):
        raise PermissionError("MCP host plan changed after approval")
    if not confirmation.get("approved") or confirmation.get("plan_digest") != plan["plan_digest"]:
        raise PermissionError("MCP host configuration requires matching approval")
    if (
        plan.get("collision_state") == "explicit_replace_required"
        and confirmation.get("replace_existing") is not True
    ):
        raise PermissionError("MCP host replacement approval is required")
    activation_state = host_profile(plan["profile_id"])["activation_guidance"][
        "post_write_state"
    ]
    receipt = _authenticate_receipt({
        "schema": HOST_LIFECYCLE_SCHEMA,
        "state": "installed" if plan["action"] == "install" else "removed",
        "profile_id": plan["profile_id"],
        "server_name": plan["server_name"],
        "plan_digest": plan["plan_digest"],
        "target_fingerprint": plan["target_fingerprint"],
        "before_digest": plan["before_digest"],
        "after_digest": plan["after_digest"],
        "collision_state": plan["collision_state"],
        "restore_mode": plan["restore_mode"],
        "restore_receipt_digest": plan["restore_receipt_digest"],
        "activation_state": activation_state,
        "fresh_session_proof": "pending",
        "target_name": plan._target.name,
        "target_locator": str(plan._target),
        "launcher_binding": (
            _public_launcher_binding(plan._launcher_binding)
            if plan._launcher_binding is not None
            else None
        ),
    })
    receipt_path = control / "receipts" / f"{plan['plan_digest']}.json"
    if receipt_path.exists():
        existing_receipt = _read_json_file(
            receipt_path,
            label="MCP host receipt",
            max_bytes=MAX_HOST_RECEIPT_BYTES,
        )
        if existing_receipt != receipt:
            raise FileExistsError("MCP host receipt conflicts with the approved plan")
        raise PermissionError("completed MCP host configuration plan is terminal")

    if plan._launcher_binding is not None:
        _assert_launcher_binding(plan._launcher_binding)
    _assert_path_binding(plan._target, plan._path_binding)
    prepare_control_dir(control, label="MCP host lifecycle")
    prepare_control_dir(plan._target.parent, label="MCP host configuration")
    runtime_parent_identity = _identity(plan._target.parent, directory=True)
    _assert_path_binding(
        plan._target,
        plan._path_binding,
        runtime_parent_identity=runtime_parent_identity,
    )
    current, current_identity = _read_target_stable(plan._target)
    if current_identity != plan._path_binding["target_identity"]:
        raise PermissionError("MCP host target identity changed after preview")
    if _digest_bytes(current) != plan["before_digest"]:
        raise PermissionError("MCP host configuration changed after preview")
    backup_path = control / "backups" / f"{plan['before_digest']}.bak"
    if current:
        prepare_control_dir(backup_path.parent, label="MCP host backup")
        if backup_path.exists():
            if not is_safe_regular_file(backup_path) or backup_path.read_bytes() != current:
                raise FileExistsError("MCP host backup path already contains different data")
        else:
            _atomic_write(backup_path, current)
    target_changed = False

    def final_target_guard() -> None:
        _assert_path_binding(
            plan._target,
            plan._path_binding,
            runtime_parent_identity=runtime_parent_identity,
        )
        guarded, guarded_identity = _read_target_stable(plan._target)
        if guarded_identity != plan._path_binding["target_identity"]:
            raise PermissionError("MCP host target identity changed before write")
        if _digest_bytes(guarded) != plan["before_digest"]:
            raise PermissionError("MCP host configuration changed before write")

    try:
        profile = host_profile(plan["profile_id"])
        _validate_configuration_bytes(
            profile,
            plan._proposed,
            allow_empty=plan._remove_target_after_apply,
        )
        if plan._remove_target_after_apply:
            if plan._target.exists():
                if not is_safe_regular_file(plan._target):
                    raise ValueError("MCP host removal target is linked or unsafe")
                final_target_guard()
                plan._target.unlink()
                target_changed = True
        else:
            _atomic_write(
                plan._target,
                plan._proposed,
                final_guard=final_target_guard,
            )
            target_changed = True
        if _digest_bytes(_read_target(plan._target)) != plan["after_digest"]:
            raise RuntimeError("MCP host configuration failed post-write verification")
        prepare_control_dir(receipt_path.parent, label="MCP host receipt")
        _atomic_write(
            receipt_path,
            (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
    except BaseException:
        try:
            if target_changed:
                current_after_failure, _identity_after_failure = _read_target_stable(
                    plan._target
                )
                if _digest_bytes(current_after_failure) != plan["after_digest"]:
                    raise PermissionError(
                        "MCP host rollback refused configuration changed after write"
                    )
                if plan._original:
                    _atomic_write(plan._target, plan._original)
                elif plan._target.exists():
                    if not is_safe_regular_file(plan._target):
                        raise ValueError("MCP host rollback target is linked or unsafe")
                    plan._target.unlink()
        except BaseException as rollback_error:
            raise RuntimeError(
                "MCP host configuration failed and rollback was incomplete"
            ) from rollback_error
        raise
    return {
        "status": "ok",
        **_public_receipt(receipt),
        "backup_path": str(backup_path) if current else None,
        "receipt_path": str(receipt_path),
        "idempotent_replay": False,
    }


def _load_bound_configuration(
    configuration_receipt_path: Path,
) -> tuple[Path, Path, dict[str, Any]]:
    receipt_path = Path(configuration_receipt_path).expanduser().resolve()
    if receipt_path.parent.name != "receipts":
        raise ValueError("MCP host configuration receipt is missing or unsafe")
    configuration = _read_json_file(
        receipt_path,
        label="MCP host configuration receipt",
        max_bytes=MAX_HOST_RECEIPT_BYTES,
    )
    _verify_receipt_authentication(configuration)
    plan_digest = str(configuration.get("plan_digest") or "")
    target_name = str(configuration.get("target_name") or "")
    required_fields = {
        "schema",
        "state",
        "profile_id",
        "server_name",
        "plan_digest",
        "target_fingerprint",
        "after_digest",
        "activation_state",
        "fresh_session_proof",
        "target_name",
        "before_digest",
        "collision_state",
        "restore_mode",
        "restore_receipt_digest",
        "launcher_binding",
        "receipt_authentication",
    }
    if (
        not required_fields <= set(configuration)
        or configuration.get("schema") != HOST_LIFECYCLE_SCHEMA
        or not re.fullmatch(r"[0-9a-f]{64}", plan_digest)
        or receipt_path.name != f"{plan_digest}.json"
        or not target_name
        or target_name in {".", ".."}
        or Path(target_name).name != target_name
        or "/" in target_name
        or "\\" in target_name
    ):
        raise ValueError("MCP host configuration receipt binding is invalid")
    target_locator = configuration.get("target_locator")
    if isinstance(target_locator, str) and target_locator:
        target = Path(target_locator).expanduser().absolute()
        expected_receipt = (
            _target_authority_control(target) / "receipts" / f"{plan_digest}.json"
        ).resolve()
    else:
        if receipt_path.parent.parent.name != ".rta-smriti-host-lifecycle":
            raise ValueError("MCP host configuration receipt binding is invalid")
        target = receipt_path.parents[2] / target_name
        expected_receipt = (
            target.parent
            / ".rta-smriti-host-lifecycle"
            / "receipts"
            / f"{plan_digest}.json"
        ).resolve()
    if (
        receipt_path != expected_receipt
        or not is_safe_regular_file(target)
        or _digest_bytes(_read_target(target)) != configuration.get("after_digest")
        or _target_fingerprint(target) != configuration.get("target_fingerprint")
    ):
        raise ValueError("MCP host configuration receipt binding is invalid")
    profile = host_profile(str(configuration.get("profile_id") or ""))
    current = _read_target(target)
    server_name = str(configuration.get("server_name") or "")
    present, server = (
        _json_server_entry(current, profile, server_name)
        if profile["format"] == "json"
        else _toml_server_entry(current, server_name)
    )
    if not present or not isinstance(server, Mapping):
        raise ValueError("MCP host installed server binding is invalid")
    expected_launcher = configuration.get("launcher_binding")
    if not isinstance(expected_launcher, Mapping):
        raise ValueError("MCP host launcher receipt binding is invalid")
    current_launcher = _public_launcher_binding(_capture_launcher_binding(server))
    if current_launcher != dict(expected_launcher):
        raise ValueError("MCP host launcher receipt binding is invalid")
    return receipt_path, target, configuration


def validate_installed_configuration(
    configuration_receipt_path: Path,
    *,
    expected_plan_digest: str | None = None,
) -> dict[str, Any]:
    """Revalidate authenticated receipt, current config bytes, and launcher identity."""

    receipt_path, _target, configuration = _load_bound_configuration(
        configuration_receipt_path
    )
    if configuration.get("state") != "installed":
        raise ValueError("MCP host configuration receipt is not installed")
    plan_digest = str(configuration["plan_digest"])
    if expected_plan_digest is not None and plan_digest != expected_plan_digest:
        raise ValueError("MCP host configuration plan binding is invalid")
    return {
        "status": "ok",
        "state": "installed",
        "profile_id": configuration["profile_id"],
        "server_name": configuration["server_name"],
        "configuration_plan_digest": plan_digest,
        "configuration_digest": configuration["after_digest"],
        "receipt_digest": _digest_json(configuration),
    }


def _require_installed_confirmation(
    configuration: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> str:
    plan_digest = str(configuration.get("plan_digest") or "")
    if (
        configuration.get("state") != "installed"
        or not confirmation.get("approved")
        or confirmation.get("configuration_plan_digest") != plan_digest
    ):
        raise PermissionError("fresh-session proof does not match an installed configuration")
    return plan_digest


def _bounded_tool_names(raw_tool_names: Any) -> set[str]:
    if not isinstance(raw_tool_names, (list, tuple, set)):
        raise ValueError("fresh-session tool catalog must be a collection")  # noqa: TRY004
    if len(raw_tool_names) > MAX_TOOL_NAMES:
        raise ValueError("fresh-session tool catalog exceeds the size limit")
    tool_names: set[str] = set()
    for raw_name in raw_tool_names:
        name = str(raw_name).strip()
        if len(name) > MAX_TOOL_NAME_CHARS:
            raise ValueError("fresh-session tool name exceeds the size limit")
        if name:
            tool_names.add(name)
    return tool_names


def _challenge_id(plan_digest: str, token: str) -> tuple[str, str]:
    nonce_digest = _digest_bytes(token.encode("utf-8"))
    challenge_id = _digest_json(
        {"configuration_plan_digest": plan_digest, "nonce_digest": nonce_digest}
    )
    return challenge_id, nonce_digest


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"fresh-session challenge {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"fresh-session challenge {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"fresh-session challenge {label} is invalid")
    return parsed.astimezone(UTC)


@contextmanager
def _challenge_transaction(control: Path, challenge_id: str):
    lock_path = control / "challenge-locks" / f"{challenge_id}.lock"
    prepare_control_dir(lock_path.parent, label="fresh-session challenge lock")
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise PermissionError("fresh-session challenge is already being consumed") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as stream:
            stream.write(f"{os.getpid()}\n")
            stream.flush()
            os.fsync(stream.fileno())
        yield
    finally:
        if lock_path.exists():
            if not is_safe_regular_file(lock_path):
                raise ValueError("fresh-session challenge lock is unsafe")
            lock_path.unlink()


def issue_fresh_session_challenge(
    configuration_receipt_path: Path,
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Issue a one-use nonce before a host starts its fresh verification session."""

    receipt_path, _target, configuration = _load_bound_configuration(
        configuration_receipt_path
    )
    plan_digest = _require_installed_confirmation(configuration, confirmation)
    token = f"rta_{secrets.token_urlsafe(32)}"
    challenge_id, nonce_digest = _challenge_id(plan_digest, token)
    issued_at = _utc_now().astimezone(UTC).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=FRESH_SESSION_CHALLENGE_TTL_SECONDS)
    challenge = {
        "schema": HOST_LIFECYCLE_SCHEMA,
        "kind": "fresh-session-challenge",
        "state": "issued",
        "challenge_id": challenge_id,
        "nonce_digest": nonce_digest,
        "profile_id": configuration["profile_id"],
        "server_name": configuration["server_name"],
        "configuration_plan_digest": plan_digest,
        "configuration_digest": configuration["after_digest"],
        "target_fingerprint": configuration["target_fingerprint"],
        "issued_at": _timestamp(issued_at),
        "expires_at": _timestamp(expires_at),
    }
    path = receipt_path.parent.parent / "challenges" / f"{challenge_id}.json"
    prepare_control_dir(path.parent, label="fresh-session challenge")
    _atomic_write(
        path,
        (json.dumps(challenge, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return {
        "status": "ok",
        "state": "issued",
        "challenge_id": challenge_id,
        "configuration_plan_digest": plan_digest,
        "challenge_token": token,
    }


def _load_challenge(
    receipt_path: Path,
    configuration: Mapping[str, Any],
    token: str,
) -> tuple[Path, dict[str, Any]]:
    if not token or len(token) > MAX_SESSION_ID_CHARS:
        raise PermissionError("fresh-session challenge token is invalid")
    challenge_id, nonce_digest = _challenge_id(str(configuration["plan_digest"]), token)
    path = receipt_path.parent.parent / "challenges" / f"{challenge_id}.json"
    if not path.exists():
        raise PermissionError("fresh-session challenge is missing or invalid")
    challenge = _read_json_file(
        path,
        label="fresh-session challenge",
        max_bytes=MAX_HOST_RECEIPT_BYTES,
    )
    issued_at = _parse_timestamp(challenge.get("issued_at"), label="issued time")
    expires_at = _parse_timestamp(challenge.get("expires_at"), label="expiry")
    expected = {
        "schema": HOST_LIFECYCLE_SCHEMA,
        "kind": "fresh-session-challenge",
        "state": "issued",
        "challenge_id": challenge_id,
        "nonce_digest": nonce_digest,
        "profile_id": configuration["profile_id"],
        "server_name": configuration["server_name"],
        "configuration_plan_digest": configuration["plan_digest"],
        "configuration_digest": configuration["after_digest"],
        "target_fingerprint": configuration["target_fingerprint"],
        "issued_at": _timestamp(issued_at),
        "expires_at": _timestamp(expires_at),
    }
    if challenge != expected:
        raise ValueError("fresh-session challenge binding is invalid")
    if expires_at != issued_at + timedelta(
        seconds=FRESH_SESSION_CHALLENGE_TTL_SECONDS
    ):
        raise ValueError("fresh-session challenge expiry binding is invalid")
    if _utc_now().astimezone(UTC) >= expires_at:
        raise PermissionError("fresh-session challenge has expired")
    return path, challenge


def record_server_observed_tool_event(
    configuration_receipt_path: Path,
    challenge_token: str,
    event: Mapping[str, Any],
) -> dict[str, Any]:
    """Record a bounded event at the MCP server boundary for later proof sealing."""

    receipt_path, _target, configuration = _load_bound_configuration(
        configuration_receipt_path
    )
    _challenge_path, initial_challenge = _load_challenge(
        receipt_path, configuration, str(challenge_token)
    )
    control = receipt_path.parent.parent
    challenge_id = str(initial_challenge["challenge_id"])
    with _challenge_transaction(control, challenge_id):
        _challenge_path, challenge = _load_challenge(
            receipt_path, configuration, str(challenge_token)
        )
        return _record_server_observed_tool_event_locked(
            receipt_path, configuration, challenge, event
        )


def _record_server_observed_tool_event_locked(
    receipt_path: Path,
    configuration: Mapping[str, Any],
    challenge: Mapping[str, Any],
    event: Mapping[str, Any],
) -> dict[str, Any]:
    challenge_id = str(challenge["challenge_id"])
    control = receipt_path.parent.parent
    sealed_path = control / "sealed-challenges" / f"{challenge_id}.json"
    if sealed_path.exists():
        raise PermissionError("fresh-session challenge is already sealed")

    session_id = str(event.get("fresh_session_id") or "").strip()
    if len(session_id) > MAX_SESSION_ID_CHARS:
        raise ValueError("fresh-session identity exceeds the size limit")
    if not session_id:
        raise ValueError("fresh-session identity is required")
    host_version = str(event.get("host_version") or "").strip()
    if not host_version or len(host_version) > MAX_HOST_VERSION_CHARS:
        raise ValueError("fresh-session host version is missing or oversized")
    tool_names = _bounded_tool_names(event.get("tool_names", []))
    tool_name = str(event.get("tool_name") or "").strip()
    status = str(event.get("status") or "").strip().casefold()
    supplied_configuration_digest = event.get("configuration_digest")
    if (
        supplied_configuration_digest is not None
        and supplied_configuration_digest != configuration["after_digest"]
    ):
        raise ValueError("fresh-session configuration binding changed")
    if status not in {"ok", "denied", "error"}:
        raise ValueError("observed MCP tool status is invalid")
    if (
        not tool_name
        or len(tool_name) > MAX_TOOL_NAME_CHARS
        or (tool_name not in tool_names and status != "denied")
    ):
        raise ValueError("observed MCP tool is missing from the bound catalog")
    binding = {
        "session_fingerprint": _digest_bytes(session_id.encode("utf-8"))[:16],
        "host_version_fingerprint": _digest_bytes(host_version.encode("utf-8"))[:16],
        "configuration_digest": configuration["after_digest"],
        "tool_catalog_digest": _digest_json({"tools": sorted(tool_names)}),
    }
    observations_path = control / "observations" / f"{challenge_id}.json"
    if observations_path.exists():
        observations = _read_json_file(
            observations_path,
            label="fresh-session observations",
            max_bytes=MAX_HOST_RECEIPT_BYTES,
        )
        if observations.get("binding") != binding:
            if observations.get("binding", {}).get("session_fingerprint") != binding["session_fingerprint"]:
                raise ValueError("fresh-session session binding changed")
            raise ValueError("fresh-session host or tool-catalog binding changed")
    else:
        observations = {
            "schema": HOST_LIFECYCLE_SCHEMA,
            "kind": "server-observed-fresh-session-events",
            "challenge_id": challenge_id,
            "profile_id": configuration["profile_id"],
            "server_name": configuration["server_name"],
            "configuration_plan_digest": configuration["plan_digest"],
            "binding": binding,
            "events": [],
        }
    events = observations.get("events")
    if not isinstance(events, list) or len(events) >= MAX_OBSERVED_EVENTS:
        raise ValueError("fresh-session observation count exceeds the size limit")
    events.append(
        {
            "sequence": len(events) + 1,
            "tool_name": tool_name,
            "status": status,
            "atlas_search_observed": (
                tool_name == "brain_search"
                and status == "ok"
                and str(event.get("project") or "").strip().casefold().startswith("atlas")
            ),
            "denied_capability_observed": (
                (
                    status == "denied"
                    and bool(str(event.get("capability") or "").strip())
                )
                or (
                    tool_name == "brain_capabilities"
                    and status == "ok"
                    and event.get("capability") == "mutating-tools-disabled"
                )
            ),
        }
    )
    prepare_control_dir(observations_path.parent, label="fresh-session observations")
    _atomic_write(
        observations_path,
        (json.dumps(observations, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return {
        "status": "ok",
        "state": "observed",
        "challenge_id": challenge_id,
        "event_count": len(events),
    }


def record_fresh_session_proof(
    configuration_receipt_path: Path,
    evidence: Mapping[str, Any],
    confirmation: Mapping[str, Any],
) -> dict[str, Any]:
    """Seal a proof derived only from nonce-bound server observation receipts."""

    receipt_path, _target, configuration = _load_bound_configuration(
        configuration_receipt_path
    )
    plan_digest = _require_installed_confirmation(configuration, confirmation)
    token = str(evidence.get("challenge_token") or "")
    if not token:
        return {
            "status": "attention_required",
            "state": "unverified",
            "reason_codes": ["nonce_challenge_missing", "server_observed_events_missing"],
        }
    _challenge_path, initial_challenge = _load_challenge(
        receipt_path, configuration, token
    )
    challenge_id = str(initial_challenge["challenge_id"])
    control = receipt_path.parent.parent
    with _challenge_transaction(control, challenge_id):
        sealed_path = control / "sealed-challenges" / f"{challenge_id}.json"
        if sealed_path.exists():
            raise PermissionError("fresh-session challenge was already consumed")
        _challenge_path, challenge = _load_challenge(
            receipt_path, configuration, token
        )
        return _record_fresh_session_proof_locked(
            receipt_path,
            configuration,
            plan_digest,
            challenge,
        )


def _record_fresh_session_proof_locked(
    receipt_path: Path,
    configuration: Mapping[str, Any],
    plan_digest: str,
    challenge: Mapping[str, Any],
) -> dict[str, Any]:
    challenge_id = str(challenge["challenge_id"])
    control = receipt_path.parent.parent
    observations_path = control / "observations" / f"{challenge_id}.json"
    if not observations_path.exists():
        return {
            "status": "attention_required",
            "state": "unverified",
            "reason_codes": ["server_observed_events_missing"],
        }
    observations = _read_json_file(
        observations_path,
        label="fresh-session observations",
        max_bytes=MAX_HOST_RECEIPT_BYTES,
    )
    if (
        observations.get("challenge_id") != challenge_id
        or observations.get("configuration_plan_digest") != plan_digest
        or observations.get("profile_id") != configuration["profile_id"]
        or observations.get("server_name") != configuration["server_name"]
        or observations.get("binding", {}).get("configuration_digest")
        != configuration["after_digest"]
    ):
        raise ValueError("fresh-session observation binding is invalid")
    events = observations.get("events")
    if not isinstance(events, list) or len(events) > MAX_OBSERVED_EVENTS:
        raise ValueError("fresh-session observations are invalid")
    atlas_observed = any(item.get("atlas_search_observed") is True for item in events)
    denied_observed = any(
        item.get("denied_capability_observed") is True for item in events
    )
    reason_codes: list[str] = []
    if not atlas_observed:
        reason_codes.append("atlas_search_unproven")
    if not denied_observed:
        reason_codes.append("denied_capability_unproven")
    if reason_codes:
        return {
            "status": "attention_required",
            "state": "unverified",
            "reason_codes": reason_codes,
        }
    binding = observations["binding"]
    evidence_summary = {
        "session_fingerprint": binding["session_fingerprint"],
        "host_version_fingerprint": binding["host_version_fingerprint"],
        "configuration_digest": binding["configuration_digest"],
        "tool_catalog_digest": binding["tool_catalog_digest"],
        "observed_event_count": len(events),
        "atlas_search_observed": True,
        "denied_capability_observed": True,
    }
    proof = {
        "schema": HOST_LIFECYCLE_SCHEMA,
        "kind": "nonce-bound-fresh-session-proof",
        "state": "protocol_verified",
        "verification_level": "protocol_verified",
        "host_verified": False,
        "host_evidence": "not_observed",
        "profile_id": configuration["profile_id"],
        "server_name": configuration["server_name"],
        "configuration_plan_digest": plan_digest,
        "challenge_id": challenge_id,
        "evidence": evidence_summary,
    }
    proof_digest = _digest_json(proof)
    proof_path = control / "proofs" / f"proof-{proof_digest}.json"
    if proof_path.exists():
        existing = _read_json_file(
            proof_path,
            label="fresh-session proof",
            max_bytes=MAX_HOST_RECEIPT_BYTES,
        )
        if existing != proof:
            raise FileExistsError("fresh-session proof conflicts with existing evidence")
    else:
        prepare_control_dir(proof_path.parent, label="fresh-session proof")
        _atomic_write(
            proof_path,
            (json.dumps(proof, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
    sealed = {
        "schema": HOST_LIFECYCLE_SCHEMA,
        "kind": "sealed-fresh-session-challenge",
        "challenge_id": challenge_id,
        "proof_digest": proof_digest,
    }
    sealed_path = control / "sealed-challenges" / f"{challenge_id}.json"
    if not sealed_path.exists():
        prepare_control_dir(sealed_path.parent, label="sealed fresh-session challenge")
        _atomic_write(
            sealed_path,
            (json.dumps(sealed, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
    return {
        "status": "ok",
        "state": "protocol_verified",
        "verification_level": "protocol_verified",
        "host_verified": False,
        "profile_id": configuration["profile_id"],
        "configuration_plan_digest": plan_digest,
        "proof_digest": proof_digest,
        "receipt_path": str(proof_path),
        "evidence": evidence_summary,
    }
