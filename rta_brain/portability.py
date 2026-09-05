"""Selective bundles and authenticated local brain snapshots."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
from pathlib import Path

from .db import VALID_PRAMANA, ensure_project, init_schema, now_iso, remember, validate_provenance
from .governance import validate_policy_input
from .ingest import read_text
from .privacy import find_sensitive_text, redact_sensitive_data, redact_sensitive_text


MAX_BUNDLE_BYTES = 25_000_000
MAX_SNAPSHOT_DATABASE_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_HEADER_BYTES = 16 * 1024
MAX_SNAPSHOT_FILE_BYTES = MAX_SNAPSHOT_HEADER_BYTES + 1 + ((MAX_SNAPSHOT_DATABASE_BYTES + 2) // 3) * 4
MAX_LEGACY_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_SNAPSHOT_KEY_BYTES = 4096
MAX_SNAPSHOT_PASSPHRASE_BYTES = 4096
MAX_PUBLIC_KEY_BYTES = 4096
MAX_PRIVATE_KEY_BYTES = 8192
MAX_BUNDLE_PROJECTS = 100
MAX_BUNDLE_RECORDS = 100_000
ALLOWED_BUNDLE_SECTIONS = frozenset({"memories", "checkpoints", "policies"})
MEMORY_STATUSES = frozenset({"active", "pinned", "superseded"})
POLICY_STATUSES = frozenset({"active", "retired"})
BUNDLE_FIELDS = frozenset({"schema_version", "kind", "created_at", "redacted", "includes", "projects"})
PROJECT_FIELDS = frozenset({"name", "repository_identity", "memories", "checkpoints", "policies"})
MEMORY_FIELDS = frozenset({
    "type", "pramana", "text", "confidence", "priority", "status", "metadata_json",
    "source_path", "source_hash", "command", "timestamp", "verification_status",
    "provenance_metadata_json",
})
CHECKPOINT_FIELDS = frozenset({
    "objective", "verified_evidence", "remaining_gaps", "next_action", "prohibited_repetition", "version",
})
POLICY_FIELDS = frozenset({
    "kind", "statement", "effect", "action_contains", "path_glob", "required_check", "pramana",
    "confidence", "provenance_json", "overrideable", "expires_at", "status",
})


def _canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _write_private_text(path: Path, text: str) -> None:
    requested = Path(path).expanduser()
    if requested.is_symlink():
        raise ValueError("refusing to replace a linked portability artifact")
    destination = requested.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        stat = destination.stat()
        if destination.is_symlink() or stat.st_nlink > 1:
            raise ValueError("refusing to replace a linked portability artifact")
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _redactor():
    count = 0

    structured_json_fields = frozenset(
        {"metadata_json", "provenance_metadata_json", "provenance_json"}
    )

    def redact_json_string(value: str) -> str | None:
        nonlocal count
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(parsed, (dict, list)):
            return None
        redacted, replacements = redact_sensitive_data(parsed)
        count += replacements
        return json.dumps(redacted, sort_keys=True, separators=(",", ":"))

    def redact(value):
        nonlocal count
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized_key = str(key)
                if normalized_key in structured_json_fields and isinstance(item, str):
                    structured = redact_json_string(item)
                    result[normalized_key] = structured if structured is not None else redact(item)
                else:
                    result[normalized_key] = redact(item)
            return result
        if isinstance(value, list):
            return [redact(item) for item in value]
        if not isinstance(value, str):
            return value
        result, replacements = redact_sensitive_text(value)
        count += replacements
        return result

    return redact, lambda: count


def _read_envelope(source: Path) -> tuple[dict, dict]:
    requested = Path(source).expanduser()
    if requested.is_symlink():
        raise ValueError("linked bundle inputs are not allowed")
    path = requested.resolve()
    if not path.is_file():
        raise ValueError(f"bundle does not exist: {path}")
    if path.stat().st_nlink > 1:
        raise ValueError("linked bundle inputs are not allowed")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError(f"bundle exceeds the {MAX_BUNDLE_BYTES // 1_000_000} MB limit")
    payload = read_text(path, MAX_BUNDLE_BYTES)
    if payload is None:
        raise ValueError("bundle changed while being read or violates the safe input policy")
    try:
        envelope = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("bundle is not valid JSON") from exc
    if not isinstance(envelope, dict):
        raise ValueError("bundle envelope must be an object")
    manifest = envelope.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("bundle manifest must be an object")
    expected_value = manifest.get("sha256")
    if not isinstance(expected_value, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_value):
        raise ValueError("bundle manifest sha256 must be a lowercase SHA-256 digest")
    if manifest.get("authentication", "none") != "none":
        raise ValueError("selective bundles do not support authenticated provenance")
    bundle = envelope.get("bundle")
    expected = expected_value
    if not isinstance(bundle, dict) or bundle.get("kind") != "rta-smriti-selective-bundle":
        raise ValueError("not an Rta-Smriti selective bundle")
    if bundle.get("schema_version") != 1:
        raise ValueError("unsupported bundle schema version")
    if not hmac.compare_digest(expected, hashlib.sha256(_canonical_json(bundle)).hexdigest()):
        raise ValueError("bundle integrity check failed")
    return envelope, bundle


def _validate_bundle(bundle: dict, conn=None) -> dict:
    unknown_bundle_fields = set(bundle) - BUNDLE_FIELDS
    if unknown_bundle_fields:
        raise ValueError(f"bundle contains unknown field(s): {', '.join(sorted(unknown_bundle_fields))}")
    includes = bundle.get("includes")
    projects = bundle.get("projects")
    if not isinstance(bundle.get("redacted"), bool):
        raise ValueError("bundle redacted flag must be boolean")
    created_at = bundle.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip() or len(created_at) > 100:
        raise ValueError("bundle created_at must be a timestamp string")
    if (
        not isinstance(includes, list) or not includes or any(not isinstance(item, str) for item in includes)
        or len(includes) != len(set(includes)) or set(includes) - ALLOWED_BUNDLE_SECTIONS
    ):
        raise ValueError("bundle includes contain an unsupported section")
    if not isinstance(projects, list) or len(projects) > MAX_BUNDLE_PROJECTS:
        raise ValueError(f"bundle projects must be a list of at most {MAX_BUNDLE_PROJECTS}")
    seen_names = set()
    counts = {"projects": len(projects), "memories": 0, "checkpoints": 0, "policies": 0}
    conflicts = []
    sensitive_findings: dict[str, int] = {}

    def inspect_text(value) -> None:
        if isinstance(value, dict):
            for item in value.values():
                inspect_text(item)
        elif isinstance(value, list):
            for item in value:
                inspect_text(item)
        elif isinstance(value, str):
            for finding in find_sensitive_text(value):
                sensitive_findings[finding.label] = sensitive_findings.get(finding.label, 0) + 1

    for project in projects:
        if not isinstance(project, dict):
            raise ValueError("bundle project entries must be objects")
        unknown_project_fields = set(project) - PROJECT_FIELDS
        if unknown_project_fields:
            raise ValueError(f"bundle contains unknown project field(s): {', '.join(sorted(unknown_project_fields))}")
        raw_name = project.get("name")
        if not isinstance(raw_name, str):
            raise ValueError("bundle project name must be a string")
        name = raw_name.strip()
        if not name or len(name) > 200 or name.casefold() in seen_names:
            raise ValueError("bundle project names must be unique, non-empty, and at most 200 characters")
        seen_names.add(name.casefold())
        repository_identity = project.get("repository_identity")
        if repository_identity is not None and (
            not isinstance(repository_identity, str) or len(repository_identity) > 4_000
        ):
            raise ValueError("bundle repository identity must be a string of at most 4,000 characters")
        if conn is not None and conn.execute("SELECT 1 FROM projects WHERE name = ?", (name,)).fetchone():
            conflicts.append(name)
        for section in ALLOWED_BUNDLE_SECTIONS:
            records = project.get(section, [])
            if section not in includes and records:
                raise ValueError(f"bundle contains {section} records outside its include manifest")
            if not isinstance(records, list):
                raise ValueError(f"bundle project {section} must be a list")
            counts[section] += len(records)
            if any(not isinstance(record, dict) for record in records):
                raise ValueError(f"bundle {section} records must be objects")
        for memory in project.get("memories", []):
            unknown_memory_fields = set(memory) - MEMORY_FIELDS
            if unknown_memory_fields:
                raise ValueError(f"bundle contains unknown memory field(s): {', '.join(sorted(unknown_memory_fields))}")
            text = memory.get("text")
            if not isinstance(text, str) or not text.strip() or len(text) > 20_000:
                raise ValueError("bundle memory text must be non-empty and at most 20,000 characters")
            memory_type = memory.get("type", "fact")
            if not isinstance(memory_type, str) or not memory_type.strip() or len(memory_type) > 200:
                raise ValueError("bundle memory type must be non-empty and at most 200 characters")
            memory_pramana = memory.get("pramana", "smriti")
            if not isinstance(memory_pramana, str) or memory_pramana not in VALID_PRAMANA:
                raise ValueError("bundle memory contains an unknown pramana")
            confidence_value = memory.get("confidence", 0.75)
            priority_value = memory.get("priority", 5)
            if isinstance(confidence_value, bool) or not isinstance(confidence_value, (int, float)):
                raise ValueError("bundle memory confidence and priority must be numeric")
            if isinstance(priority_value, bool) or not isinstance(priority_value, int):
                raise ValueError("bundle memory confidence and priority must be numeric")
            try:
                confidence = float(confidence_value)
                priority = int(priority_value)
            except (TypeError, ValueError) as exc:
                raise ValueError("bundle memory confidence and priority must be numeric") from exc
            if not 0 <= confidence <= 1 or not 1 <= priority <= 10:
                raise ValueError("bundle memory confidence or priority is outside the supported range")
            memory_status = memory.get("status", "active")
            if not isinstance(memory_status, str) or memory_status not in MEMORY_STATUSES:
                raise ValueError("bundle memory contains an unknown status")
            for field in ("metadata_json", "provenance_metadata_json"):
                try:
                    parsed = json.loads(memory.get(field) or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"bundle contains invalid {field}") from exc
                if not isinstance(parsed, dict):
                    raise ValueError(f"bundle {field} must decode to an object")
            provenance = {
                "source_path": memory.get("source_path"), "source_hash": memory.get("source_hash"),
                "command": memory.get("command"), "timestamp": memory.get("timestamp"),
                "verification_status": memory.get("verification_status", "unverified"),
                "metadata": json.loads(memory.get("provenance_metadata_json") or "{}"),
            }
            for field, maximum in (("source_path", 4_000), ("source_hash", 256), ("command", 8_000), ("timestamp", 100)):
                value = provenance[field]
                if value is not None and (not isinstance(value, str) or len(value.strip()) > maximum):
                    raise ValueError(f"bundle memory {field} must be a string of at most {maximum:,} characters")
            validate_provenance(provenance)
        for checkpoint in project.get("checkpoints", []):
            unknown_checkpoint_fields = set(checkpoint) - CHECKPOINT_FIELDS
            if unknown_checkpoint_fields:
                raise ValueError(
                    f"bundle contains unknown checkpoint field(s): {', '.join(sorted(unknown_checkpoint_fields))}"
                )
            for field in (
                "objective", "verified_evidence", "remaining_gaps", "next_action", "prohibited_repetition",
            ):
                value = checkpoint.get(field, "")
                if not isinstance(value, str) or len(value) > 20_000:
                    raise ValueError(f"bundle checkpoint {field} must be a string of at most 20,000 characters")
            if not checkpoint.get("objective", "").strip():
                raise ValueError("bundle checkpoint objective must not be empty")
            version = checkpoint.get("version", 1)
            if isinstance(version, bool) or not isinstance(version, int) or version < 1:
                raise ValueError("bundle checkpoint version must be a positive integer")
        for policy in project.get("policies", []):
            unknown_policy_fields = set(policy) - POLICY_FIELDS
            if unknown_policy_fields:
                raise ValueError(f"bundle contains unknown policy field(s): {', '.join(sorted(unknown_policy_fields))}")
            try:
                provenance = json.loads(policy.get("provenance_json") or "{}")
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("bundle contains invalid policy provenance JSON") from exc
            if not isinstance(provenance, dict):
                raise ValueError("bundle policy provenance must decode to an object")
            if policy.get("status", "active") not in POLICY_STATUSES:
                raise ValueError("bundle policy contains an unknown status")
            overrideable = policy.get("overrideable", True)
            if not isinstance(overrideable, (bool, int)) or overrideable not in {False, True, 0, 1}:
                raise ValueError("bundle policy overrideable must be boolean")
            validate_policy_input(
                kind=policy.get("kind", ""), statement=policy.get("statement", ""),
                effect=policy.get("effect", "warn"), action_contains=policy.get("action_contains", ""),
                path_glob=policy.get("path_glob", ""), required_check=policy.get("required_check", ""),
                pramana=policy.get("pramana", "smriti"), confidence=policy.get("confidence", 0.75),
                provenance=provenance, overrideable=bool(overrideable),
                expires_at=policy.get("expires_at"),
            )
        inspect_text(project)

    total_records = counts["memories"] + counts["checkpoints"] + counts["policies"]
    if total_records > MAX_BUNDLE_RECORDS:
        raise ValueError(f"bundle exceeds the {MAX_BUNDLE_RECORDS:,} record limit")
    warnings = []
    if not bool(bundle.get("redacted")):
        warnings.append("Bundle is explicitly unredacted; review paths and secrets before sharing.")
    residual_count = sum(sensitive_findings.values())
    if residual_count:
        labels = ", ".join(sorted(sensitive_findings))
        warnings.append(f"Detected {residual_count} residual sensitive value(s): {labels}.")
    if bundle.get("redacted") and residual_count:
        raise ValueError("bundle claims redaction but still contains sensitive values")
    return {
        "status": "ok", "kind": bundle["kind"], "schema_version": 1,
        "authenticated": False, "integrity": "content-sha256",
        "redacted": bool(bundle.get("redacted")), "includes": sorted(includes),
        "counts": counts, "conflicts": conflicts, "warnings": warnings,
    }


def export_bundle(
    conn,
    output: Path,
    *,
    projects: list[str] | None = None,
    include: tuple[str, ...] = ("memories", "checkpoints", "policies"),
    redact: bool = True,
    preview: bool = False,
) -> dict:
    init_schema(conn)
    selected_include = set(include)
    if not selected_include or selected_include - ALLOWED_BUNDLE_SECTIONS:
        raise ValueError(f"bundle include must use: {', '.join(sorted(ALLOWED_BUNDLE_SECTIONS))}")
    selected_names = projects or [row["name"] for row in conn.execute("SELECT name FROM projects ORDER BY name")]
    if len(selected_names) > MAX_BUNDLE_PROJECTS:
        raise ValueError(f"bundle project selection exceeds {MAX_BUNDLE_PROJECTS} projects")
    payload_projects = []
    for name in selected_names:
        project = conn.execute("SELECT id, name, repository_identity FROM projects WHERE name = ?", (name,)).fetchone()
        if not project:
            raise ValueError(f"project does not exist: {name}")
        project_id = int(project["id"])
        item = {"name": project["name"], "repository_identity": project["repository_identity"]}
        if "memories" in selected_include:
            item["memories"] = [dict(row) for row in conn.execute(
                """
                SELECT m.type, m.pramana, m.text, m.confidence, m.priority, m.status, m.metadata_json,
                       mp.source_path, mp.source_hash, mp.command, mp.timestamp,
                       mp.verification_status, mp.metadata_json AS provenance_metadata_json
                FROM memories m LEFT JOIN memory_provenance mp ON mp.memory_id = m.id
                WHERE m.project_id = ? ORDER BY m.id
                """,
                (project_id,),
            )]
        if "checkpoints" in selected_include:
            item["checkpoints"] = [dict(row) for row in conn.execute(
                """
                SELECT objective, verified_evidence, remaining_gaps, next_action, prohibited_repetition, version
                FROM checkpoints WHERE project_id = ? ORDER BY version, id
                """,
                (project_id,),
            )]
        if "policies" in selected_include:
            item["policies"] = [dict(row) for row in conn.execute(
                """
                SELECT kind, statement, effect, action_contains, path_glob, required_check, pramana,
                       confidence, provenance_json, overrideable, expires_at, status
                FROM governance_policies WHERE project_id = ? ORDER BY id
                """,
                (project_id,),
            )]
        payload_projects.append(item)
    bundle = {
        "schema_version": 1,
        "kind": "rta-smriti-selective-bundle",
        "created_at": now_iso(),
        "redacted": bool(redact),
        "includes": sorted(selected_include),
        "projects": payload_projects,
    }
    redact_value, redaction_count = _redactor()
    if redact:
        bundle = redact_value(bundle)
    inspection = _validate_bundle(bundle)
    digest = hashlib.sha256(_canonical_json(bundle)).hexdigest()
    envelope = {
        "manifest": {"sha256": digest, "authentication": "none", "integrity": "content-sha256"},
        "bundle": bundle,
    }
    if preview:
        return {
            **inspection, "preview": True, "would_write": str(Path(output).expanduser().resolve()),
            "redactions": redaction_count(), "sha256": digest,
        }
    destination = Path(output).expanduser().resolve()
    _write_private_text(destination, json.dumps(envelope, indent=2, sort_keys=True))
    return {
        "status": "ok", "preview": False, "authenticated": False, "integrity": "content-sha256",
        "path": str(destination), "projects": len(payload_projects),
        "counts": inspection["counts"], "warnings": inspection["warnings"],
        "redactions": redaction_count(), "sha256": digest,
    }


def inspect_bundle(source: Path, *, conn=None) -> dict:
    envelope, bundle = _read_envelope(source)
    if conn is not None:
        init_schema(conn)
    inspection = _validate_bundle(bundle, conn=conn)
    return {
        **inspection,
        "preview": True,
        "path": str(Path(source).expanduser().resolve()),
        "sha256": str(envelope["manifest"]["sha256"]),
    }


def _ensure_quarantine_schema(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS portability_quarantine (
            id INTEGER PRIMARY KEY,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            record_type TEXT NOT NULL CHECK(record_type IN ('checkpoint', 'policy')),
            payload_json TEXT NOT NULL,
            source_bundle_sha256 TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'promoted', 'rejected')),
            created_at TEXT NOT NULL
        )
        """
    )


def _quarantine_record(
    conn,
    *,
    project_id: int,
    record_type: str,
    payload: dict,
    bundle_sha256: str,
) -> None:
    conn.execute(
        """
        INSERT INTO portability_quarantine(
            project_id, record_type, payload_json, source_bundle_sha256, status, created_at
        ) VALUES (?, ?, ?, ?, 'pending', ?)
        """,
        (project_id, record_type, json.dumps(payload, sort_keys=True), bundle_sha256, now_iso()),
    )


def import_bundle(conn, source: Path, *, conflict: str = "rename") -> dict:
    if conflict not in {"rename", "merge", "fail"}:
        raise ValueError("bundle conflict must be rename, merge, or fail")
    envelope, bundle = _read_envelope(source)
    init_schema(conn)
    preview = _validate_bundle(bundle, conn=conn)
    if conflict == "fail" and preview["conflicts"]:
        raise ValueError(f"project already exists: {preview['conflicts'][0]}")
    staging = sqlite3.connect(":memory:")
    staging.row_factory = sqlite3.Row
    conn.backup(staging)
    destination = staging
    _ensure_quarantine_schema(destination)
    bundle_sha256 = str(envelope["manifest"]["sha256"])
    imported_projects = memories = 0
    quarantined_checkpoints = quarantined_policies = 0
    try:
        for project_data in bundle.get("projects", []):
            requested = str(project_data.get("name") or "imported").strip()
            existing = destination.execute("SELECT 1 FROM projects WHERE name = ?", (requested,)).fetchone()
            if existing and conflict == "rename":
                suffix = 2
                name = f"{requested}-imported"
                while destination.execute("SELECT 1 FROM projects WHERE name = ?", (name,)).fetchone():
                    name = f"{requested}-imported-{suffix}"
                    suffix += 1
            else:
                name = requested
            project_id = ensure_project(destination, name)
            imported_projects += 1
            for memory in project_data.get("memories", []):
                metadata = json.loads(memory.get("metadata_json") or "{}")
                provenance_metadata = json.loads(memory.get("provenance_metadata_json") or "{}")
                imported_claims = {
                    "pramana": memory.get("pramana", "smriti"),
                    "status": memory.get("status", "active"),
                    "source_path": memory.get("source_path"),
                    "source_hash": memory.get("source_hash"),
                    "command": memory.get("command"),
                    "timestamp": memory.get("timestamp"),
                    "verification_status": memory.get("verification_status", "unverified"),
                    "provenance_metadata": provenance_metadata,
                    "bundle_sha256": bundle_sha256,
                }
                created = remember(
                    destination, memory.get("text", ""), project=name, memory_type=memory.get("type", "fact"),
                    pramana="smriti", confidence=min(float(memory.get("confidence", 0.75)), 0.75),
                    priority=min(int(memory.get("priority", 5)), 5),
                    metadata={
                        **metadata,
                        "imported_bundle": True,
                        "imported_trust": "unverified",
                        "imported_claims": imported_claims,
                    },
                    provenance={
                        "verification_status": "unverified",
                        "metadata": {
                            "imported_bundle": True,
                            "bundle_sha256": bundle_sha256,
                            "claimed_provenance": imported_claims,
                        },
                    },
                )
                imported_status = str(memory.get("status") or "active")
                if imported_status == "superseded":
                    destination.execute(
                        "UPDATE memories SET status = ? WHERE id = ?",
                        ("superseded", int(created["memory"]["id"])),
                    )
                    destination.commit()
                memories += 1
            for checkpoint in project_data.get("checkpoints", []):
                _quarantine_record(
                    destination,
                    project_id=project_id,
                    record_type="checkpoint",
                    payload=checkpoint,
                    bundle_sha256=bundle_sha256,
                )
                quarantined_checkpoints += 1
            for policy in project_data.get("policies", []):
                _quarantine_record(
                    destination,
                    project_id=project_id,
                    record_type="policy",
                    payload=policy,
                    bundle_sha256=bundle_sha256,
                )
                quarantined_policies += 1
        destination.commit()
        destination.backup(conn)
    finally:
        destination.close()
    return {
        "status": "ok", "authenticated": False, "integrity": "content-sha256",
        "projects": imported_projects, "memories": memories, "checkpoints": 0, "policies": 0,
        "quarantined": {"checkpoints": quarantined_checkpoints, "policies": quarantined_policies},
        "warnings": preview["warnings"],
    }


def _read_or_create_key(key_path: Path, *, create: bool) -> bytes:
    requested = Path(key_path).expanduser()
    if requested.is_symlink():
        raise ValueError("linked snapshot keys are not allowed")
    path = requested.resolve()
    if path.exists():
        key_stat = path.stat()
        if key_stat.st_nlink > 1:
            raise ValueError("linked snapshot keys are not allowed")
        if key_stat.st_size > MAX_SNAPSHOT_KEY_BYTES:
            raise ValueError(f"snapshot key exceeds the {MAX_SNAPSHOT_KEY_BYTES:,} byte limit")
        key = path.read_bytes()
        if len(key) < 32:
            raise ValueError("snapshot key must contain at least 32 bytes")
        return key
    if not create:
        raise ValueError(f"snapshot key does not exist: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(key)
        handle.flush()
        os.fsync(handle.fileno())
    return key


def snapshot_passphrase_keygen(passphrase_path: Path) -> dict:
    """Create a private 256-bit snapshot passphrase file without replacing anything."""
    requested = Path(passphrase_path).expanduser()
    if requested.is_symlink() or requested.exists():
        raise ValueError("snapshot passphrase file already exists")
    path = requested.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())
    return {
        "status": "ok",
        "path": str(path),
        "entropy_bits": len(value) * 8,
        "created": True,
    }


def _read_required_key_file(key_path: Path, *, label: str, limit: int) -> bytes:
    requested = Path(key_path).expanduser()
    if requested.is_symlink():
        raise ValueError(f"linked {label} keys are not allowed")
    path = requested.resolve()
    if not path.exists():
        raise ValueError(f"{label} key does not exist: {path}")
    stat = path.stat()
    if stat.st_nlink > 1:
        raise ValueError(f"linked {label} keys are not allowed")
    if stat.st_size > limit:
        raise ValueError(f"{label} key exceeds the {limit:,} byte limit")
    return path.read_bytes()


def _load_ed25519_private_key(private_key_path: Path):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ValueError(
            "Ed25519 snapshots require the optional cryptography package; "
            "install rta-smriti-brain[signing] locally"
        ) from exc
    key_bytes = _read_required_key_file(private_key_path, label="snapshot private", limit=MAX_PRIVATE_KEY_BYTES)
    try:
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except ValueError as exc:
        raise ValueError("snapshot private key must be an unencrypted Ed25519 PEM key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("snapshot private key must be an Ed25519 key")
    return key


def _load_ed25519_public_key(public_key_path: Path):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ValueError(
            "Ed25519 snapshot verification requires the optional cryptography package; "
            "install rta-smriti-brain[signing] locally"
        ) from exc
    key_bytes = _read_required_key_file(public_key_path, label="snapshot public", limit=MAX_PUBLIC_KEY_BYTES)
    try:
        key = serialization.load_pem_public_key(key_bytes)
    except ValueError as exc:
        raise ValueError("snapshot public key must be an Ed25519 PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("snapshot public key must be an Ed25519 key")
    return key


def snapshot_keygen(private_key_path: Path, public_key_path: Path) -> dict:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ValueError(
            "Ed25519 snapshot key generation requires the optional cryptography package; "
            "install rta-smriti-brain[signing] locally"
        ) from exc
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    _write_private_text(private_key_path, private_bytes)
    _write_private_text(public_key_path, public_bytes)
    return {
        "status": "ok",
        "signature_algorithm": "Ed25519",
        "private_key": str(Path(private_key_path).expanduser().resolve()),
        "public_key": str(Path(public_key_path).expanduser().resolve()),
    }


def _exactly_one_auth(**values) -> None:
    selected = [name for name, value in values.items() if value is not None]
    if len(selected) != 1:
        raise ValueError("provide exactly one snapshot authentication material option")


def snapshot_create(
    db_path: Path,
    output: Path,
    *,
    key_path: Path | None = None,
    private_key_path: Path | None = None,
) -> dict:
    _exactly_one_auth(key_path=key_path, private_key_path=private_key_path)
    requested_source = Path(db_path).expanduser()
    if requested_source.is_symlink():
        raise ValueError("linked brain databases are not allowed for snapshots")
    source_path = requested_source.resolve()
    if not source_path.is_file():
        raise ValueError(f"brain database does not exist: {source_path}")
    if source_path.stat().st_nlink > 1:
        raise ValueError("linked brain databases are not allowed for snapshots")
    key = _read_or_create_key(key_path, create=True) if key_path is not None else None
    private_key = _load_ed25519_private_key(private_key_path) if private_key_path is not None else None
    with tempfile.TemporaryDirectory(prefix="rta-snapshot-") as tmp:
        consistent = Path(tmp) / "brain.sqlite"
        source = sqlite3.connect(str(source_path))
        target = sqlite3.connect(str(consistent))
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        database_bytes = consistent.stat().st_size
        if database_bytes > MAX_SNAPSHOT_DATABASE_BYTES:
            raise ValueError(
                f"brain database exceeds the {MAX_SNAPSHOT_DATABASE_BYTES // (1024 * 1024)} MiB snapshot limit"
            )
        database_hash = hashlib.sha256()
        with consistent.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                database_hash.update(chunk)
        consistent_db = sqlite3.connect(str(consistent))
        try:
            project_count = int(consistent_db.execute("SELECT COUNT(*) FROM projects").fetchone()[0])
        finally:
            consistent_db.close()
        manifest = {
            "schema_version": 2, "kind": "rta-smriti-signed-snapshot", "created_at": now_iso(),
            "database_sha256": database_hash.hexdigest(), "database_bytes": database_bytes,
            "project_count": project_count,
            "signature_algorithm": "Ed25519" if private_key is not None else "HMAC-SHA256",
            "payload_encoding": "base64-lines",
        }
        if private_key is not None:
            signature = base64.b64encode(private_key.sign(_canonical_json(manifest))).decode("ascii")
        else:
            signature = hmac.new(key, _canonical_json(manifest), hashlib.sha256).hexdigest()
        requested_destination = Path(output).expanduser()
        if requested_destination.is_symlink():
            raise ValueError("refusing to replace a linked portability artifact")
        destination = requested_destination.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and destination.stat().st_nlink > 1:
            raise ValueError("refusing to replace a linked portability artifact")
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output_handle, consistent.open("rb") as database_handle:
                header = _canonical_json({"manifest": manifest, "signature": signature})
                if len(header) > MAX_SNAPSHOT_HEADER_BYTES:
                    raise ValueError("snapshot manifest exceeds the safe header limit")
                output_handle.write(header + b"\n")
                for chunk in iter(lambda: database_handle.read(48 * 1024), b""):
                    output_handle.write(base64.b64encode(chunk))
                output_handle.flush()
                os.fsync(output_handle.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {
        "status": "ok", "path": str(destination), "schema_version": 2,
        "signature_algorithm": manifest["signature_algorithm"], "project_count": project_count,
        "database_bytes": database_bytes,
    }


ENCRYPTED_SNAPSHOT_MAGIC = b"RTA-SMRITI-ENCRYPTED-V3\n"
ENCRYPTED_SNAPSHOT_TAG_BYTES = 16
ENCRYPTED_SNAPSHOT_SCRYPT_N = 2**17
ENCRYPTED_SNAPSHOT_SCRYPT_R = 8
ENCRYPTED_SNAPSHOT_SCRYPT_P = 1
MAX_ENCRYPTED_SNAPSHOT_BYTES = (
    len(ENCRYPTED_SNAPSHOT_MAGIC) + MAX_SNAPSHOT_HEADER_BYTES + 1
    + MAX_SNAPSHOT_DATABASE_BYTES + ENCRYPTED_SNAPSHOT_TAG_BYTES
)


def _snapshot_passphrase(path: Path) -> bytes:
    value = _read_required_key_file(
        path, label="snapshot passphrase", limit=MAX_SNAPSHOT_PASSPHRASE_BYTES,
    ).rstrip(b"\r\n")
    if len(value) < 12:
        raise ValueError("snapshot passphrase must contain at least 12 bytes")
    return value


def _derive_snapshot_encryption_key(passphrase: bytes, salt: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError as exc:
        raise ValueError(
            "encrypted snapshots require the optional cryptography package; "
            "install rta-smriti-brain[signing] locally"
        ) from exc
    return Scrypt(
        salt=salt,
        length=32,
        n=ENCRYPTED_SNAPSHOT_SCRYPT_N,
        r=ENCRYPTED_SNAPSHOT_SCRYPT_R,
        p=ENCRYPTED_SNAPSHOT_SCRYPT_P,
    ).derive(passphrase)


def snapshot_create_encrypted(
    db_path: Path,
    output: Path,
    *,
    passphrase_path: Path,
    private_key_path: Path | None = None,
) -> dict:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ValueError(
            "encrypted snapshots require the optional cryptography package; "
            "install rta-smriti-brain[signing] locally"
        ) from exc
    requested_source = Path(db_path).expanduser()
    if requested_source.is_symlink():
        raise ValueError("linked brain databases are not allowed for snapshots")
    source_path = requested_source.resolve()
    if not source_path.is_file() or source_path.stat().st_nlink > 1:
        raise ValueError("brain database must be an existing unlinked file")
    passphrase = _snapshot_passphrase(passphrase_path)
    private_key = _load_ed25519_private_key(private_key_path) if private_key_path else None
    requested_destination = Path(output).expanduser()
    if requested_destination.is_symlink():
        raise ValueError("refusing to replace a linked portability artifact")
    destination = requested_destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and destination.stat().st_nlink > 1:
        raise ValueError("refusing to replace a linked portability artifact")

    with tempfile.TemporaryDirectory(prefix="rta-encrypted-snapshot-") as tmp:
        consistent = Path(tmp) / "brain.sqlite"
        source = sqlite3.connect(str(source_path))
        target = sqlite3.connect(str(consistent))
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        database_bytes = consistent.stat().st_size
        if database_bytes > MAX_SNAPSHOT_DATABASE_BYTES:
            raise ValueError(
                f"brain database exceeds the {MAX_SNAPSHOT_DATABASE_BYTES // (1024 * 1024)} MiB snapshot limit"
            )
        digest = hashlib.sha256()
        with consistent.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        check = sqlite3.connect(str(consistent))
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("brain database failed SQLite integrity verification")
            project_count = int(check.execute("SELECT COUNT(*) FROM projects").fetchone()[0])
        finally:
            check.close()
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        manifest = {
            "schema_version": 3,
            "kind": "rta-smriti-encrypted-snapshot",
            "created_at": now_iso(),
            "database_sha256": digest.hexdigest(),
            "database_bytes": database_bytes,
            "project_count": project_count,
            "encryption": "AES-256-GCM",
            "kdf": {
                "name": "scrypt",
                "n": ENCRYPTED_SNAPSHOT_SCRYPT_N,
                "r": ENCRYPTED_SNAPSHOT_SCRYPT_R,
                "p": ENCRYPTED_SNAPSHOT_SCRYPT_P,
                "salt": base64.b64encode(salt).decode("ascii"),
            },
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "signature_algorithm": "Ed25519" if private_key else "none",
        }
        signature = (
            base64.b64encode(private_key.sign(_canonical_json(manifest))).decode("ascii")
            if private_key else None
        )
        header = _canonical_json({"manifest": manifest, "signature": signature})
        if len(header) > MAX_SNAPSHOT_HEADER_BYTES:
            raise ValueError("encrypted snapshot manifest exceeds the safe header limit")
        key = _derive_snapshot_encryption_key(passphrase, salt)
        temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(temporary, flags, 0o600)
        try:
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(header)
            with os.fdopen(descriptor, "wb") as output_handle, consistent.open("rb") as database_handle:
                output_handle.write(ENCRYPTED_SNAPSHOT_MAGIC)
                output_handle.write(header + b"\n")
                for chunk in iter(lambda: database_handle.read(1024 * 1024), b""):
                    output_handle.write(encryptor.update(chunk))
                output_handle.write(encryptor.finalize())
                output_handle.write(encryptor.tag)
                output_handle.flush()
                os.fsync(output_handle.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
    return {
        "status": "ok", "path": str(destination), "schema_version": 3,
        "encryption": "AES-256-GCM", "signature_algorithm": manifest["signature_algorithm"],
        "project_count": project_count, "database_bytes": database_bytes,
    }


def _decrypt_encrypted_snapshot(
    source: Path,
    passphrase_path: Path,
    destination: Path,
    *,
    public_key_path: Path | None = None,
) -> dict:
    try:
        from cryptography.exceptions import InvalidSignature, InvalidTag
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise ValueError(
            "encrypted snapshots require the optional cryptography package; "
            "install rta-smriti-brain[signing] locally"
        ) from exc
    requested = Path(source).expanduser()
    if requested.is_symlink() or not requested.is_file() or requested.stat().st_nlink > 1:
        raise ValueError("encrypted snapshot must be an existing unlinked file")
    resolved = requested.resolve()
    if resolved.stat().st_size > MAX_ENCRYPTED_SNAPSHOT_BYTES:
        raise ValueError("encrypted snapshot exceeds the safe size limit")
    passphrase = _snapshot_passphrase(passphrase_path)
    with resolved.open("rb") as handle:
        if handle.read(len(ENCRYPTED_SNAPSHOT_MAGIC)) != ENCRYPTED_SNAPSHOT_MAGIC:
            raise ValueError("not an Rta-Smriti encrypted snapshot")
        header = handle.readline(MAX_SNAPSHOT_HEADER_BYTES + 1)
        if not header.endswith(b"\n") or len(header) > MAX_SNAPSHOT_HEADER_BYTES:
            raise ValueError("encrypted snapshot header is invalid")
        header = header[:-1]
        try:
            envelope = json.loads(header)
            manifest = envelope["manifest"]
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("encrypted snapshot manifest is invalid") from exc
        required = {
            "schema_version", "kind", "created_at", "database_sha256", "database_bytes",
            "project_count", "encryption", "kdf", "nonce", "signature_algorithm",
        }
        if not isinstance(manifest, dict) or set(manifest) != required:
            raise ValueError("encrypted snapshot manifest fields are missing or unsupported")
        if manifest.get("schema_version") != 3 or manifest.get("kind") != "rta-smriti-encrypted-snapshot":
            raise ValueError("unsupported encrypted snapshot schema")
        if manifest.get("encryption") != "AES-256-GCM" or manifest.get("signature_algorithm") not in {"none", "Ed25519"}:
            raise ValueError("unsupported encrypted snapshot cryptography")
        kdf = manifest.get("kdf")
        if not isinstance(kdf, dict) or set(kdf) != {"name", "n", "r", "p", "salt"}:
            raise ValueError("encrypted snapshot KDF parameters are invalid")
        if (kdf.get("name"), kdf.get("n"), kdf.get("r"), kdf.get("p")) != (
            "scrypt",
            ENCRYPTED_SNAPSHOT_SCRYPT_N,
            ENCRYPTED_SNAPSHOT_SCRYPT_R,
            ENCRYPTED_SNAPSHOT_SCRYPT_P,
        ):
            raise ValueError("unsupported encrypted snapshot KDF parameters")
        try:
            salt = base64.b64decode(kdf["salt"], validate=True)
            nonce = base64.b64decode(manifest["nonce"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("encrypted snapshot salt or nonce is invalid") from exc
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("encrypted snapshot salt or nonce has an invalid length")
        signature = envelope.get("signature")
        signature_verified = False
        if manifest["signature_algorithm"] == "Ed25519":
            if public_key_path is not None:
                try:
                    _load_ed25519_public_key(public_key_path).verify(
                        base64.b64decode(signature, validate=True), _canonical_json(manifest),
                    )
                    signature_verified = True
                except (InvalidSignature, ValueError, TypeError):
                    return {"status": "invalid", "valid": False, "reason": "snapshot signature verification failed"}
        elif signature is not None:
            raise ValueError("unsigned encrypted snapshot contains an unexpected signature")
        payload_start = handle.tell()
        payload_bytes = resolved.stat().st_size - payload_start - ENCRYPTED_SNAPSHOT_TAG_BYTES
        declared_bytes = manifest.get("database_bytes")
        if not isinstance(declared_bytes, int) or declared_bytes < 0 or declared_bytes > MAX_SNAPSHOT_DATABASE_BYTES:
            raise ValueError("encrypted snapshot database size is invalid")
        if payload_bytes != declared_bytes:
            return {"status": "invalid", "valid": False, "reason": "encrypted snapshot payload size mismatch"}
        handle.seek(-ENCRYPTED_SNAPSHOT_TAG_BYTES, os.SEEK_END)
        tag = handle.read(ENCRYPTED_SNAPSHOT_TAG_BYTES)
        handle.seek(payload_start)
        key = _derive_snapshot_encryption_key(passphrase, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        digest = hashlib.sha256()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        descriptor = os.open(destination, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output_handle:
                remaining = payload_bytes
                while remaining:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        return {"status": "invalid", "valid": False, "reason": "encrypted snapshot payload is truncated"}
                    clear = decryptor.update(chunk)
                    output_handle.write(clear)
                    digest.update(clear)
                    remaining -= len(chunk)
                try:
                    clear = decryptor.finalize()
                except InvalidTag:
                    return {"status": "invalid", "valid": False, "reason": "snapshot passphrase or authentication tag is invalid"}
                output_handle.write(clear)
                digest.update(clear)
                output_handle.flush()
                os.fsync(output_handle.fileno())
        finally:
            if destination.exists() and digest.hexdigest() != manifest.get("database_sha256"):
                destination.unlink()
        if digest.hexdigest() != manifest.get("database_sha256"):
            return {"status": "invalid", "valid": False, "reason": "decrypted database digest mismatch"}
    check = sqlite3.connect(str(destination))
    try:
        if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            destination.unlink(missing_ok=True)
            return {"status": "invalid", "valid": False, "reason": "decrypted database failed SQLite integrity verification"}
    finally:
        check.close()
    return {
        "status": "ok", "valid": True, "schema_version": 3, "encryption": "AES-256-GCM",
        "signature_algorithm": manifest["signature_algorithm"], "signature_verified": signature_verified,
        "database_bytes": declared_bytes, "project_count": manifest["project_count"],
    }


def snapshot_verify_encrypted(
    source: Path, *, passphrase_path: Path, public_key_path: Path | None = None,
) -> dict:
    with tempfile.TemporaryDirectory(prefix="rta-encrypted-verify-") as tmp:
        destination = Path(tmp) / "brain.sqlite"
        return _decrypt_encrypted_snapshot(
            source, passphrase_path, destination, public_key_path=public_key_path,
        )


def snapshot_restore_encrypted(
    source: Path,
    output_db: Path,
    *,
    passphrase_path: Path,
    public_key_path: Path | None = None,
) -> dict:
    requested = Path(output_db).expanduser()
    if requested.is_symlink():
        raise ValueError("refusing to restore through a linked database path")
    destination = requested.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValueError("refusing to replace an existing database during snapshot restore")
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    try:
        result = _decrypt_encrypted_snapshot(
            source, passphrase_path, temporary, public_key_path=public_key_path,
        )
        if not result.get("valid"):
            temporary.unlink(missing_ok=True)
            return result
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise ValueError("refusing to replace an existing database during snapshot restore") from exc
        except OSError as exc:
            raise ValueError("snapshot restore requires atomic no-clobber file creation") from exc
        temporary.unlink()
        return {**result, "path": str(destination)}
    finally:
        temporary.unlink(missing_ok=True)


def _validate_snapshot_manifest(manifest, *, schema_version: int) -> tuple[dict | None, str | None]:
    if not isinstance(manifest, dict):
        return None, "snapshot manifest must be an object"
    allowed = {
        "schema_version", "kind", "created_at", "database_sha256", "database_bytes",
        "project_count", "signature_algorithm",
    }
    if schema_version == 2:
        allowed.add("payload_encoding")
    if set(manifest) != allowed:
        return None, "snapshot manifest fields are missing or unsupported"
    if manifest.get("schema_version") != schema_version:
        return None, "unsupported snapshot schema version"
    if manifest.get("kind") != "rta-smriti-signed-snapshot":
        return None, "not an Rta-Smriti snapshot"
    if manifest.get("signature_algorithm") not in {"HMAC-SHA256", "Ed25519"}:
        return None, "unsupported snapshot signature algorithm"
    if schema_version == 1 and manifest.get("signature_algorithm") != "HMAC-SHA256":
        return None, "unsupported legacy snapshot signature algorithm"
    if schema_version == 2 and manifest.get("payload_encoding") != "base64-lines":
        return None, "unsupported snapshot payload encoding"
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip() or len(created_at) > 100:
        return None, "snapshot created_at is invalid"
    digest = manifest.get("database_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None, "snapshot database digest is invalid"
    database_bytes = manifest.get("database_bytes")
    project_count = manifest.get("project_count")
    if isinstance(database_bytes, bool) or not isinstance(database_bytes, int) or database_bytes < 0:
        return None, "snapshot database size is invalid"
    if database_bytes > MAX_SNAPSHOT_DATABASE_BYTES:
        return None, "snapshot database exceeds the safe verification limit"
    if isinstance(project_count, bool) or not isinstance(project_count, int) or project_count < 0:
        return None, "snapshot project count is invalid"
    return manifest, None


def _authenticate_manifest(
    header,
    *,
    key: bytes | None = None,
    public_key_path: Path | None = None,
    schema_version: int,
) -> tuple[dict | None, str | None]:
    if not isinstance(header, dict) or set(header) != {"manifest", "signature"}:
        return None, "snapshot header fields are missing or unsupported"
    manifest, error = _validate_snapshot_manifest(header.get("manifest"), schema_version=schema_version)
    if error:
        return None, error
    signature = header.get("signature")
    algorithm = manifest.get("signature_algorithm")
    if algorithm == "HMAC-SHA256":
        if key is None:
            return None, "snapshot HMAC key is required for this snapshot"
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
            return None, "snapshot signature is invalid"
        expected = hmac.new(key, _canonical_json(manifest), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None, "snapshot manifest authentication failed"
    elif algorithm == "Ed25519":
        if public_key_path is None:
            return None, "snapshot public key is required for this snapshot"
        if not isinstance(signature, str) or not re.fullmatch(r"[A-Za-z0-9+/=]{40,200}", signature):
            return None, "snapshot signature is invalid"
        public_key = _load_ed25519_public_key(public_key_path)
        try:
            public_key.verify(base64.b64decode(signature, validate=True), _canonical_json(manifest))
        except Exception:
            return None, "snapshot manifest authentication failed"
    return manifest, None


def _verify_base64_chunks(chunks, *, manifest: dict) -> tuple[bool, str]:
    declared_bytes = int(manifest["database_bytes"])
    expected_encoded = ((declared_bytes + 2) // 3) * 4
    encoded_bytes = decoded_bytes = 0
    digest = hashlib.sha256()
    for chunk in chunks:
        if not isinstance(chunk, (bytes, bytearray)):
            return False, "snapshot payload is not Base64 bytes"
        encoded_bytes += len(chunk)
        if encoded_bytes > expected_encoded:
            return False, "snapshot payload exceeds its authenticated size"
        try:
            decoded = base64.b64decode(chunk, validate=True)
        except (ValueError, base64.binascii.Error):
            return False, "snapshot payload is not valid Base64"
        decoded_bytes += len(decoded)
        if decoded_bytes > declared_bytes or decoded_bytes > MAX_SNAPSHOT_DATABASE_BYTES:
            return False, "snapshot decoded payload exceeds its authenticated size"
        digest.update(decoded)
    if encoded_bytes != expected_encoded or decoded_bytes != declared_bytes:
        return False, "snapshot payload size does not match its authenticated manifest"
    if not hmac.compare_digest(digest.hexdigest(), str(manifest["database_sha256"])):
        return False, "snapshot database digest mismatch"
    return True, "verified"


def _fixed_base64_chunks(handle):
    while True:
        chunk = handle.read(64 * 1024)
        if not chunk:
            return
        yield chunk


def _legacy_base64_chunks(payload: str):
    for offset in range(0, len(payload), 64 * 1024):
        yield payload[offset : offset + 64 * 1024].encode("ascii")


def snapshot_verify(
    source: Path,
    *,
    key_path: Path | None = None,
    public_key_path: Path | None = None,
) -> dict:
    _exactly_one_auth(key_path=key_path, public_key_path=public_key_path)
    key = _read_or_create_key(key_path, create=False) if key_path is not None else None
    requested = Path(source).expanduser()
    if requested.is_symlink():
        return {"status": "ok", "valid": False, "reason": "linked snapshot inputs are not allowed"}
    resolved = requested.resolve()
    if not resolved.is_file() or resolved.stat().st_nlink > 1:
        return {"status": "ok", "valid": False, "reason": "snapshot input is missing or linked"}
    file_size = resolved.stat().st_size
    if file_size > MAX_SNAPSHOT_FILE_BYTES:
        return {"status": "ok", "valid": False, "reason": "snapshot exceeds the safe verification limit"}
    try:
        with resolved.open("rb") as handle:
            first_line = handle.readline(MAX_SNAPSHOT_HEADER_BYTES + 1)
            if first_line.endswith(b"\n"):
                header = json.loads(first_line[:-1].decode("ascii"))
                if isinstance(header, dict) and "database_base64" not in header:
                    manifest, error = _authenticate_manifest(
                        header, key=key, public_key_path=public_key_path, schema_version=2,
                    )
                    if error:
                        return {"status": "ok", "valid": False, "reason": error}
                    valid, reason = _verify_base64_chunks(_fixed_base64_chunks(handle), manifest=manifest)
                    return {"status": "ok", "valid": valid, "reason": reason, "manifest": manifest}
        if file_size > MAX_LEGACY_SNAPSHOT_BYTES:
            return {
                "status": "ok", "valid": False,
                "reason": "legacy snapshot exceeds the safe verification limit; recreate it with this version",
            }
        legacy_text = read_text(resolved, MAX_LEGACY_SNAPSHOT_BYTES)
        if legacy_text is None:
            return {
                "status": "ok", "valid": False,
                "reason": "legacy snapshot changed while being read or violates the safe input policy",
            }
        envelope = json.loads(legacy_text)
        if not isinstance(envelope, dict):
            raise ValueError("snapshot envelope must be an object")
        header = {"manifest": envelope.get("manifest"), "signature": envelope.get("signature")}
        manifest, error = _authenticate_manifest(header, key=key, public_key_path=public_key_path, schema_version=1)
        if error:
            return {"status": "ok", "valid": False, "reason": error}
        payload = envelope.get("database_base64")
        if not isinstance(payload, str):
            raise ValueError("legacy snapshot payload must be a Base64 string")
        valid, reason = _verify_base64_chunks(_legacy_base64_chunks(payload), manifest=manifest)
        return {"status": "ok", "valid": valid, "reason": reason, "manifest": manifest}
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError, json.JSONDecodeError) as exc:
        return {"status": "ok", "valid": False, "reason": f"invalid snapshot envelope: {exc}"}
