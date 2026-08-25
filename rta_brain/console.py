import hmac
import ipaddress
import json
import mimetypes
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from socketserver import TCPServer
from urllib.parse import parse_qs, urlparse

from .capture import (
    bind_session,
    close_session_binding,
    control_capture_retention,
    delete_capture_content,
    export_capture_events,
    list_capture_policies,
    list_capture_sources,
    register_policy,
    retire_capture_policy,
    set_capture_source_state,
)
from .capture_control import (
    capture_diagnostics,
    capture_replay,
    capture_status_report,
)
from .capture_daemon import start_capture, stop_capture
from .capture_types import CapturePolicy
from .context import build_context_pack, build_continuation_prompt
from .cognition import cognition_snapshot, record_observation, reconcile_observation
from .context_host import (
    audit_context_for_operator,
    authorize_context_contract,
    build_task_contract,
    compile_context_for_agent,
    ensure_context_agent_profile,
    explain_context_for_agent,
    record_context_outcome_for_operator,
    revoke_context_compilation_grant,
)
from .continuity import operational_readiness
from .continuity_daemon import continuity_status, start_continuity, stop_continuity
from .db import (
    attach_memory_provenance,
    connect,
    get_project_settings,
    graph,
    graph_query,
    ingest_repo,
    init_schema,
    integrity_diagnostics,
    latest_checkpoint,
    reflect,
    remember,
    save_checkpoint,
    search,
    stale_check,
    update_project_settings,
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
from .hooks import install_git_hooks, uninstall_git_hooks
from .lifecycle import apply_memory_feedback, run_conservative_decay
from .multimodal import (
    add_derivation,
    delete_media,
    export_multimodal_manifest,
    ingest_media,
    list_multimodal_derivations,
    list_multimodal_evidence,
    purge_expired_media,
    redact_derivation,
    set_media_retention,
    verify_multimodal_source,
)
from .parsers import ParserRegistry
from .portability import (
    export_bundle,
    import_bundle,
    inspect_bundle,
    snapshot_create,
    snapshot_create_encrypted,
    snapshot_keygen,
    snapshot_passphrase_keygen,
    snapshot_restore_encrypted,
    snapshot_verify,
    snapshot_verify_encrypted,
)
from .project import (
    mcp_config_payload,
    mcp_doctor,
    projects_list,
    runtime_shell,
    self_check,
    shell_cli_command,
)
from .repository import (
    canonical_root,
    canonical_root_key,
    inspect_repository,
    trusted_git_candidates,
)
from .temporal import (
    append_claim,
    attach_evidence,
    change_claim_state,
    define_validator,
    observe_repository_anchor,
    rebuild_projections,
    record_abstention,
    redact_truth_for_operator,
    relate_claims,
    revise_claim,
    run_validator,
    truth_as_of,
    truth_at_commit,
    truth_current,
    truth_diff,
    truth_explain,
    truth_history,
    truth_overview,
    validator_history,
    verify_ledger,
)
from .watch_daemon import start_watcher, stop_watcher, watcher_status
from .workspaces import (
    add_project_to_workspace,
    create_workspace,
    delete_workspace,
    get_workspace,
    list_workspaces,
    remove_project_from_workspace,
    search_workspace,
    workspace_health,
)


@dataclass(frozen=True)
class ConsoleConfig:
    tool_root: Path
    brain_dir: Path
    default_db: Path | None = None
    default_project: str | None = None
    capability_token: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    instance_id: str | None = None


MAX_REQUEST_BYTES = 1_048_576
MAX_TREE_ITEMS = 500
MAX_FILE_PREVIEW_CHARS = 20_000


def _capture_policy_from_payload(payload: dict) -> CapturePolicy:
    profile = str(payload.get("profile", "continuity")).strip().lower()
    if profile == "metadata-only":
        base = CapturePolicy.metadata_only()
    elif profile == "continuity":
        base = CapturePolicy.continuity()
    elif profile == "forensic":
        base = CapturePolicy(profile="forensic", retain_payloads=True)
    else:
        raise ValueError("capture policy profile must be metadata-only, continuity, or forensic")
    retain_payloads = payload.get("retain_payloads", base.retain_payloads)
    if type(retain_payloads) is not bool:
        raise ValueError("retain_payloads must be a boolean")
    return CapturePolicy(
        profile=base.profile,
        enabled_event_names=base.enabled_event_names,
        field_allowlist=base.field_allowlist,
        privacy_ceiling=str(payload.get("privacy_ceiling", base.privacy_ceiling)),
        retain_payloads=retain_payloads,
        retention_seconds=int(payload.get("retention_seconds", base.retention_seconds)),
        max_event_bytes=int(payload.get("max_event_bytes", base.max_event_bytes)),
        max_field_chars=int(payload.get("max_field_chars", base.max_field_chars)),
        max_collection_items=int(payload.get("max_collection_items", base.max_collection_items)),
    )


def _trusted_git_candidates() -> list[Path]:
    return trusted_git_candidates()


def resolve_brain_db(config: ConsoleConfig, value: str | Path, must_exist: bool = True) -> Path:
    candidate = Path(value).expanduser().resolve()
    if candidate.suffix.lower() != ".sqlite":
        raise ValueError("brain database must be a .sqlite file")
    brain_root = config.brain_dir.expanduser().resolve()
    try:
        candidate.relative_to(brain_root)
        allowed = True
    except ValueError:
        allowed = False
    if config.default_db and candidate == config.default_db.expanduser().resolve():
        allowed = True
    if not allowed:
        raise ValueError("brain database is outside the configured brain directory")
    if must_exist and not candidate.is_file():
        raise ValueError(f"brain database does not exist: {candidate}")
    if candidate.exists() and candidate.stat().st_nlink > 1:
        raise ValueError("hard-linked brain databases are not allowed")
    return candidate


def _row_count(conn: sqlite3.Connection, table: str, project_id: int | None = None) -> int:
    if project_id is None:
        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
    else:
        row = conn.execute(f"SELECT COUNT(*) AS c FROM {table} WHERE project_id = ?", (project_id,)).fetchone()
    return int(row["c"])


def _open_db(db_path: str | Path) -> sqlite3.Connection:
    return connect(Path(db_path).expanduser().resolve())


def _project_root(conn: sqlite3.Connection, project: str) -> Path:
    row = conn.execute(
        "SELECT root_path FROM projects WHERE name = ?", (str(project).strip(),)
    ).fetchone()
    if not row or not row["root_path"]:
        raise ValueError("temporal truth mutation requires a canonical project root")
    return Path(str(row["root_path"])).expanduser().resolve()


def scan_brain_registry(brain_dir: Path) -> list[dict]:
    """Discover project identities and cheap counts without repository inspection."""
    brain_dir = brain_dir.expanduser().resolve()
    if not brain_dir.exists():
        return []
    entries: list[dict] = []
    for db_path in sorted(brain_dir.glob("*.sqlite")):
        conn = None
        try:
            if db_path.is_symlink() or db_path.stat().st_nlink > 1:
                continue
            conn = _open_db(db_path)
            init_schema(conn)
            payload = projects_list(conn)
            for project in payload["projects"]:
                root_path = project.get("root_path")
                entries.append(
                    {
                        "status": "ok",
                        "scan_state": "checking",
                        "db_path": str(db_path),
                        "db_file": db_path.name,
                        "project": project["name"],
                        "root_path": root_path,
                        "repository_identity": project.get("repository_identity"),
                        "canonical_root": canonical_root(root_path) if root_path else None,
                        "created_at": project.get("created_at"),
                        "ready": None,
                        "integrity": {"status": "checking", "operationally_ready": False},
                        "sources": int(project.get("sources") or 0),
                        "memories": int(project.get("memories") or 0),
                        "freshness": {"mode": "summary", "state": "not_checked"},
                        "suggested_next_command": None,
                    }
                )
        except Exception as exc:
            entries.append(
                {
                    "status": "error",
                    "scan_state": "error",
                    "db_path": str(db_path),
                    "db_file": db_path.name,
                    "project": db_path.stem,
                    "ready": False,
                    "error": f"{exc.__class__.__name__}: {exc}",
                }
            )
        finally:
            if conn is not None:
                conn.close()
    roots_by_project: dict[str, dict[str, str]] = {}
    projects_by_root: dict[str, list[dict]] = {}
    for entry in entries:
        if entry.get("status") != "ok" or not entry.get("canonical_root"):
            continue
        root = str(entry["canonical_root"])
        roots_by_project.setdefault(str(entry["project"]).casefold(), {})[canonical_root_key(root)] = root
        projects_by_root.setdefault(canonical_root_key(root), []).append(entry)
    for entry in entries:
        roots = roots_by_project.get(str(entry.get("project", "")).casefold(), {})
        entry["root_conflict"] = len(roots) > 1
        owners = projects_by_root.get(canonical_root_key(entry["canonical_root"]), []) if entry.get("canonical_root") else []
        entry["root_duplicate"] = len(owners) > 1
    return entries

def scan_brain_databases(brain_dir: Path) -> list[dict]:
    brain_dir = brain_dir.expanduser().resolve()
    if not brain_dir.exists():
        return []
    entries: list[dict] = []
    repository_inspections = {}
    for db_path in sorted(brain_dir.glob("*.sqlite")):
        conn = None
        try:
            if db_path.is_symlink() or db_path.stat().st_nlink > 1:
                continue
            conn = _open_db(db_path)
            init_schema(conn)
            payload = projects_list(conn)
            for project in payload["projects"]:
                root_path = project.get("root_path")
                root_key = canonical_root_key(root_path) if root_path else ""
                inspection = repository_inspections.get(root_key)
                if inspection is None:
                    inspection = inspect_repository(root_path)
                    repository_inspections[root_key] = inspection
                health = self_check(
                    conn,
                    project=project["name"],
                    check_files=False,
                    active_root=root_path if root_path and Path(root_path).is_dir() else None,
                    repository_inspection=inspection,
                )
                project_id = int(project["id"])
                git = inspection.state()
                integrity = health["integrity"]
                entries.append(
                    {
                        "status": "ok",
                        "db_path": str(db_path),
                        "db_file": db_path.name,
                        "project": project["name"],
                        "root_path": project.get("root_path"),
                        "repository_identity": project.get("repository_identity"),
                        "canonical_root": canonical_root(project["root_path"]) if project.get("root_path") else None,
                        "git": git,
                        "created_at": project.get("created_at"),
                        "ready": bool(health["ready"] and integrity["operationally_ready"]),
                        "integrity": integrity,
                        "sources": int(health["sources"]),
                        "memories": int(health["memories"]),
                        "entities": int(health["entities"]),
                        "chunks": _row_count(conn, "chunks"),
                        "edges": _row_count(conn, "edges", project_id),
                        "freshness": health["freshness"],
                        "suggested_next_command": health["suggested_next_command"],
                    }
                )
        except Exception as exc:
            entries.append(
                {
                    "status": "error",
                    "db_path": str(db_path),
                    "db_file": db_path.name,
                    "project": db_path.stem,
                    "error": f"{exc.__class__.__name__}: {exc}",
                }
            )
        finally:
            if conn is not None:
                conn.close()
    roots_by_project: dict[str, dict[str, str]] = {}
    projects_by_root: dict[str, list[dict]] = {}
    for entry in entries:
        if entry.get("status") != "ok" or not entry.get("canonical_root"):
            continue
        root = str(entry["canonical_root"])
        roots_by_project.setdefault(str(entry["project"]).casefold(), {})[canonical_root_key(root)] = root
        projects_by_root.setdefault(canonical_root_key(root), []).append(entry)
    for entry in entries:
        roots = roots_by_project.get(str(entry.get("project", "")).casefold(), {})
        entry["root_conflict"] = len(roots) > 1
        root_owners = projects_by_root.get(canonical_root_key(entry["canonical_root"]), []) if entry.get("canonical_root") else []
        entry["root_duplicate"] = len(root_owners) > 1
        entry["ready"] = bool(entry.get("ready") and not entry["root_conflict"] and not entry["root_duplicate"])
        if len(roots) > 1:
            entry["root_conflict_roots"] = sorted(roots.values())
    return entries


def read_memories(
    db_path: str | Path,
    project: str,
    query: str = "",
    memory_type: str = "",
    pramana: str = "",
    status: str = "",
    limit: int = 100,
) -> dict:
    conn = _open_db(db_path)
    try:
        init_schema(conn)
        row = conn.execute("SELECT id FROM projects WHERE name = ?", (project,)).fetchone()
        if not row:
            return {"status": "ok", "project": project, "memories": []}
        clauses = ["m.project_id = ?"]
        params: list = [int(row["id"])]
        if query:
            clauses.append("LOWER(m.text) LIKE ?")
            params.append(f"%{query.lower()}%")
        if memory_type:
            clauses.append("m.type = ?")
            params.append(memory_type)
        if pramana:
            clauses.append("m.pramana = ?")
            params.append(pramana)
        if status:
            clauses.append("m.status = ?")
            params.append(status)
        params.append(max(1, min(int(limit), 500)))
        rows = []
        for item in conn.execute(
                f"""
                SELECT m.id, m.type, m.pramana, m.text, m.confidence, m.priority, m.status,
                       m.created_at, m.updated_at,
                       mp.source_path AS provenance_source_path,
                       mp.source_hash AS provenance_source_hash,
                       mp.command AS provenance_command,
                       mp.timestamp AS provenance_timestamp,
                       mp.verification_status AS provenance_verification_status,
                       mp.metadata_json AS provenance_metadata_json
                FROM memories m
                LEFT JOIN memory_provenance mp ON mp.memory_id = m.id
                WHERE {" AND ".join(clauses)}
                ORDER BY m.status = 'pinned' DESC, m.priority DESC, m.updated_at DESC, m.id DESC
                LIMIT ?
                """,
                params,
            ):
            memory = dict(item)
            attach_memory_provenance(memory)
            rows.append(memory)
        return {"status": "ok", "project": project, "memories": rows}
    finally:
        conn.close()


def _relative_source_path(value: str) -> str:
    normalized = str(value or "").replace("\\", "/").strip("/")
    parts = [part for part in normalized.split("/") if part and part != "."]
    if any(part == ".." for part in parts):
        raise ValueError("file tree requires a relative path that cannot traverse outside the project")
    return "/".join(parts)


def read_file_tree(
    db_path: str | Path,
    project: str,
    prefix: str = "",
    query: str = "",
    limit: int = MAX_TREE_ITEMS,
) -> dict:
    conn = _open_db(db_path)
    try:
        init_schema(conn)
        row = conn.execute("SELECT id FROM projects WHERE name = ?", (project,)).fetchone()
        if not row:
            return {"status": "ok", "project": project, "prefix": "", "entries": [], "total_files": 0, "truncated": False}
        project_id = int(row["id"])
        safe_prefix = _relative_source_path(prefix)
        normalized_query = str(query or "").strip().lower()
        item_limit = max(1, min(int(limit), MAX_TREE_ITEMS))
        total_files = int(conn.execute(
            "SELECT COUNT(*) AS count FROM sources WHERE project_id = ? AND kind = 'file'",
            (project_id,),
        ).fetchone()["count"])
        if normalized_query:
            escaped_query = normalized_query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            matched_files = int(conn.execute(
                """
                SELECT COUNT(*) AS count
                FROM sources
                WHERE project_id = ? AND kind = 'file' AND LOWER(title) LIKE ? ESCAPE '\\'
                """,
                (project_id, f"%{escaped_query}%"),
            ).fetchone()["count"])
            rows = conn.execute(
                """
                SELECT title, metadata_json, updated_at
                FROM sources
                WHERE project_id = ? AND kind = 'file' AND LOWER(title) LIKE ? ESCAPE '\\'
                ORDER BY LOWER(title), title
                LIMIT ?
                """,
                (project_id, f"%{escaped_query}%", item_limit + 1),
            ).fetchall()
            matches = []
            for source in rows[:item_limit]:
                relative_path = _relative_source_path(source["title"])
                try:
                    metadata = json.loads(source["metadata_json"] or "{}")
                except json.JSONDecodeError:
                    metadata = {}
                matches.append(
                    {
                        "kind": "file",
                        "name": relative_path.rsplit("/", 1)[-1],
                        "relative_path": relative_path,
                        "size": int(metadata.get("size") or 0),
                        "updated_at": source["updated_at"],
                    }
                )
            return {
                "status": "ok",
                "project": project,
                "prefix": safe_prefix,
                "query": normalized_query,
                "entries": matches,
                "total_files": total_files,
                "matched_files": matched_files,
                "truncated": matched_files > item_limit,
            }

        prefix_marker = f"{safe_prefix}/" if safe_prefix else ""
        escaped_prefix = prefix_marker.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like_pattern = f"{escaped_prefix}%"
        remainder_start = len(prefix_marker) + 1
        descendants = int(conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM sources
            WHERE project_id = ? AND kind = 'file' AND title LIKE ? ESCAPE '\\'
            """,
            (project_id, like_pattern),
        ).fetchone()["count"])
        directory_rows = conn.execute(
            """
            SELECT substr(remainder, 1, instr(remainder, '/') - 1) AS name, COUNT(*) AS count
            FROM (
                SELECT substr(title, ?) AS remainder
                FROM sources
                WHERE project_id = ? AND kind = 'file' AND title LIKE ? ESCAPE '\\'
            )
            WHERE instr(remainder, '/') > 0
            GROUP BY name
            ORDER BY LOWER(name), name
            LIMIT ?
            """,
            (remainder_start, project_id, like_pattern, item_limit + 1),
        ).fetchall()
        directories = [
            {
                "kind": "directory",
                "name": str(source["name"]),
                "relative_path": f"{prefix_marker}{source['name']}" if prefix_marker else str(source["name"]),
                "count": int(source["count"]),
            }
            for source in directory_rows
        ]
        remaining_limit = max(0, item_limit + 1 - len(directories))
        file_rows = conn.execute(
            """
            SELECT title, metadata_json, updated_at
            FROM sources
            WHERE project_id = ? AND kind = 'file' AND title LIKE ? ESCAPE '\\'
              AND instr(substr(title, ?), '/') = 0
            ORDER BY LOWER(title), title
            LIMIT ?
            """,
            (project_id, like_pattern, remainder_start, remaining_limit),
        ).fetchall()
        files = []
        for source in file_rows:
            relative_path = _relative_source_path(source["title"])
            remainder = relative_path[len(prefix_marker):]
            try:
                metadata = json.loads(source["metadata_json"] or "{}")
            except json.JSONDecodeError:
                metadata = {}
            files.append(
                {
                    "kind": "file",
                    "name": remainder,
                    "relative_path": relative_path,
                    "size": int(metadata.get("size") or 0),
                    "updated_at": source["updated_at"],
                }
            )
        entries = [*directories, *files]
        return {
            "status": "ok",
            "project": project,
            "prefix": safe_prefix,
            "entries": entries[:item_limit],
            "total_files": total_files,
            "descendant_files": descendants,
            "truncated": len(entries) > item_limit,
        }
    finally:
        conn.close()


def read_file_preview(db_path: str | Path, project: str, relative_path: str) -> dict:
    conn = _open_db(db_path)
    try:
        init_schema(conn)
        safe_path = _relative_source_path(relative_path)
        row = conn.execute(
            """
            SELECT s.id, s.title, s.hash, s.metadata_json, s.updated_at
            FROM sources s
            JOIN projects p ON p.id = s.project_id
            WHERE p.name = ? AND s.kind = 'file' AND s.title = ?
            """,
            (project, safe_path),
        ).fetchone()
        if not row:
            return {"status": "ok", "project": project, "file": None}
        chunks = conn.execute(
            "SELECT text FROM chunks WHERE source_id = ? ORDER BY ordinal",
            (int(row["id"]),),
        ).fetchall()
        content = "\n\n".join(str(item["text"]) for item in chunks)
        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except json.JSONDecodeError:
            metadata = {}
        return {
            "status": "ok",
            "project": project,
            "file": {
                "relative_path": safe_path,
                "name": safe_path.rsplit("/", 1)[-1],
                "size": int(metadata.get("size") or 0),
                "sha256": row["hash"],
                "updated_at": row["updated_at"],
                "content": content[:MAX_FILE_PREVIEW_CHARS],
                "preview_truncated": len(content) > MAX_FILE_PREVIEW_CHARS,
            },
        }
    finally:
        conn.close()


def publish_readiness(tool_root: Path) -> dict:
    tool_root = tool_root.resolve()
    required_files = [
        "README.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "GITHUB_PUBLISH_CHECKLIST.md",
        "pyproject.toml",
        "package-lock.json",
        ".github/workflows/ci.yml",
        ".gitignore",
    ]
    checks = [{"name": name, "ok": (tool_root / name).exists()} for name in required_files]
    license_exists = any((tool_root / name).exists() for name in ("LICENSE", "LICENSE.md", "COPYING"))
    checks.append({"name": "LICENSE", "ok": license_exists, "note": "MIT license present." if license_exists else "Choose and add a real license before public release."})

    git_ok = False
    git_clean = False
    git_note = "Not initialized as a git repository."
    try:
        git_executable = next((str(path) for path in trusted_git_candidates()), None)
        if not git_executable:
            raise FileNotFoundError("Git was not found in a trusted installation directory")
        result = subprocess.run(
            [git_executable, "-C", str(tool_root), "rev-parse", "--is-inside-work-tree"],
            text=True,
            capture_output=True,
            timeout=5,
        )
        git_ok = result.returncode == 0 and result.stdout.strip() == "true"
        if git_ok:
            status = subprocess.run([git_executable, "-C", str(tool_root), "status", "--short"], text=True, capture_output=True, timeout=5)
            git_clean = status.returncode == 0 and not status.stdout.strip()
            git_note = "Repository detected."
    except Exception as exc:
        git_note = f"Git check failed: {exc}"

    checks.append({"name": "git repository", "ok": git_ok, "note": git_note})
    checks.append(
        {
            "name": "clean working tree",
            "ok": git_ok and git_clean,
            "note": "All release files are committed." if git_clean else "Commit or intentionally remove outstanding changes before publishing.",
        }
    )
    ready_count = sum(1 for item in checks if item["ok"])
    return {
        "status": "ok",
        "tool_root": str(tool_root),
        "ready": ready_count == len(checks),
        "checks": checks,
        "commands": [
            "npm audit --audit-level=high",
            "npm run build",
            "npm run build:launch",
            "python scripts/privacy_scan.py",
            "python -m unittest discover -s tests -v",
            "python -m compileall -q rta_brain tests scripts",
            "pip install -e . --dry-run --no-deps",
            "git init",
            "git status --short",
            "git add -- <reviewed release files only>",
            "git commit -m \"feat: launch rta-smriti brain\"",
        ],
    }


def checkpoint_status_snapshot(conn: sqlite3.Connection, db_path: Path, project: str) -> dict:
    """Return checkpoint and lifecycle state without a repository integrity walk."""
    checkpoint = latest_checkpoint(conn, project)
    lifecycle = continuity_status(db_path, project, include_binding_diagnostics=False)
    reasons: list[str] = ["project_integrity_not_checked"]
    if checkpoint is None:
        reasons.append("no_structured_checkpoint")
    elif checkpoint.get("source") == "continuity-daemon":
        project_row = conn.execute("SELECT id FROM projects WHERE name = ?", (project,)).fetchone()
        truncated = (
            conn.execute(
                "SELECT 1 FROM session_events WHERE project_id = ? AND event_type = 'history_truncated' LIMIT 1",
                (int(project_row["id"]),),
            ).fetchone()
            if project_row else None
        )
        if truncated:
            reasons.append("continuity_history_truncated")
    if lifecycle.get("state") != "running":
        reasons.append("continuity_not_running")
    if int(lifecycle.get("sessions_pending") or 0) > 0:
        reasons.append("continuity_capture_backlog")
    if lifecycle.get("has_error") or lifecycle.get("last_error") or int(lifecycle.get("consecutive_errors") or 0) > 0:
        reasons.append("continuity_capture_errors")
    return {
        "status": "ok",
        "project": project,
        "database_healthy": None,
        "continuation_ready": None,
        "operational_state": "integrity_not_checked",
        "reasons": reasons,
        "latest_checkpoint": checkpoint,
        "event_count": None,
        "work_state_conflicts": None,
        "integrity": {"status": "not_checked", "operationally_ready": None},
        "temporal_truth": {"status": "not_checked"},
        "continuity": lifecycle,
    }


def dashboard_bootstrap_snapshot(config: ConsoleConfig) -> dict:
    """Return the first meaningful dashboard payload without deep project checks."""
    return {
        "status": "ok",
        "brain_dir": str(config.brain_dir.expanduser().resolve()),
        "default_db": str(config.default_db) if config.default_db else None,
        "default_project": config.default_project,
        "shell": runtime_shell(),
        "cli_command": shell_cli_command(config.tool_root),
        "projects": scan_brain_registry(config.brain_dir),
        "project_scan_state": "checking",
        "publish": None,
    }

def dashboard_snapshot(config: ConsoleConfig) -> dict:
    return {
        "status": "ok",
        "brain_dir": str(config.brain_dir.expanduser().resolve()),
        "default_db": str(config.default_db) if config.default_db else None,
        "default_project": config.default_project,
        "shell": runtime_shell(),
        "cli_command": shell_cli_command(config.tool_root),
        "projects": scan_brain_databases(config.brain_dir),
        "publish": publish_readiness(config.tool_root),
    }


def _read_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length") or 0)
    if length <= 0:
        return {}
    if length > MAX_REQUEST_BYTES:
        raise ValueError("request body exceeds the 1 MB limit")
    raw = handler.rfile.read(length).decode("utf-8")
    payload = json.loads(raw) if raw.strip() else {}
    if not isinstance(payload, dict):
        raise ValueError("JSON request body must be an object")
    return payload


def _query(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    parsed = urlparse(handler.path)
    values = parse_qs(parsed.query)
    return {key: value[-1] for key, value in values.items() if value}


def resolve_static_asset(static_dir: Path, requested_path: str) -> Path | None:
    static_root = static_dir.resolve()
    asset = "index.html" if requested_path in ("", "/") else requested_path.lstrip("/")
    candidate = (static_root / asset).resolve()
    try:
        candidate.relative_to(static_root)
    except ValueError:
        return None
    return candidate


def is_local_origin(handler: BaseHTTPRequestHandler) -> bool:
    origin = handler.headers.get("Origin") or handler.headers.get("Referer")
    if not origin:
        return True
    expected = f"http://{handler.headers.get('Host') or ''}"
    if origin.startswith("http://") or origin.startswith("https://"):
        parsed = urlparse(origin)
        return f"{parsed.scheme}://{parsed.netloc}" == expected
    return origin.startswith(expected + "/")


def is_local_request(handler: BaseHTTPRequestHandler) -> bool:
    hostname = urlparse(f"//{handler.headers.get('Host') or ''}").hostname
    if hostname not in {"127.0.0.1", "localhost", "::1"}:
        return False
    client = getattr(handler, "client_address", ("127.0.0.1", 0))[0]
    try:
        return ipaddress.ip_address(client).is_loopback
    except ValueError:
        return client == "localhost"


def _request_capability(handler: BaseHTTPRequestHandler) -> str:
    return handler.headers.get("X-Rta-Smriti-Token") or ""


def is_authorized_request(handler: BaseHTTPRequestHandler, config: ConsoleConfig) -> bool:
    supplied = _request_capability(handler)
    return bool(supplied) and hmac.compare_digest(supplied, config.capability_token)


def make_handler(config: ConsoleConfig):
    static_dir = Path(__file__).resolve().parent / "static"

    class ConsoleHandler(BaseHTTPRequestHandler):
        server_version = "RtaSmritiConsole/0.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, format, *args):  # noqa: A003
            sys.stderr.write("[rta-console] " + (format % args) + "\n")

        def _security_headers(self) -> None:
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")

        def _json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _file(self, path: Path) -> None:
            resolved = path.resolve()
            if not resolved.exists() or not resolved.is_file():
                self.send_error(404)
                return
            body = resolved.read_bytes()
            ctype = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "public, max-age=31536000, immutable" if "assets" in resolved.parts else "no-store")
            self._security_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            try:
                if not is_local_request(self):
                    self._json({"status": "error", "error": {"type": "Forbidden", "message": "non-loopback request rejected"}}, status=403)
                    return
                if parsed.path.startswith("/api/") and (not is_authorized_request(self, config) or not is_local_origin(self)):
                    self._json({"status": "error", "error": {"type": "Forbidden", "message": "valid local capability required"}}, status=403)
                    return
                if parsed.path == "/api/runtime-health":
                    self._json({"status": "ok", "instance_id": config.instance_id})
                    return
                if parsed.path == "/api/bootstrap":
                    self._json(dashboard_bootstrap_snapshot(config))
                    return
                if parsed.path == "/api/health":
                    self._json(dashboard_snapshot(config))
                    return
                if parsed.path == "/api/projects":
                    self._json({"status": "ok", "projects": scan_brain_databases(config.brain_dir)})
                    return
                if parsed.path == "/api/memories":
                    q = _query(self)
                    self._json(
                        read_memories(
                            resolve_brain_db(config, q["db_path"]),
                            q["project"],
                            query=q.get("query", ""),
                            memory_type=q.get("type", ""),
                            pramana=q.get("pramana", ""),
                            status=q.get("status", ""),
                            limit=int(q.get("limit", "100")),
                        )
                    )
                    return
                if parsed.path == "/api/files":
                    q = _query(self)
                    self._json(
                        read_file_tree(
                            resolve_brain_db(config, q["db_path"]),
                            q["project"],
                            prefix=q.get("prefix", ""),
                            query=q.get("query", ""),
                            limit=int(q.get("limit", str(MAX_TREE_ITEMS))),
                        )
                    )
                    return
                if parsed.path == "/api/file-preview":
                    q = _query(self)
                    self._json(
                        read_file_preview(
                            resolve_brain_db(config, q["db_path"]),
                            q["project"],
                            q["path"],
                        )
                    )
                    return
                if parsed.path == "/api/graph":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(graph(conn, project=q["project"], limit=int(q.get("limit", "120"))))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/stale-check":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(stale_check(conn, project=q["project"]))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/settings":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        settings = get_project_settings(conn, q["project"])
                        root_row = conn.execute(
                            "SELECT root_path FROM projects WHERE name = ?", (q["project"],)
                        ).fetchone()
                        self._json({
                            "status": "ok", "settings": settings,
                            "parser_capabilities": ParserRegistry(
                                lsp_command=settings["lsp_command"],
                                lsp_auto_discovery=bool(settings["lsp_auto_discovery"]),
                                lsp_discovery_excluded_root=Path(root_row["root_path"]) if root_row and root_row["root_path"] else None,
                            ).capabilities(),
                        })
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/watcher":
                    q = _query(self)
                    db_path = resolve_brain_db(config, q["db_path"])
                    self._json(watcher_status(db_path, q["project"]))
                    return
                if parsed.path == "/api/continuity":
                    q = _query(self)
                    db_path = resolve_brain_db(config, q["db_path"])
                    self._json(continuity_status(db_path, q["project"], include_binding_diagnostics=False))
                    return
                if parsed.path == "/api/checkpoint":
                    q = _query(self)
                    db_path = resolve_brain_db(config, q["db_path"])
                    conn = _open_db(db_path)
                    try:
                        self._json({
                            "status": "ok",
                            "project": q["project"],
                            "checkpoint": latest_checkpoint(conn, q["project"]),
                            "readiness": (
                                checkpoint_status_snapshot(conn, db_path, q["project"])
                                if q.get("mode") == "summary"
                                else operational_readiness(
                                    conn, q["project"], lifecycle=continuity_status(db_path, q["project"], include_binding_diagnostics=False),
                                    include_event_count=False,
                                )
                            ),
                        })
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/continuation-prompt":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json({"status": "ok", "project": q["project"], "prompt": build_continuation_prompt(conn, q["project"])})
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/mcp-config":
                    q = _query(self)
                    db_path = resolve_brain_db(config, q["db_path"])
                    self._json(mcp_config_payload(str(db_path), q["project"], q.get("name", "rta-smriti"), config.tool_root))
                    return
                if parsed.path == "/api/graph-query":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(graph_query(
                            conn, project=q["project"], query_type=q.get("type", "impact"),
                            target=q["target"], depth=int(q.get("depth", "2")), limit=int(q.get("limit", "100")),
                        ))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/retrieval-diagnostics":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(retrieval_diagnostics(
                            conn, q["query"], project=q["project"], limit=int(q.get("limit", "8")),
                        ))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/workspaces":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(get_workspace(conn, q["workspace"]) if q.get("workspace") else list_workspaces(conn))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/integrity":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(integrity_diagnostics(conn, project=q["project"]))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/workspace-health":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(workspace_health(conn, q["workspace"]))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/workspace-search":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(search_workspace(
                            conn, workspace=q["workspace"], query=q["query"],
                            limit_per_project=int(q.get("limit", "4")),
                        ))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/governance":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        policies = list_policies(
                            conn,
                            project=q["project"],
                            include_retired=q.get("include_retired", "").lower() in {"1", "true", "yes"},
                        )
                        receipts = list_receipts(
                            conn,
                            project=q["project"],
                            limit=int(q.get("limit", "50")),
                        )
                        self._json({
                            "status": "ok",
                            "project": q["project"],
                            "policies": policies["policies"],
                            "receipts": receipts["receipts"],
                        })
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/truth":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        mode = q.get("mode", "overview")
                        if mode == "overview":
                            result = truth_overview(
                                conn, project=q["project"],
                                limit=int(q.get("limit", "100")),
                            )
                        elif mode == "current":
                            result = truth_current(
                                conn, project=q["project"], claim_id=q["claim_id"],
                                valid_at=q.get("valid_at"),
                            )
                        elif mode == "history":
                            result = truth_history(
                                conn, project=q["project"], claim_id=q["claim_id"],
                                limit=int(q.get("limit", "100")),
                            )
                        elif mode == "explain":
                            result = truth_explain(
                                conn, project=q["project"], claim_id=q["claim_id"],
                                valid_at=q.get("valid_at"),
                            )
                        elif mode == "as-of":
                            result = truth_as_of(
                                conn, project=q["project"], claim_id=q["claim_id"],
                                valid_at=q["valid_at"],
                                recorded_sequence=int(q["recorded_sequence"]),
                            )
                        elif mode == "diff":
                            result = truth_diff(
                                conn, project=q["project"],
                                from_sequence=int(q["from_sequence"]),
                                to_sequence=int(q["to_sequence"]),
                                valid_at=q["valid_at"],
                                limit=int(q.get("limit", "100")),
                            )
                        elif mode == "at-commit":
                            result = truth_at_commit(
                                conn, project=q["project"], claim_id=q["claim_id"],
                                commit=q["commit"], valid_at=q["valid_at"],
                            )
                        elif mode == "validator-history":
                            result = validator_history(
                                conn, project=q["project"],
                                validator_id=q["validator_id"],
                                limit=int(q.get("limit", "100")),
                            )
                        elif mode == "ledger":
                            result = verify_ledger(conn, project=q["project"])
                        else:
                            raise ValueError(f"unsupported truth query mode: {mode}")
                        self._json(redact_truth_for_operator(result))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/capture":
                    q = _query(self)
                    database = resolve_brain_db(config, q["db_path"])
                    conn = _open_db(database)
                    try:
                        project = q["project"]
                        mode = str(q.get("mode", "overview")).strip().lower()
                        root = _project_root(conn, project)
                        if mode == "overview":
                            result = capture_status_report(
                                conn, database=database, project=project,
                            )
                        elif mode == "sources":
                            result = list_capture_sources(conn, project=project)
                        elif mode == "policies":
                            result = list_capture_policies(
                                conn,
                                project=project,
                                include_retired=q.get("include_retired", "").lower()
                                in {"1", "true", "yes"},
                            )
                        elif mode in {"timeline", "replay"}:
                            replay_mode = (
                                "chronological" if mode == "timeline"
                                else str(q.get("replay_mode", "chronological"))
                            )
                            result = capture_replay(
                                conn,
                                project=project,
                                active_root=root,
                                mode=replay_mode,
                                after_sequence=int(q.get("after_sequence", "0")),
                                limit=int(q.get("limit", "100")),
                                privacy_ceiling=q.get("privacy_ceiling", "internal"),
                            )
                        elif mode == "diagnostics":
                            result = capture_diagnostics(
                                conn,
                                database=database,
                                project=project,
                                active_root=root,
                            )
                        else:
                            raise ValueError("capture mode must be overview, sources, policies, timeline, replay, or diagnostics")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/cognition":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        self._json(cognition_snapshot(
                            conn,
                            project=q["project"],
                            active_root=_project_root(conn, q["project"]),
                            include_change_impact=q.get("include_change_impact", "true").casefold()
                            not in {"0", "false", "no"},
                        ))
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/multimodal":
                    q = _query(self)
                    conn = _open_db(resolve_brain_db(config, q["db_path"]))
                    try:
                        project = q["project"]
                        mode = str(q.get("mode", "sources")).strip().casefold()
                        if mode == "sources":
                            result = list_multimodal_evidence(
                                conn, project=project, limit=int(q.get("limit", "100"))
                            )
                        elif mode == "derivations":
                            result = list_multimodal_derivations(
                                conn,
                                project=project,
                                source_id=q["source_id"],
                                include_text=q.get("include_text", "false").casefold()
                                in {"1", "true", "yes"},
                                limit=int(q.get("limit", "100")),
                            )
                        elif mode == "verify":
                            result = verify_multimodal_source(
                                conn,
                                project=project,
                                active_root=_project_root(conn, project),
                                source_id=q["source_id"],
                            )
                        elif mode == "export":
                            result = export_multimodal_manifest(
                                conn,
                                project=project,
                                audience=q.get("audience", "local"),
                                limit=int(q.get("limit", "1000")),
                            )
                        else:
                            raise ValueError("multimodal mode must be sources, derivations, verify, or export")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if parsed.path == "/api/publish-readiness":
                    self._json(publish_readiness(config.tool_root))
                    return
                if parsed.path == "/favicon.ico":
                    self.send_response(204)
                    self.end_headers()
                    return
                asset = resolve_static_asset(static_dir, parsed.path)
                if asset is None:
                    self.send_error(404)
                    return
                self._file(asset)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json({"status": "error", "error": {"type": exc.__class__.__name__, "message": str(exc)}}, status=400)
            except Exception as exc:
                self._json({"status": "error", "error": {"type": exc.__class__.__name__, "message": "request could not be completed"}}, status=500)

        def do_POST(self) -> None:
            try:
                if not is_local_request(self) or not is_local_origin(self) or not is_authorized_request(self, config):
                    self._json({"status": "error", "error": {"type": "Forbidden", "message": "valid local capability required"}}, status=403)
                    return
                if (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower() != "application/json":
                    self._json({"status": "error", "error": {"type": "UnsupportedMediaType", "message": "application/json is required"}}, status=415)
                    return
                payload = _read_body(self)
                if self.path == "/api/context-compiler":
                    database = resolve_brain_db(config, payload["db_path"])
                    conn = _open_db(database)
                    try:
                        project = str(payload["project"])
                        action = str(payload["action"])
                        if action == "authorize-and-compile":
                            profile = ensure_context_agent_profile(
                                conn,
                                project=project,
                                profile_id=str(payload["profile_id"]),
                                actor_id="dashboard-operator",
                                max_input_tokens=int(payload["max_input_tokens"]),
                                privacy_ceiling=str(
                                    payload.get("privacy_ceiling", "internal")
                                ),
                            )
                            contract = build_task_contract(
                                project=project,
                                agent_profile_id=str(payload["profile_id"]),
                                objective=str(payload["objective"]),
                                actor_id="dashboard-operator",
                                comparison_modes=list(payload.get("comparison_modes", [])),
                                compiler_mode=str(payload.get("compiler_mode", "balanced")),
                                max_input_tokens=int(payload["max_input_tokens"]),
                                privacy_ceiling=str(
                                    payload.get("privacy_ceiling", "internal")
                                ),
                            )
                            authorized = authorize_context_contract(
                                conn,
                                project=project,
                                agent_profile_version_id=profile[
                                    "agent_profile_version_id"
                                ],
                                contract=contract,
                                actor_id="dashboard-operator",
                            )
                            result = compile_context_for_agent(
                                conn,
                                db_path=database,
                                project=project,
                                active_root=_project_root(conn, project),
                                task_contract_id=authorized["task_contract_id"],
                                principal_id=str(payload["principal_id"]),
                                session_id=str(payload["session_id"]),
                                variant_id=str(payload.get("variant", "primary")),
                            )
                            result["authorization"] = {
                                "task_contract_id": authorized["task_contract_id"],
                                "contract_id": authorized["contract_id"],
                                "agent_profile_version_id": profile[
                                    "agent_profile_version_id"
                                ],
                            }
                        elif action == "explain":
                            result = explain_context_for_agent(
                                conn,
                                db_path=database,
                                project=project,
                                compilation_id=str(payload["compilation_id"]),
                                principal_id=str(payload["principal_id"]),
                                session_id=str(payload["session_id"]),
                            )
                        elif action == "audit":
                            result = audit_context_for_operator(
                                conn,
                                db_path=database,
                                project=project,
                                compilation_id=str(payload["compilation_id"]),
                                operator_id="dashboard-operator",
                                session_id=str(payload["session_id"]),
                            )
                        elif action == "outcome":
                            result = record_context_outcome_for_operator(
                                conn,
                                db_path=database,
                                project=project,
                                compilation_id=str(payload["compilation_id"]),
                                operator_id="dashboard-operator",
                                session_id=str(payload["session_id"]),
                                outcome=dict(payload["outcome"]),
                            )
                        elif action == "revoke":
                            result = revoke_context_compilation_grant(
                                conn,
                                db_path=database,
                                project=project,
                                compilation_id=str(payload["compilation_id"]),
                                operator_id="dashboard-operator",
                                reason=str(payload["reason"]),
                            )
                        else:
                            raise ValueError("unknown context compiler action")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/context-pack":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(
                            {
                                "status": "ok",
                                "pack": build_context_pack(
                                    conn,
                                    payload["task"],
                                    project=payload["project"],
                                    limit=int(payload.get("limit", 8)),
                                    max_tokens=int(payload.get("max_tokens", 4_000)),
                                ),
                            }
                        )
                    finally:
                        conn.close()
                    return
                if self.path == "/api/search":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(search(conn, payload["query"], project=payload.get("project"), limit=int(payload.get("limit", 8))))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/truth":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        project = str(payload["project"])
                        root = _project_root(conn, project)
                        action = str(payload["action"])
                        common = {
                            "project": project,
                            "active_root": root,
                            "actor_type": "operator",
                            "actor_id": "dashboard-operator",
                            "source": "dashboard",
                        }
                        if action == "assert":
                            result = append_claim(
                                conn, **common,
                                claim_id=payload.get("claim_id"),
                                subject=str(payload["subject"]),
                                predicate=str(payload["predicate"]),
                                value=payload["value"],
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                                valid_from=payload.get("valid_from"),
                                valid_to=payload.get("valid_to"),
                                expires_at=payload.get("expires_at"),
                                epistemic_state=str(payload.get("state", "observed")),
                                state_reason=str(payload.get("reason", "")),
                                authority_class="operator",
                                confidence=float(payload.get("confidence", 1.0)),
                                verification_status=str(payload.get("verification_status", "unverified")),
                                privacy_class=str(payload.get("privacy_class", "internal")),
                            )
                        elif action == "revise":
                            result = revise_claim(
                                conn, **common, claim_id=str(payload["claim_id"]),
                                value=payload["value"], reason=str(payload["reason"]),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                                valid_from=payload.get("valid_from"),
                                valid_to=payload.get("valid_to"),
                            )
                        elif action == "state":
                            result = change_claim_state(
                                conn, **common, claim_id=str(payload["claim_id"]),
                                new_state=str(payload["state"]), reason=str(payload["reason"]),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                            )
                        elif action == "relate":
                            result = relate_claims(
                                conn, **common, relation_id=payload.get("relation_id"),
                                from_claim_id=str(payload["from_claim_id"]),
                                relation_type=str(payload["relation_type"]),
                                to_claim_id=str(payload["to_claim_id"]),
                                confidence=float(payload.get("confidence", 0.7)),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                            )
                        elif action == "evidence":
                            provenance = payload.get("provenance", {})
                            if not isinstance(provenance, dict):
                                raise ValueError("truth evidence provenance must be an object")
                            result = attach_evidence(
                                conn, **common, claim_id=str(payload["claim_id"]),
                                evidence_id=str(payload["evidence_id"]),
                                source_identifier=str(payload["source_identifier"]),
                                source_hash=payload.get("source_hash"),
                                method=str(payload["method"]),
                                polarity=str(payload["polarity"]),
                                authority_class="operator",
                                confidence=float(payload.get("confidence", 1.0)),
                                uncertainty=str(payload.get("uncertainty", "")),
                                provenance=provenance,
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                                verification_status=str(payload.get("verification_status", "unverified")),
                                privacy_class=str(payload.get("privacy_class", "internal")),
                            )
                        elif action == "abstain":
                            result = record_abstention(
                                conn, **common, abstention_id=payload.get("abstention_id"),
                                query_scope=str(payload["query_scope"]),
                                missing_evidence=list(payload.get("missing_evidence", [])),
                                unresolved_conflicts=list(payload.get("unresolved_conflicts", [])),
                                minimum_revalidation_action=str(payload["minimum_revalidation_action"]),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                            )
                        elif action == "validator-add":
                            validator_type = str(payload["validator_type"])
                            if validator_type == "command_exit":
                                raise ValueError("command validators must be defined and run from the owner CLI")
                            config_payload = payload.get("config", {})
                            if not isinstance(config_payload, dict):
                                raise ValueError("validator config must be an object")
                            result = define_validator(
                                conn, **common, validator_id=str(payload["validator_id"]),
                                validator_type=validator_type, claim_id=str(payload["claim_id"]),
                                config=config_payload, failure_effect=str(payload["failure_effect"]),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                            )
                        elif action == "validator-run":
                            result = run_validator(
                                conn, **common, validator_id=str(payload["validator_id"]),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                                allow_command=False, trusted_executables=(),
                            )
                        elif action == "anchor":
                            result = observe_repository_anchor(
                                conn, **common, anchor_id=str(payload["anchor_id"]),
                                idempotency_key=str(payload["idempotency_key"]),
                                expected_stream_version=int(payload["expected_version"]),
                            )
                        elif action == "rebuild":
                            result = rebuild_projections(
                                conn, project=project, active_root=root,
                            )
                        else:
                            raise ValueError(f"unsupported truth action: {action}")
                        self._json(redact_truth_for_operator(result))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/memory":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(
                            remember(
                                conn,
                                payload["text"],
                                project=payload["project"],
                                memory_type=payload.get("type", "fact"),
                                pramana=payload.get("pramana", "smriti"),
                                confidence=float(payload.get("confidence", 0.75)),
                                priority=int(payload.get("priority", 5)),
                                provenance=payload.get("provenance"),
                            )
                        )
                    finally:
                        conn.close()
                    return
                if self.path == "/api/checkpoint":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(
                            save_checkpoint(
                                conn,
                                project=payload["project"],
                                objective=payload["objective"],
                                verified_evidence=payload.get("verified_evidence", ""),
                                remaining_gaps=payload.get("remaining_gaps", ""),
                                next_action=payload.get("next_action", ""),
                                prohibited_repetition=payload.get("prohibited_repetition", ""),
                                expected_version=payload.get("expected_version"),
                            )
                        )
                    finally:
                        conn.close()
                    return
                if self.path == "/api/reflect":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(reflect(conn, project=payload["project"]))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/ingest-repo":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        row = conn.execute("SELECT root_path FROM projects WHERE name = ?", (payload["project"],)).fetchone()
                        if not row or not row["root_path"]:
                            raise ValueError("project has no repository path to refresh")
                        self._json(ingest_repo(conn, Path(row["root_path"]), project=payload["project"], force=bool(payload.get("force", False))))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/settings":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        settings = update_project_settings(conn, payload["project"], payload.get("settings", {}))
                        root_row = conn.execute(
                            "SELECT root_path FROM projects WHERE name = ?", (payload["project"],)
                        ).fetchone()
                        self._json({
                            "status": "ok", "settings": settings,
                            "parser_capabilities": ParserRegistry(
                                lsp_command=settings["lsp_command"],
                                lsp_auto_discovery=bool(settings["lsp_auto_discovery"]),
                                lsp_discovery_excluded_root=Path(root_row["root_path"]) if root_row and root_row["root_path"] else None,
                            ).capabilities(),
                        })
                    finally:
                        conn.close()
                    return
                if self.path == "/api/watcher":
                    db_path = resolve_brain_db(config, payload["db_path"])
                    project = str(payload["project"])
                    action = str(payload.get("action", "status"))
                    if action == "stop":
                        self._json(stop_watcher(db_path, project))
                        return
                    if action != "start":
                        raise ValueError("watcher action must be start or stop")
                    conn = _open_db(db_path)
                    try:
                        row = conn.execute(
                            "SELECT root_path FROM projects WHERE name = ?", (project,)
                        ).fetchone()
                    finally:
                        conn.close()
                    if not row or not row["root_path"]:
                        raise ValueError("project has no repository path to watch")
                    self._json(
                        start_watcher(
                            db_path,
                            Path(row["root_path"]),
                            project,
                            interval_seconds=float(payload.get("interval", 5.0)),
                        )
                    )
                    return
                if self.path == "/api/continuity":
                    db_path = resolve_brain_db(config, payload["db_path"])
                    project = str(payload["project"])
                    action = str(payload.get("action", "status"))
                    if action == "stop":
                        self._json(stop_continuity(db_path, project))
                        return
                    if action != "start":
                        raise ValueError("continuity action must be start or stop")
                    conn = _open_db(db_path)
                    try:
                        row = conn.execute("SELECT root_path FROM projects WHERE name = ?", (project,)).fetchone()
                    finally:
                        conn.close()
                    if not row or not row["root_path"]:
                        raise ValueError("project has no canonical root for continuity capture")
                    self._json(
                        start_continuity(
                            db_path,
                            Path(row["root_path"]),
                            project,
                            Path(payload.get("sessions_root") or (Path.home() / ".codex" / "sessions")),
                            interval_seconds=float(payload.get("interval", 2.0)),
                            inactivity_seconds=float(payload.get("inactivity", 900.0)),
                        )
                    )
                    return
                if self.path == "/api/capture":
                    database = resolve_brain_db(config, payload["db_path"])
                    project = str(payload["project"])
                    action = str(payload.get("action", "status")).strip().lower()
                    if action == "daemon-start":
                        conn = _open_db(database)
                        try:
                            _project_root(conn, project)
                        finally:
                            conn.close()
                        self._json(start_capture(
                            database,
                            interval_seconds=float(payload.get("interval", 1.0)),
                            batch_size=int(payload.get("batch_size", 100)),
                        ))
                        return
                    if action == "daemon-stop":
                        conn = _open_db(database)
                        try:
                            _project_root(conn, project)
                        finally:
                            conn.close()
                        self._json(stop_capture(
                            database, timeout=float(payload.get("timeout", 10.0)),
                        ))
                        return
                    conn = _open_db(database)
                    try:
                        root = _project_root(conn, project)
                        if action == "policy-preview":
                            policy = _capture_policy_from_payload(payload)
                            result = {
                                "status": "ok",
                                "policy": policy.as_dict(),
                                "policy_digest": policy.digest,
                                "writes_state": False,
                            }
                        elif action == "policy-register":
                            policy = _capture_policy_from_payload(payload)
                            result = register_policy(
                                conn,
                                project=project,
                                active_root=root,
                                policy_id=payload.get("policy_id", policy.profile),
                                policy_version=int(payload.get("policy_version", 1)),
                                policy=policy,
                            )
                        elif action == "policy-retire":
                            result = retire_capture_policy(
                                conn,
                                project=project,
                                active_root=root,
                                policy_digest=payload["policy_digest"],
                            )
                        elif action == "source-state":
                            result = set_capture_source_state(
                                conn,
                                project=project,
                                active_root=root,
                                source_id=payload["source_id"],
                                state=payload["state"],
                            )
                        elif action == "bind-session":
                            result = bind_session(
                                conn,
                                database=database,
                                project=project,
                                active_root=root,
                                source_id=payload["source_id"],
                                external_session_id=payload["external_session_id"],
                                cursor_kind=payload.get("cursor_kind", "sequence"),
                                start_cursor=str(payload.get("start_cursor", "0")),
                                operator_id="dashboard-operator",
                            )
                        elif action == "close-session":
                            result = close_session_binding(
                                conn,
                                database=database,
                                project=project,
                                active_root=root,
                                binding_id=payload["binding_id"],
                                operator_id="dashboard-operator",
                            )
                        elif action in {"retention-preview", "retention-confirm"}:
                            result = control_capture_retention(
                                conn,
                                project=project,
                                active_root=root,
                                policy_digest=payload["policy_digest"],
                                run_id=payload["run_id"],
                                actor_id="dashboard-operator",
                                batch_size=int(payload.get("batch_size", 100)),
                                confirm=action == "retention-confirm",
                                confirmation_token=payload.get("confirmation_token"),
                            )
                        elif action in {"redaction-preview", "export"}:
                            result = export_capture_events(
                                conn,
                                project=project,
                                active_root=root,
                                after_sequence=int(payload.get("after_sequence", 0)),
                                limit=int(payload.get("limit", 100)),
                                privacy_ceiling=payload.get("privacy_ceiling", "internal"),
                                max_bytes=int(payload.get("max_bytes", 2_000_000)),
                            )
                            if action == "redaction-preview":
                                result = {**result, "operation": "redaction-preview", "writes_state": False}
                        elif action in {"deletion-preview", "deletion-confirm"}:
                            result = delete_capture_content(
                                conn,
                                project=project,
                                active_root=root,
                                scope=payload["scope"],
                                scope_token=payload["scope_token"],
                                reason_class=payload.get("reason_class", "operator-request"),
                                actor_id="dashboard-operator",
                                policy_digest=payload["policy_digest"],
                                confirm=action == "deletion-confirm",
                                confirmation_token=payload.get("confirmation_token"),
                                secure_compact=payload.get("secure_compact", False),
                            )
                        else:
                            raise ValueError(
                                "capture action must be policy-preview, policy-register, policy-retire, "
                                "source-state, bind-session, close-session, retention-preview, "
                                "retention-confirm, redaction-preview, "
                                "deletion-preview, deletion-confirm, export, daemon-start, or daemon-stop"
                            )
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/cognition":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        project = str(payload["project"])
                        root = _project_root(conn, project)
                        action = str(payload.get("action", "")).strip().casefold()
                        if action == "observe":
                            result = record_observation(
                                conn,
                                project=project,
                                active_root=root,
                                observation_id=payload["observation_id"],
                                subsystem=payload["subsystem"],
                                entity_key=payload["entity_key"],
                                expected_state=payload.get("expected_state"),
                                observed_state=payload["observed_state"],
                                status=payload["status"],
                                source_identifier=payload["source_identifier"],
                                source_hash=payload.get("source_hash"),
                                evidence=payload.get("evidence"),
                                observed_at=payload.get("observed_at"),
                                valid_until=payload.get("valid_until"),
                                privacy_class=payload.get("privacy_class", "internal"),
                                sharing_policy=payload.get("sharing_policy", "local-only"),
                            )
                        elif action == "reconcile":
                            result = reconcile_observation(
                                conn,
                                project=project,
                                active_root=root,
                                observation_id=payload["observation_id"],
                                receipt_id=payload["receipt_id"],
                                action="set_status",
                                outcome=payload["status"],
                                reason=payload["reason"],
                                actor_type="operator",
                                actor_id="dashboard-operator",
                                evidence=payload.get("evidence"),
                            )
                        else:
                            raise ValueError("cognition action must be observe or reconcile")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/multimodal":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        project = str(payload["project"])
                        root = _project_root(conn, project)
                        action = str(payload.get("action", "")).strip().casefold()
                        if action == "add":
                            result = ingest_media(
                                conn,
                                project=project,
                                active_root=root,
                                path=payload["path"],
                                privacy_class=payload.get("privacy_class", "internal"),
                                sharing_policy=payload.get("sharing_policy", "local-only"),
                                metadata=payload.get("metadata"),
                                maximum_bytes=int(payload.get("maximum_bytes", 32 * 1024 * 1024)),
                            )
                        elif action == "derive":
                            result = add_derivation(
                                conn,
                                project=project,
                                source_id=payload["source_id"],
                                method=payload["method"],
                                text=payload["text"],
                                confidence=float(payload["confidence"]),
                                verification_status=payload.get("verification_status", "unverified"),
                                tool_identity=payload.get("tool_identity", "dashboard-operator"),
                                model_identity=payload.get("model_identity"),
                                derivation_id=payload.get("derivation_id"),
                                metadata=payload.get("metadata"),
                                actor_type="operator",
                                actor_id="dashboard-operator",
                            )
                        elif action == "redact":
                            result = redact_derivation(
                                conn,
                                project=project,
                                active_root=root,
                                derivation_id=payload["derivation_id"],
                                reason=payload["reason"],
                                actor_type="operator",
                                actor_id="dashboard-operator",
                            )
                        elif action == "delete":
                            result = delete_media(
                                conn,
                                project=project,
                                active_root=root,
                                source_id=payload["source_id"],
                                reason=payload["reason"],
                                actor_type="operator",
                                actor_id="dashboard-operator",
                            )
                        elif action == "retention":
                            result = set_media_retention(
                                conn,
                                project=project,
                                active_root=root,
                                source_id=payload["source_id"],
                                retain_until=payload["retain_until"],
                                actor_type="operator",
                                actor_id="dashboard-operator",
                            )
                        elif action == "purge":
                            dry_run = payload.get("dry_run", True)
                            if type(dry_run) is not bool:
                                raise ValueError("dry_run must be a boolean")
                            result = purge_expired_media(
                                conn,
                                project=project,
                                active_root=root,
                                actor_type="operator",
                                actor_id="dashboard-operator",
                                now=payload.get("now"),
                                dry_run=dry_run,
                            )
                        else:
                            raise ValueError("multimodal action must be add, derive, redact, delete, retention, or purge")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/preflight":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(preflight(
                            conn,
                            project=payload["project"],
                            action=payload["action"],
                            path=payload.get("path"),
                            completed_checks=payload.get("completed_checks") or [],
                            override_reason=payload.get("override_reason"),
                            actor=payload.get("actor", "operator"),
                            operational_context=(
                                build_operational_context(conn, payload["project"], db_path=resolve_brain_db(config, payload["db_path"]))
                                if bool(payload.get("include_operational_context")) else None
                            ),
                        ))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/governance-policy":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        policy_action = str(payload.get("action", "create")).strip().lower()
                        if policy_action == "retire":
                            result = retire_policy(
                                conn,
                                project=payload["project"],
                                policy_id=int(payload["policy_id"]),
                                reason=payload["reason"],
                            )
                        elif policy_action == "create":
                            result = create_policy(
                                conn,
                                project=payload["project"],
                                kind=payload["kind"],
                                statement=payload["statement"],
                                effect=payload.get("effect", "warn"),
                                action_contains=payload.get("action_contains", ""),
                                path_glob=payload.get("path_glob", ""),
                                required_check=payload.get("required_check", ""),
                                pramana=payload.get("pramana", "smriti"),
                                confidence=float(payload.get("confidence", 0.75)),
                                provenance=payload.get("provenance"),
                                overrideable=bool(payload.get("overrideable", True)),
                                expires_at=payload.get("expires_at"),
                            )
                        else:
                            raise ValueError("governance policy action must be create or retire")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/workspace":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        action = str(payload.get("action", "create")).strip().lower()
                        if action == "create":
                            result = create_workspace(conn, payload["name"], payload.get("description", ""))
                        elif action == "add":
                            result = add_project_to_workspace(
                                conn, workspace=payload["name"], project=payload["project"], role=payload.get("role", "member"),
                                db_path=resolve_brain_db(config, payload["member_db_path"]) if payload.get("member_db_path") else None,
                            )
                        elif action == "remove":
                            result = remove_project_from_workspace(
                                conn, workspace=payload["name"], project=payload["project"],
                                db_path=resolve_brain_db(config, payload["member_db_path"]) if payload.get("member_db_path") else None,
                            )
                        elif action == "delete":
                            result = delete_workspace(conn, payload["name"])
                        else:
                            raise ValueError("workspace action must be create, add, remove, or delete")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/memory-feedback":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(apply_memory_feedback(
                            conn, project=payload["project"], memory_id=int(payload["memory_id"]),
                            outcome=payload["outcome"], evidence=payload.get("evidence", ""),
                        ))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/memory-decay":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        self._json(run_conservative_decay(
                            conn, project=payload["project"],
                            minimum_age_days=int(payload.get("minimum_age_days", 90)), step=float(payload.get("step", 0.03)),
                        ))
                    finally:
                        conn.close()
                    return
                if self.path == "/api/bundle":
                    conn = _open_db(resolve_brain_db(config, payload["db_path"]))
                    try:
                        action = str(payload.get("action", "export")).strip().lower()
                        if action == "export":
                            result = export_bundle(
                                conn, Path(payload["path"]), projects=payload.get("projects"),
                                include=tuple(payload.get("include") or ("memories", "checkpoints", "policies")),
                                redact=bool(payload.get("redact", True)),
                            )
                        elif action == "preview-export":
                            result = export_bundle(
                                conn, Path(payload["path"]), projects=payload.get("projects"),
                                include=tuple(payload.get("include") or ("memories", "checkpoints", "policies")),
                                redact=bool(payload.get("redact", True)), preview=True,
                            )
                        elif action == "preview-import":
                            result = inspect_bundle(Path(payload["path"]), conn=conn)
                        elif action == "import":
                            result = import_bundle(conn, Path(payload["path"]), conflict=payload.get("conflict", "rename"))
                        else:
                            raise ValueError("bundle action must be export, preview-export, preview-import, or import")
                        self._json(result)
                    finally:
                        conn.close()
                    return
                if self.path == "/api/snapshot":
                    action = str(payload.get("action", "create")).strip().lower()
                    if action == "keygen":
                        self._json(snapshot_keygen(Path(payload["path"]), Path(payload["public_key_path"])))
                    elif action == "passphrase-keygen":
                        self._json(snapshot_passphrase_keygen(Path(payload["path"])))
                    elif action == "create":
                        db_path = resolve_brain_db(config, payload["db_path"])
                        self._json(snapshot_create(
                            db_path,
                            Path(payload["path"]),
                            key_path=Path(payload["key_path"]) if payload.get("key_path") else None,
                            private_key_path=Path(payload["private_key_path"]) if payload.get("private_key_path") else None,
                        ))
                    elif action == "verify":
                        self._json(snapshot_verify(
                            Path(payload["path"]),
                            key_path=Path(payload["key_path"]) if payload.get("key_path") else None,
                            public_key_path=Path(payload["public_key_path"]) if payload.get("public_key_path") else None,
                        ))
                    elif action == "encrypt":
                        db_path = resolve_brain_db(config, payload["db_path"])
                        self._json(snapshot_create_encrypted(
                            db_path, Path(payload["path"]), passphrase_path=Path(payload["passphrase_path"]),
                            private_key_path=Path(payload["private_key_path"]) if payload.get("private_key_path") else None,
                        ))
                    elif action == "verify-encrypted":
                        self._json(snapshot_verify_encrypted(
                            Path(payload["path"]), passphrase_path=Path(payload["passphrase_path"]),
                            public_key_path=Path(payload["public_key_path"]) if payload.get("public_key_path") else None,
                        ))
                    elif action == "restore":
                        self._json(snapshot_restore_encrypted(
                            Path(payload["path"]), Path(payload["output_db"]),
                            passphrase_path=Path(payload["passphrase_path"]),
                            public_key_path=Path(payload["public_key_path"]) if payload.get("public_key_path") else None,
                        ))
                    else:
                        raise ValueError(
                            "snapshot action must be create, verify, keygen, passphrase-keygen, "
                            "encrypt, verify-encrypted, or restore"
                        )
                    return
                if self.path == "/api/mcp-doctor":
                    db_path = resolve_brain_db(config, payload["db_path"])
                    self._json(mcp_doctor(
                        db_path, payload["project"], config.tool_root,
                        timeout=float(payload.get("timeout", 10)),
                    ))
                    return
                if self.path == "/api/git-hooks":
                    action = str(payload.get("action", "install")).strip().lower()
                    db_path = resolve_brain_db(config, payload["db_path"])
                    conn = _open_db(db_path)
                    try:
                        row = conn.execute(
                            "SELECT root_path FROM projects WHERE name = ?", (payload["project"],),
                        ).fetchone()
                    finally:
                        conn.close()
                    if not row or not row["root_path"]:
                        raise ValueError("selected project has no canonical repository root")
                    root = canonical_root(row["root_path"])
                    if action == "install":
                        self._json(install_git_hooks(root, db_path=db_path, project=payload["project"]))
                    elif action == "uninstall":
                        self._json(uninstall_git_hooks(root))
                    else:
                        raise ValueError("git-hooks action must be install or uninstall")
                    return
                if self.path == "/api/bootstrap":
                    from .onboarding import onboard_project

                    self._json(
                        onboard_project(
                            config.tool_root,
                            Path(payload["path"]),
                            brain_dir=config.brain_dir,
                            project=payload.get("project"),
                            target_agent=payload.get("target_agent", "universal"),
                            write_agents=bool(payload.get("write_agents", False)),
                            embedding_provider=payload.get("embedding_provider", "hash"),
                            watcher_interval=float(payload.get("interval", 2.0)),
                            open_browser=False,
                            manage_console=False,
                        )
                    )
                    return
                self._json({"status": "error", "error": {"type": "NotFound", "message": self.path}}, status=404)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json({"status": "error", "error": {"type": exc.__class__.__name__, "message": str(exc)}}, status=400)
            except Exception as exc:
                self._json({"status": "error", "error": {"type": exc.__class__.__name__, "message": "request could not be completed"}}, status=500)

        def do_OPTIONS(self) -> None:
            self._json({"status": "error", "error": {"type": "MethodNotAllowed", "message": "cross-origin preflight is not supported"}}, status=405)

    return ConsoleHandler


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, max_workers: int = 16, **kwargs):
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._worker_condition = threading.Condition()
        self._active_workers = 0
        super().__init__(*args, **kwargs)

    def server_bind(self) -> None:
        # The host is already constrained to a literal loopback address.
        # Avoid HTTPServer's reverse-DNS lookup, which can block startup.
        TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])

    def process_request(self, request, client_address) -> None:
        if not self._worker_slots.acquire(blocking=False):
            request.close()
            return
        with self._worker_condition:
            self._active_workers += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._worker_condition:
                self._active_workers -= 1
                self._worker_condition.notify_all()
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._worker_condition:
                self._active_workers -= 1
                self._worker_condition.notify_all()
            self._worker_slots.release()

    def wait_for_idle(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._worker_condition:
            while self._active_workers:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._worker_condition.wait(timeout=remaining)
        return True


def create_dashboard_server(
    tool_root: Path,
    brain_dir: Path,
    default_db: Path | None = None,
    default_project: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    capability_token: str | None = None,
    instance_id: str | None = None,
) -> tuple[BoundedThreadingHTTPServer, ConsoleConfig, str]:
    """Bind a loopback console and return the server, config, and authorized URL."""
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("dashboard host must be loopback-only")
    preferred_port = int(port)
    if not 0 <= preferred_port <= 65_535:
        raise ValueError("dashboard port must be between 0 and 65,535")
    config_options = {
        "tool_root": tool_root.resolve(),
        "brain_dir": brain_dir.expanduser().resolve(),
        "default_db": default_db.expanduser().resolve() if default_db else None,
        "default_project": default_project,
        "instance_id": instance_id,
    }
    if capability_token is not None:
        config_options["capability_token"] = capability_token
    config = ConsoleConfig(**config_options)
    candidates = (0,) if preferred_port == 0 else range(preferred_port, min(preferred_port + 50, 65_536))
    last_error = None
    server = None
    for candidate in candidates:
        try:
            server = BoundedThreadingHTTPServer((host, candidate), make_handler(config))
            break
        except OSError as exc:
            last_error = exc
    if server is None:
        if last_error is not None:
            raise OSError(
                f"no available dashboard port found from {preferred_port} "
                f"to {min(preferred_port + 49, 65_535)}"
            ) from last_error
        raise OSError("dashboard could not bind a loopback port")
    selected_port = int(server.server_address[1])
    return server, config, f"http://{host}:{selected_port}/#token={config.capability_token}"


def run_dashboard(
    tool_root: Path,
    brain_dir: Path,
    default_db: Path | None = None,
    default_project: str | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> dict:
    server, _config, url = create_dashboard_server(
        tool_root,
        brain_dir,
        default_db=default_db,
        default_project=default_project,
        host=host,
        port=port,
    )
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    print(f"Rta-Smriti Operator Console: {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return {"status": "ok", "url": url}
