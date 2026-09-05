"""Multi-repository workspace metadata over independently bound projects."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

from .context import filter_search_results_by_privacy
from .db import init_schema, now_iso, search


def _name(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > 200:
        raise ValueError(f"{label} exceeds 200 characters")
    return text


def create_workspace(conn, name: str, description: str = "") -> dict:
    init_schema(conn)
    workspace_name = _name(name, "workspace name")
    description_text = str(description or "").strip()
    if len(description_text) > 2_000:
        raise ValueError("workspace description exceeds 2,000 characters")
    timestamp = now_iso()
    with conn:
        conn.execute(
            """
            INSERT INTO workspaces(name, description, created_at, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET description = excluded.description, updated_at = excluded.updated_at
            """,
            (workspace_name, description_text, timestamp, timestamp),
        )
    return get_workspace(conn, workspace_name)


def _connection_path(conn) -> str:
    row = conn.execute("PRAGMA database_list").fetchone()
    return str(Path(row["file"]).resolve()) if row and row["file"] else ":memory:"


def _existing_brain_path(value: str | Path) -> Path:
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise ValueError("workspace member brain must not be a linked file")
    try:
        resolved = requested.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"workspace member brain does not exist: {requested}") from exc
    if not resolved.is_file():
        raise ValueError(f"workspace member brain is not a regular file: {resolved}")
    if resolved.stat().st_nlink > 1:
        raise ValueError("workspace member brain must not be a linked file")
    return resolved


def _regular_file_identity(path: Path) -> tuple[int, int]:
    details = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise ValueError("workspace member brain must not be a linked file")
    return int(details.st_dev), int(details.st_ino)


def _pin_existing_brain(path: Path) -> tuple[int, tuple[int, int]]:
    expected = _regular_file_identity(path)
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_CLOEXEC", "O_NOFOLLOW"):
        flags |= int(getattr(os, name, 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("workspace member brain changed while it was opened") from exc
    try:
        opened = os.fstat(descriptor)
        identity = (int(opened.st_dev), int(opened.st_ino))
        if (
            identity != expected
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            raise ValueError("workspace member brain changed while it was opened")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _workspace_sidecar_paths(database: Path) -> tuple[Path, Path]:
    return Path(f"{database}-wal"), Path(f"{database}-shm")


def _pin_existing_sidecars(
    database: Path,
) -> dict[Path, tuple[int, tuple[int, int]]]:
    pinned: dict[Path, tuple[int, tuple[int, int]]] = {}
    try:
        for sidecar in _workspace_sidecar_paths(database):
            if sidecar.exists() or sidecar.is_symlink():
                try:
                    pinned[sidecar] = _pin_existing_brain(sidecar)
                except (OSError, ValueError) as exc:
                    raise ValueError(
                        "workspace member brain sidecar is unsafe"
                    ) from exc
        return pinned
    except BaseException:
        for descriptor, _identity in pinned.values():
            os.close(descriptor)
        raise


def _verify_and_pin_sidecars(
    database: Path,
    pinned: dict[Path, tuple[int, tuple[int, int]]],
) -> None:
    for sidecar in _workspace_sidecar_paths(database):
        if sidecar in pinned:
            try:
                current = _regular_file_identity(sidecar)
            except (OSError, ValueError) as exc:
                raise ValueError(
                    "workspace member brain sidecar changed while it was opened"
                ) from exc
            if current != pinned[sidecar][1]:
                raise ValueError(
                    "workspace member brain sidecar changed while it was opened"
                )
        elif sidecar.exists() or sidecar.is_symlink():
            try:
                pinned[sidecar] = _pin_existing_brain(sidecar)
            except (OSError, ValueError) as exc:
                raise ValueError(
                    "workspace member brain sidecar is unsafe"
                ) from exc


def _connect_existing_brain(value: str | Path, *, read_only: bool = False) -> tuple[sqlite3.Connection, Path]:
    resolved = _existing_brain_path(value)
    descriptor, identity = _pin_existing_brain(resolved)
    sidecars = _pin_existing_sidecars(resolved)
    mode = "ro" if read_only else "rw"
    conn = None
    try:
        conn = sqlite3.connect(f"{resolved.as_uri()}?mode={mode}", uri=True)
        if _regular_file_identity(resolved) != identity:
            raise ValueError("workspace member brain changed while it was opened")
        _verify_and_pin_sidecars(resolved, sidecars)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        if read_only:
            conn.execute("PRAGMA query_only = ON")
        if _regular_file_identity(resolved) != identity:
            raise ValueError("workspace member brain changed while it was opened")
        _verify_and_pin_sidecars(resolved, sidecars)
        return conn, resolved
    except OSError as exc:
        if conn is not None:
            conn.close()
        raise ValueError("workspace member brain changed while it was opened") from exc
    except BaseException:
        if conn is not None:
            conn.close()
        raise
    finally:
        os.close(descriptor)
        for sidecar_descriptor, _sidecar_identity in sidecars.values():
            os.close(sidecar_descriptor)


def add_project_to_workspace(
    conn, *, workspace: str, project: str, role: str = "member", db_path: str | Path | None = None,
) -> dict:
    init_schema(conn)
    workspace_name = _name(workspace, "workspace")
    project_name = _name(project, "project")
    role_name = _name(role, "role")
    workspace_row = conn.execute("SELECT id FROM workspaces WHERE name = ?", (workspace_name,)).fetchone()
    if not workspace_row:
        raise ValueError(f"workspace does not exist: {workspace_name}")
    owner_path = _connection_path(conn)
    if db_path:
        member_conn, resolved_member = _connect_existing_brain(db_path)
        member_db_path = str(resolved_member)
        if member_db_path == owner_path:
            member_conn.close()
            member_conn = conn
    else:
        member_db_path = owner_path
        member_conn = conn
    try:
        init_schema(member_conn)
        project_row = member_conn.execute("SELECT id FROM projects WHERE name = ?", (project_name,)).fetchone()
        if not project_row:
            raise ValueError(f"project does not exist in member brain: {project_name}")
    finally:
        if member_conn is not conn:
            member_conn.close()
    with conn:
        conn.execute(
            """
            INSERT INTO workspace_members(workspace_id, db_path, project_name, role, added_at) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(workspace_id, db_path, project_name) DO UPDATE SET role = excluded.role
            """,
            (int(workspace_row["id"]), member_db_path, project_name, role_name, now_iso()),
        )
        conn.execute("UPDATE workspaces SET updated_at = ? WHERE id = ?", (now_iso(), int(workspace_row["id"])))
    return get_workspace(conn, workspace_name)


def get_workspace(conn, name: str) -> dict:
    init_schema(conn)
    row = conn.execute("SELECT * FROM workspaces WHERE name = ?", (_name(name, "workspace"),)).fetchone()
    if not row:
        raise ValueError(f"workspace does not exist: {name}")
    projects = [dict(item) for item in conn.execute(
        """
        SELECT project_name AS project, role, db_path, added_at
        FROM workspace_members WHERE workspace_id = ? ORDER BY project_name, db_path
        """,
        (int(row["id"]),),
    )]
    if not projects:
        projects = [dict(item) for item in conn.execute(
            """
            SELECT p.name AS project, wp.role, p.root_path, p.repository_identity, wp.added_at,
                   ? AS db_path
            FROM workspace_projects wp JOIN projects p ON p.id = wp.project_id
            WHERE wp.workspace_id = ? ORDER BY p.name
            """,
            (_connection_path(conn), int(row["id"])),
        )]
    return {"status": "ok", "workspace": dict(row), "projects": projects}


def list_workspaces(conn) -> dict:
    init_schema(conn)
    rows = [dict(row) for row in conn.execute(
        """
        SELECT w.*, COUNT(wp.project_name) AS project_count
        FROM workspaces w LEFT JOIN workspace_members wp ON wp.workspace_id = w.id
        GROUP BY w.id ORDER BY w.name
        """
    )]
    return {"status": "ok", "workspaces": rows}


def workspace_health(conn, name: str) -> dict:
    details = get_workspace(conn, name)
    owner_path = _connection_path(conn)
    members = []
    for item in details["projects"]:
        member_path = str(item.get("db_path") or owner_path)
        member = {
            "project": item["project"], "role": item["role"],
            "available": False, "project_present": False,
        }
        try:
            if member_path == owner_path:
                member_conn = conn
            else:
                member_conn, _ = _connect_existing_brain(member_path, read_only=True)
            try:
                row = member_conn.execute(
                    "SELECT 1 FROM projects WHERE name = ?", (item["project"],),
                ).fetchone()
                member["available"] = True
                member["project_present"] = bool(row)
                if not row:
                    member["error"] = "project is no longer present in the member brain"
            finally:
                if member_conn is not conn:
                    member_conn.close()
        except (OSError, sqlite3.Error, ValueError):
            member["error"] = "member brain is unavailable"
        members.append(member)
    healthy = sum(1 for item in members if item["available"] and item["project_present"])
    return {
        "status": "ok" if healthy == len(members) else "degraded",
        "workspace": name,
        "members": members,
        "summary": {"total": len(members), "healthy": healthy, "unavailable": len(members) - healthy},
    }


def remove_project_from_workspace(
    conn, *, workspace: str, project: str, db_path: str | Path | None = None,
) -> dict:
    details = get_workspace(conn, workspace)
    workspace_id = int(details["workspace"]["id"])
    project_name = _name(project, "project")
    member_path = str(Path(db_path).expanduser().resolve()) if db_path else _connection_path(conn)
    with conn:
        cursor = conn.execute(
            "DELETE FROM workspace_members WHERE workspace_id = ? AND db_path = ? AND project_name = ?",
            (workspace_id, member_path, project_name),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"workspace member does not exist: {project_name}")
        conn.execute("UPDATE workspaces SET updated_at = ? WHERE id = ?", (now_iso(), workspace_id))
    return get_workspace(conn, workspace)


def delete_workspace(conn, name: str) -> dict:
    workspace_name = _name(name, "workspace")
    with conn:
        cursor = conn.execute("DELETE FROM workspaces WHERE name = ?", (workspace_name,))
    if cursor.rowcount == 0:
        raise ValueError(f"workspace does not exist: {workspace_name}")
    return {"status": "deleted", "workspace": workspace_name}


def search_workspace(
    conn,
    *,
    workspace: str,
    query: str,
    limit_per_project: int = 4,
    privacy_ceiling: str | None = None,
) -> dict:
    details = get_workspace(conn, workspace)
    bounded_limit = max(1, min(20, int(limit_per_project)))
    results = []
    errors = []
    for item in details["projects"]:
        member_path = str(item.get("db_path") or _connection_path(conn))
        owner_path = _connection_path(conn)
        try:
            if member_path == owner_path:
                member_conn = conn
            else:
                member_conn, resolved_member = _connect_existing_brain(member_path, read_only=True)
                member_path = str(resolved_member)
            try:
                result = filter_search_results_by_privacy(
                    search(
                        member_conn, query, project=item["project"], limit=bounded_limit,
                        record_recall=False, _initialize=False,
                    ),
                    privacy_ceiling,
                )
            finally:
                if member_conn is not conn:
                    member_conn.close()
        except (OSError, sqlite3.Error, ValueError) as exc:
            errors.append({
                "project": item["project"], "role": item["role"],
                "error": "member brain is unavailable" if isinstance(exc, (OSError, ValueError)) else "member brain query failed",
            })
            continue
        results.append({
            "project": item["project"], "role": item["role"],
            "retrieval": result["retrieval"], "memories": result["memories"],
            "chunks": result["chunks"], "truth": result.get("truth", []),
        })
    return {
        "status": "degraded" if errors else "ok",
        "workspace": workspace, "query": str(query), "results": results, "errors": errors,
    }
