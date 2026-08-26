"""One-command, resumable project onboarding for Rta-Smriti."""

from __future__ import annotations

from pathlib import Path

from .capture_daemon import start_capture
from .capture_spool import capture_control_root_path, ensure_capture_control_root
from .continuity_daemon import DEFAULT_BACKLOG_TAIL_BYTES, start_continuity
from .db import connect
from .project import (
    bootstrap_project,
    project_db_path,
    self_check,
    shell_cli_command,
    shell_quote,
)
from .repository import repository_state, same_root
from .runtime_control import is_safe_regular_file, read_json, write_json
from .watch_daemon import start_watcher

SUPPORTED_TARGET_AGENTS = frozenset({
    "universal", "codex", "claude-code", "cursor", "github-copilot",
    "gemini-cli", "windsurf", "cline", "aider", "opencode", "continue", "custom",
})


def derive_project_name(root: Path) -> str:
    value = "".join(character.lower() if character.isalnum() else "-" for character in root.name)
    return value.strip("-") or "project"


def _stage(name: str, state: str, detail: str) -> dict:
    return {"name": name, "state": state, "detail": detail}


def _recovery_commands(tool_root: Path, repo: Path, brain_dir: Path, db_path: Path, project: str) -> dict:
    cli = shell_cli_command(tool_root)
    return {
        "resume": (
            f"{cli} start {shell_quote(repo)} --project {shell_quote(project)} "
            f"--brain-dir {shell_quote(brain_dir)} --no-open"
        ),
        "watcher": (
            f"{cli} --db {shell_quote(db_path)} watcher start {shell_quote(repo)} "
            f"--project {shell_quote(project)}"
        ),
        "capture": f"{cli} --db {shell_quote(db_path)} capture daemon start",
        "console": f"{cli} console start --brain-dir {shell_quote(brain_dir)} --no-open",
        "verify": f"{cli} --db {shell_quote(db_path)} self-check --project {shell_quote(project)}",
    }


def _enrollment_path(db_path: Path) -> Path:
    return capture_control_root_path(db_path) / "service-enrollment.json"


def _save_service_enrollment(
    db_path: Path, *, project: str, root: Path, sessions_root: Path,
    watcher: bool, capture: bool, continuity: bool,
) -> Path:
    database = db_path.expanduser().resolve()
    ensure_capture_control_root(database)
    path = _enrollment_path(database)
    write_json(path, {
        "schema": "rta-smriti.service-enrollment/v1",
        "db_path": str(database),
        "project": project,
        "root": str(root.expanduser().resolve()),
        "sessions_root": str(sessions_root.expanduser().resolve()),
        "watcher": bool(watcher),
        "capture": bool(capture),
        "continuity": bool(continuity),
    }, label="service enrollment")
    return path


def supervise_brain(
    tool_root: Path, brain_dir: Path, *, port: int = 8765,
    open_browser: bool = False,
) -> dict:
    """Restart only services explicitly enrolled by successful onboarding."""

    brains = brain_dir.expanduser().resolve()
    if not brains.is_dir() or brains.is_symlink():
        raise ValueError(f"brain directory is missing or linked: {brains}")
    projects = []
    failed = False

    def require_running(name: str, state: dict) -> dict:
        if state.get("state") not in {"running", "current"}:
            raise RuntimeError(f"{name} did not become ready: {state.get('state')}")
        return state

    for database in sorted(brains.glob("*.sqlite")):
        if not is_safe_regular_file(database):
            continue
        receipt_path = _enrollment_path(database)
        receipt = read_json(receipt_path)
        if receipt is None:
            continue
        item = {"project": receipt.get("project"), "db_path": str(database), "services": {}}
        try:
            if (
                receipt.get("schema") != "rta-smriti.service-enrollment/v1"
                or Path(str(receipt.get("db_path", ""))).expanduser().resolve() != database.resolve()
            ):
                raise ValueError("service enrollment receipt does not match its brain")
            project = str(receipt["project"])
            root = Path(str(receipt["root"])).expanduser().resolve()
            sessions = Path(str(receipt["sessions_root"])).expanduser().resolve()
            conn = connect(database)
            try:
                binding = conn.execute(
                    "SELECT root_path FROM projects WHERE name = ?",
                    (project,),
                ).fetchone()
            finally:
                conn.close()
            if (
                binding is None
                or not binding["root_path"]
                or not same_root(str(binding["root_path"]), root)
            ):
                raise ValueError(
                    "service enrollment root does not match the brain's canonical project root"
                )
            if receipt.get("watcher"):
                item["services"]["watcher"] = require_running(
                    "watcher", start_watcher(database, root, project),
                )
            if receipt.get("capture"):
                item["services"]["capture"] = require_running(
                    "capture", start_capture(database),
                )
            if receipt.get("continuity") and sessions.is_dir():
                item["services"]["continuity"] = require_running(
                    "continuity", start_continuity(database, root, project, sessions),
                )
            elif receipt.get("continuity"):
                item["services"]["continuity"] = {
                    "state": "unavailable", "reason": "sessions_root_missing",
                }
            item["state"] = "running"
        except Exception as exc:  # noqa: BLE001 - isolate one enrolled project
            failed = True
            item["state"] = "error"
            item["error_class"] = exc.__class__.__name__
        projects.append(item)

    from .console_daemon import start_console

    console = start_console(
        tool_root, brains, port=port, open_browser=open_browser,
    )
    if console.get("state") != "running":
        failed = True
    return {
        "status": "partial" if failed else "ok",
        "brain_dir": str(brains),
        "projects": projects,
        "console": console,
    }


def onboard_project(
    tool_root: Path,
    path: Path,
    *,
    brain_dir: Path,
    project: str | None = None,
    target_agent: str = "universal",
    write_agents: bool = False,
    embedding_provider: str | None = None,
    watcher_interval: float = 2.0,
    sessions_root: Path | None = None,
    start_continuity_capture: bool = True,
    start_universal_capture: bool = True,
    continuity_interval: float | None = None,
    continuity_inactivity: float = 900.0,
    continuity_lookback_days: float = 30.0,
    continuity_backlog_tail_bytes: int = DEFAULT_BACKLOG_TAIL_BYTES,
    port: int = 8765,
    open_browser: bool = True,
    start_sync: bool = True,
    manage_console: bool = True,
) -> dict:
    requested = path.expanduser().resolve()
    brains = brain_dir.expanduser().resolve()
    stages: list[dict] = []
    if not requested.is_dir():
        raise ValueError(f"project path does not exist or is not a directory: {requested}")
    if target_agent not in SUPPORTED_TARGET_AGENTS:
        raise ValueError(f"unsupported target agent: {target_agent}")

    git = repository_state(requested)
    repo = Path(git["repository_root"]).resolve() if git["is_git_repo"] else requested
    selected_project = project.strip() if project else derive_project_name(repo)
    if not selected_project:
        raise ValueError("project name cannot be empty")
    db_path = project_db_path(brains, selected_project)
    recovery = _recovery_commands(tool_root, repo, brains, db_path, selected_project)
    stages.append(_stage("discover", "complete", "Canonical project root and identity resolved."))

    result = {
        "status": "partial",
        "ready": False,
        "project": selected_project,
        "target_agent": target_agent,
        "repo_path": str(repo),
        "db_path": str(db_path),
        "git": git,
        "stages": stages,
        "recovery_commands": recovery,
    }
    try:
        bootstrap = bootstrap_project(
            None,
            repo,
            selected_project,
            brains,
            write_agents,
            tool_root,
            embedding_provider=embedding_provider,
        )
        result["bootstrap"] = bootstrap
        stages.append(_stage("bootstrap", "complete", "Brain migrated and repository index refreshed."))

        if start_sync:
            watcher = start_watcher(
                db_path,
                repo,
                selected_project,
                interval_seconds=watcher_interval,
            )
            if watcher.get("state") != "running":
                raise RuntimeError(f"repository watcher is not running: {watcher.get('state')}")
            stages.append(_stage("watcher", "complete", "Incremental repository sync is running."))
        else:
            watcher = {"status": "ok", "state": "disabled"}
            stages.append(_stage("watcher", "complete", "Incremental sync was explicitly disabled."))
        result["watcher"] = watcher

        if start_universal_capture:
            capture = start_capture(db_path, interval_seconds=max(0.1, watcher_interval))
            if capture.get("state") != "running":
                raise RuntimeError(f"universal capture daemon is not running: {capture.get('state')}")
            stages.append(_stage("capture", "complete", "Universal capture normalization is running."))
        else:
            capture = {"status": "ok", "state": "disabled"}
            stages.append(_stage("capture", "complete", "Universal capture was explicitly disabled."))
        result["capture"] = capture

        if start_continuity_capture:
            sessions = (sessions_root or (Path.home() / ".codex" / "sessions")).expanduser().resolve()
            if sessions.is_dir():
                continuity = start_continuity(
                    db_path,
                    repo,
                    selected_project,
                    sessions,
                    interval_seconds=continuity_interval or max(0.1, watcher_interval),
                    inactivity_seconds=continuity_inactivity,
                    lookback_days=continuity_lookback_days,
                    backlog_tail_bytes=continuity_backlog_tail_bytes,
                )
                if continuity.get("state") != "running":
                    raise RuntimeError(f"task continuity capture is not running: {continuity.get('state')}")
                stages.append(_stage("continuity", "complete", "Managed Codex task continuity capture is running."))
            else:
                continuity = {
                    "status": "ok",
                    "state": "unavailable",
                    "reason": "codex_sessions_root_missing",
                    "sessions_root": str(sessions),
                }
                stages.append(_stage("continuity", "complete", "Codex task continuity capture skipped because the sessions directory was not found."))
        else:
            continuity = {"status": "ok", "state": "disabled"}
            stages.append(_stage("continuity", "complete", "Task continuity capture was explicitly disabled."))
        result["continuity"] = continuity

        if manage_console:
            from .console_daemon import start_console

            console = start_console(
                tool_root,
                brains,
                default_db=db_path,
                default_project=selected_project,
                port=port,
                open_browser=open_browser,
            )
            if console.get("state") != "running":
                raise RuntimeError(f"operator console is not running: {console.get('state')}")
        else:
            console = {"status": "ok", "state": "current"}
        result["console"] = console
        stages.append(_stage(
            "console", "complete",
            "Managed operator console is authenticated and reachable."
            if manage_console else "Current authenticated operator console remains active.",
        ))

        conn = connect(db_path)
        try:
            readiness = self_check(conn, project=selected_project, check_files=False)
        finally:
            conn.close()
        result["readiness"] = readiness
        if not readiness.get("ready"):
            raise RuntimeError("project brain did not pass readiness verification")
        stages.append(_stage("verify", "complete", "Indexed evidence and local runtime passed readiness checks."))
        _save_service_enrollment(
            db_path,
            project=selected_project,
            root=repo,
            sessions_root=(sessions_root or (Path.home() / ".codex" / "sessions")),
            watcher=start_sync,
            capture=start_universal_capture,
            continuity=start_continuity_capture,
        )
        result.update({"status": "ok", "ready": True})
        return result
    except Exception as exc:  # noqa: BLE001 - return a resumable onboarding receipt
        completed = {stage["name"] for stage in stages}
        failed_stage = next(
            name for name in (
                "bootstrap", "watcher", "capture", "continuity", "console", "verify",
            ) if name not in completed
        )
        stages.append(_stage(failed_stage, "failed", f"{exc.__class__.__name__}: {exc}"))
        result["error"] = {"type": exc.__class__.__name__, "message": str(exc), "stage": failed_stage}
        return result
