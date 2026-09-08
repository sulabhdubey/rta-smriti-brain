"""Explicitly managed, opt-in Git checkpoint hooks."""

from __future__ import annotations

import os
import secrets
import shlex
import sys
from pathlib import Path

from .repository import configured_hooks_path, verified_git_layout
from .runtime_control import runtime_executable

MARKER = "# RTA_SMIRTI_MANAGED_HOOK_V1"


def _hook_path(root: Path) -> Path:
    resolved = Path(root).expanduser().resolve()
    layout = verified_git_layout(resolved)
    if not layout:
        raise ValueError(f"project is not an accessible Git repository: {resolved}")
    repository_root, _git_dir, common_dir = layout
    hooks = configured_hooks_path(repository_root, common_dir)
    if hooks is None:
        raise ValueError(f"Git hooks directory is unavailable: {resolved}")
    try:
        hooks.relative_to(common_dir)
    except ValueError as exc:
        raise ValueError(
            f"Git hooks directory is outside the verified Git common directory: {hooks}"
        ) from exc
    if not hooks.is_dir():
        raise ValueError(f"Git hooks directory does not exist: {hooks}")
    return hooks / "post-commit"


def _cli_invocation() -> str:
    executable_path = str(runtime_executable()).replace("\\", "/")
    if getattr(sys, "frozen", False):
        return shlex.quote(executable_path)
    trusted_root = str(Path(__file__).resolve().parents[1]).replace("\\", "/")
    bootstrap = (
        "import runpy,sys;"
        f"sys.path.insert(0,{trusted_root!r});"
        "runpy.run_module('rta_brain.cli',run_name='__main__')"
    )
    return " ".join(shlex.quote(part) for part in (executable_path, "-I", "-c", bootstrap))


def _assert_unlinked_hook(hook: Path) -> None:
    if hook.is_symlink() or (hook.exists() and hook.stat().st_nlink > 1):
        raise ValueError("managed Git hook must not be a linked file")


def _write_hook(hook: Path, script: str) -> None:
    temporary = hook.with_name(f".{hook.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(script)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, hook)
    finally:
        if temporary.exists():
            temporary.unlink()


def install_git_hooks(root: Path, *, db_path: Path, project: str) -> dict:
    hook = _hook_path(root)
    _assert_unlinked_hook(hook)
    if hook.exists() and MARKER not in hook.read_text(encoding="utf-8", errors="ignore"):
        raise ValueError("an unmanaged post-commit hook already exists; Rta-Smriti will not overwrite it")
    db = shlex.quote(str(Path(db_path).expanduser().resolve()).replace("\\", "/"))
    cli = _cli_invocation()
    project_name = shlex.quote(str(project))
    script = (
        "#!/bin/sh\n"
        f"{MARKER}\n"
        f"{cli} --db {db} checkpoint --project {project_name} "
        "--objective \"Continue after Git commit\" "
        "--verified-evidence \"Git commit recorded by opt-in hook\" "
        "--next-action \"Review the latest checkpoint before resuming\" >/dev/null 2>&1 || true\n"
    )
    _write_hook(hook, script)
    try:
        os.chmod(hook, 0o755)
    except OSError:
        pass
    return {"status": "ok", "installed": True, "hook_path": str(hook), "event": "post-commit"}


def uninstall_git_hooks(root: Path) -> dict:
    hook = _hook_path(root)
    _assert_unlinked_hook(hook)
    if not hook.exists():
        return {"status": "ok", "removed": False, "hook_path": str(hook)}
    if MARKER not in hook.read_text(encoding="utf-8", errors="ignore"):
        raise ValueError("post-commit hook is not managed by Rta-Smriti")
    hook.unlink()
    return {"status": "ok", "removed": True, "hook_path": str(hook)}
