"""Platform path normalization that preserves link-traversal defenses."""

from __future__ import annotations

import stat
import sys
from pathlib import Path


_DARWIN_ROOT_ALIASES = (
    (Path("/var"), Path("/private/var")),
    (Path("/tmp"), Path("/private/tmp")),
)


def canonicalize_system_root_alias(path: str | Path) -> Path:
    """Resolve only Apple's fixed root aliases, leaving other links detectable."""

    selected = Path(path).expanduser()
    if not selected.is_absolute():
        selected = selected.absolute()
    if sys.platform != "darwin":
        return selected

    for alias, expected_target in _DARWIN_ROOT_ALIASES:
        try:
            relative = selected.relative_to(alias)
        except ValueError:
            continue
        try:
            alias_info = alias.lstat()
            resolved_alias = alias.resolve(strict=True)
            target_info = expected_target.lstat()
        except OSError as exc:
            raise ValueError("macOS system path alias is unavailable") from exc
        if (
            not stat.S_ISLNK(alias_info.st_mode)
            or resolved_alias != expected_target
            or not stat.S_ISDIR(target_info.st_mode)
            or expected_target.is_symlink()
        ):
            raise ValueError("macOS system path alias is not trusted")
        return expected_target / relative
    return selected
