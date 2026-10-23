import hashlib
import os
import re
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path


IGNORED_DIRS = {
    ".git",
    ".rta-smriti",
    ".hg",
    ".svn",
    ".venv",
    ".venv-wsl-cuda",
    "venv",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".cache",
    ".agents",
    ".firecrawl",
    ".playwright-cli",
    ".worktree",
    ".worktrees",
    "worktrees",
    ".ruff_cache",
    ".mypy_cache",
    ".hypothesis",
    ".tox",
    ".nox",
    ".turbo",
    ".parcel-cache",
    ".vite",
    ".pnpm-store",
    "ms-playwright",
    "playwright-report",
    "blob-report",
    "test-scratch",
    ".pytest_cache",
    ".superpowers",
    "audit",
    "build",
    "coverage",
    "data",
    "dist",
    "execution_leases",
    "logs",
    "output",
    "state_write_locks",
    "test-results",
    "unused",
}

IGNORED_PREFIXES = (
    "tmp",
    ".tmp",
    ".venv",
    "temp",
    "cache",
    "__pycache__",
    "chromium-",
    "chrome-headless-shell-",
    "firefox-",
    "webkit-",
    "playwright-",
    "test-scratch",
    ".worktree",
)

TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".css",
    ".html",
    ".sql",
    ".ps1",
    ".sh",
}

MAX_REPO_FILES = 50_000
MAX_FILE_BYTES = 512_000
MAX_REPO_TOTAL_BYTES = 2_000_000_000
MAX_REPO_TRAVERSED_ENTRIES = 250_000

CANONICAL_CONTROL_FILE_MAX_BYTES = 4_000_000
CANONICAL_CONTROL_NAMES = {"live_context.md", "project_live_context.md", "active_context.md"}
CANONICAL_CONTROL_DIRECTORIES = {"00_source_of_truth", "source_of_truth", "source-of-truth"}

SYMBOL_PATTERNS = [
    re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE),
    re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE),
    re.compile(r"^\s*async\s+def\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE),
    re.compile(r"^\s*function\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.MULTILINE),
    re.compile(r"^\s*export\s+function\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.MULTILINE),
    re.compile(r"^\s*export\s+class\s+([A-Za-z_$][A-Za-z0-9_$]*)", re.MULTILINE),
    re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(", re.MULTILINE),
]

IMPORT_PATTERNS = [
    re.compile(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_\.]*)", re.MULTILINE),
    re.compile(r"^\s*from\s+([A-Za-z_][A-Za-z0-9_\.]*)\s+import\s+", re.MULTILINE),
    re.compile(r"^\s*import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]", re.MULTILINE),
    re.compile(r"require\(['\"]([^'\"]+)['\"]\)"),
]


@dataclass(frozen=True)
class FileRecord:
    path: Path
    relative_path: str
    text: str
    sha256: str
    symbols: list[str]
    imports: list[str]
    calls: list[str]
    chunks: list[str]
    parser: str = "regex"
    parser_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class _VerifiedText:
    path: Path
    text: str


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def effective_file_limit(root: Path, path: Path, default_limit: int) -> int:
    """Allow explicit, project-neutral control files without widening the repo-wide cap."""

    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix().lower()
    except (OSError, ValueError):
        return int(default_limit)
    parts = relative.split("/")
    name = parts[-1]
    is_live_context = name in CANONICAL_CONTROL_NAMES or name.endswith("_live_context.md")
    is_source_truth = len(parts) <= 3 and parts[0] in CANONICAL_CONTROL_DIRECTORIES
    if is_live_context or is_source_truth:
        return max(int(default_limit), CANONICAL_CONTROL_FILE_MAX_BYTES)
    return int(default_limit)


def walk_repo(root: Path, rejected: list[dict[str, str]] | None = None, max_file_bytes: int = MAX_FILE_BYTES):
    root = root.resolve()

    def reject(path: Path, reason: str) -> None:
        if rejected is not None:
            rejected.append({"path": str(path.absolute()), "reason": reason})

    yielded = 0
    total_bytes = 0
    traversed = 0
    for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        traversed += len(directories) + len(filenames)
        if traversed > MAX_REPO_TRAVERSED_ENTRIES:
            raise ValueError(f"repository exceeds the {MAX_REPO_TRAVERSED_ENTRIES:,} entry traversal limit")
        kept_directories = []
        for name in directories:
            path = current_path / name
            if name in IGNORED_DIRS or name.lower().startswith(IGNORED_PREFIXES):
                continue
            if path.is_symlink():
                reject(path, "symlink-directory")
                continue
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in filenames:
            path = current_path / name
            if name.lower().startswith(IGNORED_PREFIXES) or not is_text_file(path):
                continue
            if path.is_symlink():
                reject(path, "symlink-file")
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
            except (OSError, ValueError):
                reject(path, "unresolvable-or-outside-root")
                continue
            try:
                stat = resolved.stat()
            except OSError:
                reject(path, "unreadable-metadata")
                continue
            if not resolved.is_file():
                reject(path, "not-a-regular-file")
                continue
            if stat.st_nlink > 1:
                reject(path, "hard-link-file")
                continue
            file_limit = effective_file_limit(root, resolved, max_file_bytes)
            if stat.st_size > file_limit:
                reject(path, f"oversized:{stat.st_size}")
                continue
            yielded += 1
            if yielded > MAX_REPO_FILES:
                raise ValueError(f"repository exceeds the {MAX_REPO_FILES:,} file ingestion limit")
            total_bytes += stat.st_size
            if total_bytes > MAX_REPO_TOTAL_BYTES:
                raise ValueError(f"repository exceeds the {MAX_REPO_TOTAL_BYTES:,} byte ingestion limit")
            yield resolved


def _file_identity(file_stat) -> tuple[int, int, int]:
    return (
        int(file_stat.st_dev),
        int(file_stat.st_ino),
        stat_module.S_IFMT(file_stat.st_mode),
    )


def _is_reparse_point(file_stat) -> bool:
    marker = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and getattr(file_stat, "st_file_attributes", 0) & marker)


def _lexical_root_for_candidate(root: Path, candidate: Path) -> Path:
    requested_root = root.expanduser().absolute()
    candidate = candidate.expanduser().absolute()
    try:
        candidate.relative_to(requested_root)
    except ValueError:
        pass
    else:
        for ancestor in (candidate, *candidate.parents):
            try:
                ancestor_stat = ancestor.lstat()
            except OSError:
                continue
            if stat_module.S_ISLNK(ancestor_stat.st_mode) or _is_reparse_point(ancestor_stat):
                raise ValueError(f"linked path ancestor rejected: {ancestor}")
            if ancestor == requested_root:
                return requested_root
        raise ValueError(f"path is outside the repository root: {candidate}")

    for ancestor in (candidate, *candidate.parents):
        try:
            ancestor_stat = ancestor.lstat()
        except OSError:
            continue
        if stat_module.S_ISLNK(ancestor_stat.st_mode) or _is_reparse_point(ancestor_stat):
            raise ValueError(f"linked path ancestor rejected: {ancestor}")
        try:
            if os.path.samefile(ancestor, requested_root):
                return ancestor
        except OSError:
            continue
    raise ValueError(f"path is outside the repository root: {candidate}")


def _capture_path_chain(root: Path, candidate: Path) -> tuple[tuple[Path, tuple[int, int, int]], ...]:
    relative = candidate.relative_to(root)
    paths = [root]
    current = root
    for part in relative.parts:
        current = current / part
        paths.append(current)
    captured = []
    for index, item in enumerate(paths):
        item_stat = item.lstat()
        if stat_module.S_ISLNK(item_stat.st_mode) or _is_reparse_point(item_stat):
            raise OSError(f"linked or reparse path rejected: {item}")
        if index < len(paths) - 1 and not stat_module.S_ISDIR(item_stat.st_mode):
            raise OSError(f"non-directory ancestor rejected: {item}")
        captured.append((item, _file_identity(item_stat)))
    return tuple(captured)


def _open_verified_descriptor(root: Path | None, candidate: Path) -> int:
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    file_flags |= getattr(os, "O_NOFOLLOW", 0)
    supports_relative_open = os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")
    if root is None or not supports_relative_open:
        return os.open(candidate, file_flags)

    relative = candidate.relative_to(root)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(root, directory_flags)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return os.open(relative.parts[-1], file_flags, dir_fd=descriptor)
    finally:
        os.close(descriptor)


def _read_verified_text(
    path: Path, max_bytes: int, root: Path | None = None, *, strict_utf8: bool = False,
) -> _VerifiedText | None:
    if max_bytes < 0:
        raise ValueError("max_bytes must not be negative")
    source = path.expanduser().absolute()
    try:
        source_lstat = source.lstat()
        if stat_module.S_ISLNK(source_lstat.st_mode) or _is_reparse_point(source_lstat):
            return None
        requested_root = root.expanduser().absolute() if root is not None else None
        canonical_root = requested_root.resolve(strict=True) if requested_root is not None else None
        if canonical_root is not None:
            if not canonical_root.is_dir():
                return None
            lexical_root = _lexical_root_for_candidate(requested_root, source)
            lexical_chain = _capture_path_chain(lexical_root, source)
        else:
            lexical_root = None
            lexical_chain = None
        candidate = source.resolve(strict=True)
        if canonical_root is not None:
            candidate.relative_to(canonical_root)
            before_chain = _capture_path_chain(canonical_root, candidate)
        else:
            before_chain = ((candidate, _file_identity(candidate.lstat())),)
        before = candidate.lstat()
        if (
            not stat_module.S_ISREG(before.st_mode)
            or stat_module.S_ISLNK(before.st_mode)
            or _is_reparse_point(before)
            or before.st_nlink > 1
            or before.st_size > max_bytes
        ):
            return None

        descriptor = _open_verified_descriptor(canonical_root, candidate)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat_module.S_ISREG(opened.st_mode)
                or opened.st_nlink > 1
                or opened.st_size > max_bytes
                or _file_identity(opened) != _file_identity(before)
                or opened.st_size != before.st_size
                or opened.st_mtime_ns != before.st_mtime_ns
            ):
                return None
            chunks = []
            remaining = max_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            after_open = os.fstat(descriptor)
            if (
                len(payload) > max_bytes
                or _file_identity(after_open) != _file_identity(opened)
                or after_open.st_size != opened.st_size
                or after_open.st_mtime_ns != opened.st_mtime_ns
            ):
                return None
        finally:
            os.close(descriptor)

        if canonical_root is not None:
            if _capture_path_chain(lexical_root, source) != lexical_chain:
                return None
            after_chain = _capture_path_chain(canonical_root, candidate)
            if after_chain != before_chain:
                return None
            post_resolved = source.resolve(strict=True)
            post_resolved.relative_to(canonical_root)
            if post_resolved != candidate:
                return None
        after_path = candidate.lstat()
        if (
            _file_identity(after_path) != _file_identity(opened)
            or after_path.st_size != after_open.st_size
            or after_path.st_mtime_ns != after_open.st_mtime_ns
        ):
            return None
    except (OSError, ValueError):
        return None

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        if strict_utf8:
            return None
        text = payload.decode("utf-8", errors="ignore")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return _VerifiedText(path=candidate, text=text)


def read_text(
    path: Path, max_bytes: int = MAX_FILE_BYTES, *, root: Path | None = None,
    strict_utf8: bool = False,
) -> str | None:
    verified = _read_verified_text(path, max_bytes=max_bytes, root=root, strict_utf8=strict_utf8)
    return verified.text if verified is not None else None


def extract_symbols(text: str) -> list[str]:
    found = []
    for pattern in SYMBOL_PATTERNS:
        found.extend(match.group(1) for match in pattern.finditer(text))
    return sorted(set(found), key=str.lower)


def extract_imports(text: str) -> list[str]:
    found = []
    for pattern in IMPORT_PATTERNS:
        found.extend(match.group(1) for match in pattern.finditer(text))
    return sorted(set(found), key=str.lower)


def extract_terms(text: str) -> list[str]:
    candidates = re.findall(r"\b[A-Z][A-Za-z0-9_]{2,}\b|`([^`]{2,80})`", text)
    uppercase = re.findall(r"\b[A-Z][A-Za-z0-9_]{2,}\b", text)
    flattened = [item for item in candidates if item] + uppercase
    words = re.findall(r"\b[A-Za-z][A-Za-z0-9_-]{3,}\b", text)
    important = [word for word in words if word.lower() in {"attestation", "release", "memory", "graph", "codex", "context", "agent"}]
    return sorted(set(flattened + important), key=str.lower)[:24]


def chunk_text(text: str, max_chars: int = 1800) -> list[str]:
    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    chunks = []
    current = ""
    for paragraph in paragraphs or [text.strip()]:
        if not current:
            current = paragraph
        elif len(current) + len(paragraph) + 2 <= max_chars:
            current = f"{current}\n\n{paragraph}"
        else:
            chunks.append(current[:max_chars])
            current = paragraph
    if current:
        chunks.append(current[:max_chars])
    return chunks[:80]


def build_file_record(
    root: Path,
    path: Path,
    max_bytes: int = MAX_FILE_BYTES,
    parser_name: str = "regex",
    lsp_command: str = "",
    parser_registry=None,
) -> FileRecord | None:
    verified = _read_verified_text(path, max_bytes=max_bytes, root=root)
    if verified is None:
        return None
    text = verified.text
    from .parsers import ParserRegistry

    registry = parser_registry or ParserRegistry(lsp_command=lsp_command)
    parsed = registry.parse(verified.path, text, parser_name=parser_name)
    return FileRecord(
        path=verified.path,
        relative_path=verified.path.relative_to(root.resolve()).as_posix(),
        text=text,
        sha256=sha256_text(text),
        symbols=parsed.symbols,
        imports=parsed.imports,
        calls=parsed.calls,
        chunks=chunk_text(text),
        parser=parsed.parser,
        parser_warnings=tuple(parsed.warnings),
    )
