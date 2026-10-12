import os
import re
import stat
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

IDENTITY_DIR = ".rta-smriti"
IDENTITY_FILE = "brain_id"
GIT_IDENTITY_FILE = "rta-smriti-brain-id"
GIT_CHECKOUT_IDENTITY_FILE = "rta-smriti-checkout-id"
DEFAULT_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_GIT_CONFIG_OUTPUT_BYTES = 1 * 1024 * 1024
_GIT_READ_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True)
class RepositoryInspection:
    root_key: str
    repository_identity: str | None
    checkout_identity: str | None
    is_git_repo: bool
    repository_root: str | None
    branch: str | None
    head: str | None
    dirty_files: int | None
    remote: str | None
    head_source: str | None

    def state(self) -> dict:
        return {
            "is_git_repo": self.is_git_repo,
            "repository_root": self.repository_root,
            "branch": self.branch,
            "head": self.head,
            "dirty_files": self.dirty_files,
            "remote": self.remote,
            "head_source": self.head_source,
        }


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def canonical_root(path: str | Path) -> str:
    return str(Path(path).expanduser().resolve())


def same_root(left: str | Path, right: str | Path) -> bool:
    return canonical_root_key(left) == canonical_root_key(right)


def canonical_root_key(path: str | Path) -> str:
    return os.path.normcase(canonical_root(path))


def trusted_git_candidates() -> list[Path]:
    if os.name != "nt":
        values = ("/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git", "/opt/local/bin/git")
    else:
        roots = (
            os.environ.get("ProgramFiles") or "C:/Program Files",
            os.environ.get("ProgramFiles(x86)") or "C:/Program Files (x86)",
            os.environ.get("LocalAppData") or str(Path.home() / "AppData" / "Local"),
        )
        values = (
            str(Path(roots[0]) / "Git" / "cmd" / "git.exe"),
            str(Path(roots[0]) / "Git" / "bin" / "git.exe"),
            str(Path(roots[1]) / "Git" / "cmd" / "git.exe"),
            str(Path(roots[2]) / "Programs" / "Git" / "cmd" / "git.exe"),
        )
    candidates = []
    for value in values:
        candidate = Path(value)
        if candidate.is_absolute() and candidate.is_file():
            candidates.append(candidate.resolve())
    return candidates


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update({
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_EXTERNAL_DIFF": "",
        "GCM_INTERACTIVE": "Never",
        "PAGER": "cat",
    })
    return environment


def _run_bounded_capture(
    command: list[str],
    *,
    timeout: float,
    max_output_bytes: int,
    creationflags: int,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str] | None:
    """Capture combined process output without allowing either pipe to grow unbounded."""
    if max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be positive")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creationflags,
        env=environment,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise OSError("bounded process pipes were not created")
    lock = threading.Lock()
    exceeded = threading.Event()
    read_error = threading.Event()
    output: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
    captured_bytes = 0

    def drain(stream, label: str) -> None:
        nonlocal captured_bytes
        try:
            while not exceeded.is_set():
                read_available = getattr(stream, "read1", stream.read)
                chunk = read_available(_GIT_READ_CHUNK_BYTES)
                if not chunk:
                    return
                should_stop = False
                with lock:
                    remaining = max_output_bytes - captured_bytes
                    if len(chunk) > remaining:
                        if remaining > 0:
                            output[label].append(chunk[:remaining])
                            captured_bytes += remaining
                        exceeded.set()
                        should_stop = True
                    else:
                        output[label].append(chunk)
                        captured_bytes += len(chunk)
                if should_stop:
                    try:
                        process.terminate()
                    except OSError:
                        pass
                    return
        except OSError:
            read_error.set()
            try:
                process.terminate()
            except OSError:
                pass

    readers = [
        threading.Thread(target=drain, args=(process.stdout, "stdout"), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, "stderr"), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        for reader in readers:
            reader.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
    if any(reader.is_alive() for reader in readers) or read_error.is_set():
        return None
    if exceeded.is_set():
        return None
    return subprocess.CompletedProcess(
        command,
        returncode,
        b"".join(output["stdout"]).decode("utf-8", errors="replace"),
        b"".join(output["stderr"]).decode("utf-8", errors="replace"),
    )


def _configured_command_keys(
    git: Path, root: Path, environment: dict[str, str],
) -> set[str] | None:
    try:
        result = _run_bounded_capture(
            [
                str(git), "--no-pager", "-C", str(root), "config", "--null", "--name-only",
                "--get-regexp", r"^(filter\..*\.(clean|process|required)|diff\..*\.(command|textconv))$",
            ],
            timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            environment=environment,
            max_output_bytes=MAX_GIT_CONFIG_OUTPUT_BYTES,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result is None:
        return None
    if result.returncode not in (0, 1):
        return None
    return {key.strip() for key in result.stdout.split("\0") if key.strip()}


def _disabled_executable_config(keys: set[str]) -> list[str]:
    drivers: set[tuple[str, str]] = set()
    for key in keys:
        match = re.fullmatch(
            r"(filter|diff)\.(.+)\.(clean|process|required|command|textconv)",
            key,
            flags=re.IGNORECASE,
        )
        if match:
            drivers.add((match.group(1).lower(), match.group(2)))
    options: list[str] = []
    for kind, driver in sorted(drivers):
        if kind == "filter":
            options.extend([
                "-c", f"filter.{driver}.clean=",
                "-c", f"filter.{driver}.process=",
                "-c", f"filter.{driver}.required=false",
            ])
        else:
            options.extend([
                "-c", f"diff.{driver}.command=",
                "-c", f"diff.{driver}.textconv=",
            ])
    return options


def _git_command(
    git: Path,
    root: Path,
    args: tuple[str, ...],
    *,
    hooks_path: Path,
    disable_hooks: bool,
    environment: dict[str, str],
) -> list[str]:
    command = [
        str(git), "--no-pager",
        "-c", "core.fsmonitor=false",
        "-c", "diff.external=",
        "-c", "core.pager=cat",
        "-c", "pager.status=false",
        "-c", "pager.config=false",
        "-c", "interactive.singleKey=false",
    ]
    if disable_hooks:
        command.extend(["-c", f"core.hooksPath={hooks_path}"])
    command_keys = _configured_command_keys(git, root, environment)
    if command_keys is None:
        raise ValueError("Git executable configuration could not be inspected safely")
    command.extend(_disabled_executable_config(command_keys))
    command.extend(["-C", str(root), *args])
    return command


def run_git_inspection(
    root: Path,
    *args: str,
    max_output_bytes: int | None = None,
) -> subprocess.CompletedProcess[str] | None:
    """Run trusted Git with repository-controlled executable features disabled."""
    candidates = trusted_git_candidates()
    if not candidates:
        return None
    resolved = Path(root).expanduser().resolve()
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    environment = _git_environment()
    with tempfile.TemporaryDirectory(prefix="rta-smriti-git-hooks-") as empty_hooks:
        try:
            command = _git_command(
                candidates[0], resolved, tuple(args), hooks_path=Path(empty_hooks),
                disable_hooks=True, environment=environment,
            )
            selected_limit = (
                DEFAULT_GIT_OUTPUT_BYTES
                if max_output_bytes is None
                else max_output_bytes
            )
            return _run_bounded_capture(
                command,
                timeout=8,
                max_output_bytes=selected_limit,
                creationflags=creationflags,
                environment=environment,
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return None


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    return run_git_inspection(root, *args)


def _stdout(root: Path, *args: str) -> str:
    result = _git(root, *args)
    return result.stdout.strip() if result and result.returncode == 0 else ""


def _git_layout(root: Path) -> tuple[Path, Path, Path] | None:
    current = root.resolve()
    for candidate_root in (current, *current.parents):
        marker = candidate_root / ".git"
        if marker.is_dir():
            git_dir = marker.resolve()
        elif marker.is_file():
            try:
                line = marker.read_text(encoding="utf-8", errors="strict").strip()
            except OSError:
                continue
            if not line.lower().startswith("gitdir:"):
                continue
            git_dir = Path(line.split(":", 1)[1].strip())
            if not git_dir.is_absolute():
                git_dir = candidate_root / git_dir
            git_dir = git_dir.resolve()
        else:
            continue
        common_dir = git_dir
        common_marker = git_dir / "commondir"
        if common_marker.is_file():
            value = common_marker.read_text(encoding="utf-8", errors="ignore").strip()
            if value:
                common_dir = Path(value)
                if not common_dir.is_absolute():
                    common_dir = git_dir / common_dir
                common_dir = common_dir.resolve()
        return candidate_root.resolve(), git_dir, common_dir
    return None


def verified_git_layout(root: Path) -> tuple[Path, Path, Path] | None:
    """Return native Git paths only when trusted Git reports the same layout."""
    layout = _git_layout(Path(root).expanduser().resolve())
    if not layout:
        return None
    repository_root, git_dir, common_dir = layout
    result = run_git_inspection(
        repository_root,
        "rev-parse", "--path-format=absolute", "--show-toplevel", "--git-dir", "--git-common-dir",
    )
    if not result or result.returncode != 0:
        return None
    values = [Path(value).expanduser().resolve() for value in result.stdout.splitlines() if value.strip()]
    if len(values) != 3:
        return None
    reported = tuple(canonical_root_key(value) for value in values)
    expected = tuple(canonical_root_key(value) for value in layout)
    if reported != expected:
        return None
    checkout_marker = repository_root / ".git"
    if checkout_marker.is_dir():
        return layout if canonical_root_key(checkout_marker) == canonical_root_key(git_dir) else None
    if not checkout_marker.is_file() or checkout_marker.is_symlink() or _is_reparse_point(checkout_marker):
        return None
    backlink = git_dir / "gitdir"
    if not backlink.is_file() or backlink.is_symlink() or _is_reparse_point(backlink):
        return None
    try:
        backlink_target = Path(backlink.read_text(encoding="utf-8", errors="strict").strip())
    except (OSError, ValueError):
        return None
    if not backlink_target.is_absolute():
        backlink_target = git_dir / backlink_target
    return layout if canonical_root_key(backlink_target) == canonical_root_key(checkout_marker) else None


def configured_hooks_path(root: Path, common_dir: Path) -> Path | None:
    """Read core.hooksPath as data while the inspection process uses disabled hooks."""
    resolved_root = Path(root).expanduser().resolve()
    result = run_git_inspection(
        resolved_root, "config", "--null", "--path", "--get-all", "core.hooksPath",
    )
    if not result or result.returncode != 0:
        return None
    values = [value for value in result.stdout.split("\0") if value]
    if not values:
        return None
    configured_values = values[:-1]
    if not configured_values:
        return common_dir.resolve() / "hooks"
    configured = Path(configured_values[-1]).expanduser()
    if not configured.is_absolute():
        configured = resolved_root / configured
    return configured.resolve()


def _read_ref(common_dir: Path, ref_name: str) -> str | None:
    ref_path = (common_dir / ref_name).resolve()
    try:
        ref_path.relative_to(common_dir.resolve())
        value = ref_path.read_text(encoding="ascii", errors="strict").strip()
    except (OSError, ValueError):
        value = ""
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        return value.lower()
    try:
        lines = (common_dir / "packed-refs").read_text(encoding="ascii", errors="ignore").splitlines()
    except OSError:
        lines = []
    for line in lines:
        if not line or line.startswith(("#", "^")):
            continue
        sha, _, name = line.partition(" ")
        if name == ref_name and re.fullmatch(r"[0-9a-fA-F]{40,64}", sha):
            return sha.lower()
    return None


def _native_head(git_dir: Path, common_dir: Path) -> tuple[str | None, str | None]:
    try:
        value = (git_dir / "HEAD").read_text(encoding="ascii", errors="strict").strip()
    except OSError:
        return None, None
    if value.startswith("ref:"):
        ref_name = value.split(":", 1)[1].strip()
        return ref_name.rsplit("/", 1)[-1], _read_ref(common_dir, ref_name)
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", value):
        return "detached", value.lower()
    return None, None


def _origin_remote(common_dir: Path) -> str | None:
    try:
        config = (common_dir / "config").read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    match = re.search(r'(?ms)^\s*\[remote\s+"origin"\]\s*$.*?^\s*url\s*=\s*(.+?)\s*$', config)
    return match.group(1).strip() if match else None


def _marker_identity(root: Path, create: bool) -> str | None:
    marker_dir = root / IDENTITY_DIR
    marker = marker_dir / IDENTITY_FILE
    if marker_dir.exists() or marker_dir.is_symlink():
        if marker_dir.is_symlink() or _is_reparse_point(marker_dir) or not marker_dir.is_dir():
            raise ValueError(f"repository identity directory is unsafe: {marker_dir}")
    if marker.exists():
        if marker.is_symlink() or marker.stat().st_nlink > 1:
            raise ValueError(f"refusing linked repository identity marker: {marker}")
        value = marker.read_text(encoding="ascii", errors="strict").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            raise ValueError(f"invalid repository identity marker: {marker}")
        return f"local:{value}"
    if not create:
        return None
    marker_dir.mkdir(parents=True, exist_ok=True)
    if marker_dir.is_symlink() or _is_reparse_point(marker_dir) or not marker_dir.is_dir():
        raise ValueError(f"repository identity directory is unsafe: {marker_dir}")
    value = uuid.uuid4().hex
    try:
        with marker.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(value + "\n")
    except FileExistsError:
        return _marker_identity(root, create=False)
    return f"local:{value}"


def _git_marker_identity(common_dir: Path, create: bool) -> str | None:
    marker = common_dir / GIT_IDENTITY_FILE
    if marker.exists():
        if marker.is_symlink() or marker.stat().st_nlink > 1:
            raise ValueError(f"refusing linked repository identity marker: {marker}")
        value = marker.read_text(encoding="ascii", errors="strict").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            raise ValueError(f"invalid repository identity marker: {marker}")
        return f"git-local:{value}"
    if not create:
        return None
    value = uuid.uuid4().hex
    try:
        with marker.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(value + "\n")
    except FileExistsError:
        return _git_marker_identity(common_dir, create=False)
    return f"git-local:{value}"


def _git_checkout_identity(git_dir: Path, create: bool) -> str | None:
    marker = git_dir / GIT_CHECKOUT_IDENTITY_FILE
    if marker.exists():
        if marker.is_symlink() or marker.stat().st_nlink > 1:
            raise ValueError(f"refusing linked checkout identity marker: {marker}")
        value = marker.read_text(encoding="ascii", errors="strict").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", value):
            raise ValueError(f"invalid checkout identity marker: {marker}")
        return f"checkout:{value}"
    if not create:
        return None
    value = uuid.uuid4().hex
    try:
        with marker.open("x", encoding="ascii", newline="\n") as stream:
            stream.write(value + "\n")
    except FileExistsError:
        return _git_checkout_identity(git_dir, create=False)
    return f"checkout:{value}"


def stable_git_identity(root: str | Path) -> str | None:
    """Return the portable first-commit identity for an established Git repo."""
    requested = Path(root).expanduser().resolve()
    layout = _git_layout(requested)
    if not layout:
        return None
    repository_root, _git_dir, _common_dir = layout
    first_commits = _stdout(repository_root, "rev-list", "--max-parents=0", "HEAD").splitlines()
    if first_commits and re.fullmatch(r"[0-9a-fA-F]{40,64}", first_commits[0]):
        return f"git:{first_commits[0].lower()}"
    return None


def repository_identity(root: str | Path, create_marker: bool = True) -> str:
    requested = Path(root).expanduser().resolve()
    if not requested.exists() or not requested.is_dir():
        raise ValueError(f"repository root does not exist or is not a directory: {requested}")
    existing_local_marker = _marker_identity(requested, create=False)
    if existing_local_marker:
        return existing_local_marker
    layout = verified_git_layout(requested)
    if layout:
        repository_root, _git_dir, common_dir = layout
        existing_git_marker = _git_marker_identity(common_dir, create=False)
        if existing_git_marker:
            return existing_git_marker
        stable_identity = stable_git_identity(repository_root)
        if stable_identity:
            return stable_identity
        marker = _git_marker_identity(common_dir, create=create_marker)
        if marker:
            return marker
    elif _git_layout(requested):
        raise ValueError("Git identity verification unavailable; refusing a replacement local identity")
    marker = _marker_identity(requested, create=create_marker)
    if not marker:
        raise ValueError("repository identity is unavailable")
    return marker


def checkout_identity(root: str | Path, create_marker: bool = True) -> str:
    """Return a stable identity for one checkout, distinct across Git worktrees and clones."""
    requested = Path(root).expanduser().resolve()
    if not requested.exists() or not requested.is_dir():
        raise ValueError(f"repository root does not exist or is not a directory: {requested}")
    layout = verified_git_layout(requested)
    if layout:
        _repository_root, git_dir, _common_dir = layout
        marker = _git_checkout_identity(git_dir, create=create_marker)
        if marker:
            return marker
    elif _git_layout(requested):
        raise ValueError("Git checkout verification unavailable; refusing a replacement local identity")
    local_identity = _marker_identity(requested, create=create_marker)
    if not local_identity:
        raise ValueError("checkout identity is unavailable")
    return f"checkout-{local_identity}"


def inspect_repository(root: str | Path | None, include_worktree: bool = True) -> RepositoryInspection:
    """Capture one fail-closed identity and Git-state view for a bounded operation."""
    requested = Path(root).expanduser().resolve() if root else None
    root_key = canonical_root_key(requested) if requested else ""
    if requested is None or not requested.exists() or not requested.is_dir():
        return RepositoryInspection(
            root_key=root_key,
            repository_identity=None,
            checkout_identity=None,
            is_git_repo=False,
            repository_root=None,
            branch=None,
            head=None,
            dirty_files=None,
            remote=None,
            head_source=None,
        )

    local_identity = None
    local_identity_invalid = False
    try:
        local_identity = _marker_identity(requested, create=False)
    except ValueError:
        local_identity_invalid = True

    native_layout = _git_layout(requested)
    verified_layout = verified_git_layout(requested) if native_layout else None
    repository_value = None
    checkout_value = None
    if not local_identity_invalid and local_identity:
        repository_value = local_identity
    elif not local_identity_invalid and verified_layout:
        repository_root, git_dir, common_dir = verified_layout
        git_marker_invalid = False
        try:
            repository_value = _git_marker_identity(common_dir, create=False)
        except ValueError:
            git_marker_invalid = True
        if not repository_value and not git_marker_invalid:
            repository_value = stable_git_identity(repository_root)
    if not local_identity_invalid and verified_layout:
        try:
            checkout_value = _git_checkout_identity(verified_layout[1], create=False)
        except ValueError:
            checkout_value = None
    if checkout_value is None and not local_identity_invalid and local_identity:
        checkout_value = f"checkout-{local_identity}"

    if not native_layout:
        return RepositoryInspection(
            root_key=root_key,
            repository_identity=repository_value,
            checkout_identity=checkout_value,
            is_git_repo=False,
            repository_root=None,
            branch=None,
            head=None,
            dirty_files=None,
            remote=None,
            head_source=None,
        )

    git_root, git_dir, common_dir = native_layout
    branch, full_head = _native_head(git_dir, common_dir)
    dirty_files = None
    if include_worktree:
        status = _git(git_root, "status", "--porcelain=v1", "--untracked-files=normal")
        if status is not None and status.returncode == 0:
            dirty_files = len([line for line in status.stdout.splitlines() if line.strip()])
    return RepositoryInspection(
        root_key=root_key,
        repository_identity=repository_value,
        checkout_identity=checkout_value,
        is_git_repo=True,
        repository_root=str(git_root),
        branch=branch or "unknown",
        head=full_head[:12] if full_head else None,
        dirty_files=dirty_files,
        remote=_origin_remote(common_dir),
        head_source="native",
    )


def repository_state(root: str | Path | None, include_worktree: bool = True) -> dict:
    empty = {
        "is_git_repo": False, "repository_root": None, "branch": None,
        "head": None, "dirty_files": None, "remote": None, "head_source": None,
    }
    if not root:
        return empty
    requested = Path(root).expanduser().resolve()
    if not requested.exists() or not requested.is_dir():
        return empty
    layout = _git_layout(requested)
    if not layout:
        return empty
    git_root, git_dir, common_dir = layout
    branch, full_head = _native_head(git_dir, common_dir)
    dirty_files = None
    if include_worktree:
        status = _git(git_root, "status", "--porcelain=v1", "--untracked-files=normal")
        if status is not None and status.returncode == 0:
            dirty_files = len([line for line in status.stdout.splitlines() if line.strip()])
    return {
        "is_git_repo": True,
        "repository_root": str(git_root),
        "branch": branch or "unknown",
        "head": full_head[:12] if full_head else None,
        "dirty_files": dirty_files,
        "remote": _origin_remote(common_dir),
        "head_source": "native",
    }
