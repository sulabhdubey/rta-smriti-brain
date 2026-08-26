"""Private, bounded filesystem spool for passive capture ingress."""

from __future__ import annotations

import csv
import ctypes
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from .capture_types import canonical_json
from .privacy import is_sensitive_field_name, redact_sensitive_text
from .runtime_control import is_safe_regular_file

_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_RECORD_RE = re.compile(r"^[0-9a-f]{32}\.json$")
_ROOT_TEMP_RE = re.compile(r"^\.(?:registry|usage)\.json\.\d+\.[0-9a-f]{32}\.tmp$")
class SpoolError(RuntimeError):
    """Base capture-spool failure."""


class SpoolUnsafeError(SpoolError):
    """The spool or record failed a local filesystem safety invariant."""


class SpoolBusyError(SpoolError):
    """Another capture process currently owns the short-lived usage lock."""


class SpoolPostCommitError(SpoolError):
    """A filesystem mutation committed before its durability barrier failed."""


@dataclass(frozen=True)
class SpoolLimits:
    max_record_bytes: int = 1_048_576
    max_source_bytes: int = 104_857_600
    max_source_records: int = 10_000
    max_total_bytes: int = 524_288_000
    max_total_records: int = 50_000
    max_sources: int = 1_024
    max_quarantine_bytes: int = 104_857_600
    max_quarantine_records: int = 1_000
    max_receipt_bytes: int = 10_485_760
    max_receipt_records: int = 10_000
    max_json_depth: int = 12
    max_json_items: int = 10_000

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_source_bytes > self.max_total_bytes:
            raise ValueError("max_source_bytes cannot exceed max_total_bytes")
        if self.max_source_records > self.max_total_records:
            raise ValueError("max_source_records cannot exceed max_total_records")


@dataclass(frozen=True)
class SpoolReceipt:
    status: str
    source_token: str
    record_id: str | None = None
    stored_bytes: int = 0
    reason: str | None = None
    path: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            key: value
            for key, value in {
                "status": self.status,
                "source_token": self.source_token,
                "record_id": self.record_id,
                "stored_bytes": self.stored_bytes,
                "reason": self.reason,
            }.items()
            if value is not None
        }


@dataclass(frozen=True)
class SpoolClaim:
    source_token: str
    record_id: str
    path: Path
    payload: dict[str, Any]
    identity: tuple[int, int, int, int]
    content_sha256: str


@dataclass(frozen=True)
class RecoveryReceipt:
    recovered: int
    quarantined: int
    skipped: int
    limited: bool = False


def source_token(source_id: str, *, project: str | None = None) -> str:
    if not isinstance(source_id, str) or not source_id.strip():
        raise ValueError("source_id must be a non-empty string")
    if project is not None and (not isinstance(project, str) or not project.strip()):
        raise ValueError("project must be a non-empty string when provided")
    if project is None:
        namespace = b"rta-smriti-capture-source-v1\0" + source_id.strip().encode("utf-8")
    else:
        namespace = (
            b"rta-smriti-capture-source-v2\0"
            + project.strip().encode("utf-8")
            + b"\0"
            + source_id.strip().encode("utf-8")
        )
    return hashlib.sha256(
        namespace
    ).hexdigest()[:32]


def capture_control_root_path(brain_path: Path) -> Path:
    """Return a privacy-safe control path without creating it."""

    database = Path(brain_path).expanduser().resolve()
    key = hashlib.sha256(
        b"rta-smriti-capture-control-v1\0" + str(database).encode("utf-8")
    ).hexdigest()[:32]
    return database.parent / ".rta-smriti-control" / key


def capture_spool_root_path(brain_path: Path) -> Path:
    """Return the isolated privacy-safe spool path for one brain database."""

    database = Path(brain_path).expanduser().resolve()
    key = hashlib.sha256(
        b"rta-smriti-capture-spool-v2\0" + str(database).encode("utf-8")
    ).hexdigest()[:32]
    return database.parent / ".rta-smriti-capture" / key


def ensure_capture_control_root(brain_path: Path) -> Path:
    """Create a brain-keyed private namespace outside the record spool."""

    root = capture_control_root_path(brain_path)
    _ensure_private_directory(root.parent)
    _ensure_private_directory(root)
    return root


def read_capture_spool_usage(
    brain_path: Path,
    *,
    source_tokens: Iterable[str] | None = None,
) -> dict[str, int]:
    """Read persisted occupancy without creating or repairing spool state."""

    selected_tokens = None
    if source_tokens is not None:
        selected_tokens = frozenset(source_tokens)
        if len(selected_tokens) > 1_024 or any(
            not isinstance(token, str) or not _TOKEN_RE.fullmatch(token)
            for token in selected_tokens
        ):
            raise ValueError("capture spool source tokens are invalid")
    transient_messages = {
        "capture spool usage receipt is missing",
        "capture spool usage receipt is unsafe",
        "capture spool usage receipt changed during inspection",
    }
    max_attempts = 8
    for attempt in range(max_attempts):
        try:
            if selected_tokens is None:
                return _read_capture_spool_usage_once(brain_path)
            return _read_capture_spool_usage_once(
                brain_path,
                source_tokens=selected_tokens,
            )
        except SpoolUnsafeError as exc:
            if str(exc) not in transient_messages or attempt == max_attempts - 1:
                raise
            time.sleep(min(0.005 * (2**attempt), 0.05))
    raise AssertionError("bounded capture usage read exhausted unexpectedly")


def _read_capture_spool_usage_once(
    brain_path: Path,
    *,
    source_tokens: frozenset[str] | None = None,
) -> dict[str, int]:
    """Perform one fail-closed stable read of the spool usage receipt."""

    root = capture_spool_root_path(brain_path)
    if not root.exists():
        return {"total_records": 0, "total_bytes": 0, "source_count": 0}
    info = root.lstat()
    if root.is_symlink() or _is_reparse_point(root) or not stat.S_ISDIR(info.st_mode):
        raise SpoolUnsafeError("capture spool directory is linked or not a directory")
    usage_path = root / "usage.json"
    if not usage_path.exists():
        raise SpoolUnsafeError("capture spool usage receipt is missing")
    if not is_safe_regular_file(usage_path) or usage_path.stat().st_size > 1_048_576:
        raise SpoolUnsafeError("capture spool usage receipt is unsafe")
    before = usage_path.stat()
    with usage_path.open("rb") as stream:
        raw = stream.read(1_048_577)
    after = usage_path.stat()
    if len(raw) > 1_048_576 or (before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SpoolUnsafeError("capture spool usage receipt changed during inspection")
    try:
        usage = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SpoolUnsafeError("capture spool usage receipt is malformed") from exc
    sources = usage.get("sources") if isinstance(usage, dict) else None
    total_records = usage.get("total_records") if isinstance(usage, dict) else None
    total_bytes = usage.get("total_bytes") if isinstance(usage, dict) else None
    if (
        not isinstance(sources, dict)
        or type(total_records) is not int
        or total_records < 0
        or type(total_bytes) is not int
        or total_bytes < 0
        or len(sources) > 1_024
    ):
        raise SpoolUnsafeError("capture spool usage receipt is malformed")
    if source_tokens is None:
        return {
            "total_records": total_records,
            "total_bytes": total_bytes,
            "source_count": len(sources),
        }
    selected = []
    for token in source_tokens:
        entry = sources.get(token)
        if entry is None:
            continue
        if not isinstance(entry, dict):
            raise SpoolUnsafeError("capture spool usage source is malformed")
        records = entry.get("records")
        byte_count = entry.get("bytes")
        if (
            type(records) is not int
            or records < 0
            or type(byte_count) is not int
            or byte_count < 0
        ):
            raise SpoolUnsafeError("capture spool usage source is malformed")
        selected.append((records, byte_count))
    return {
        "total_records": sum(records for records, _ in selected),
        "total_bytes": sum(byte_count for _, byte_count in selected),
        "source_count": len(selected),
    }


def _is_reparse_point(path: Path) -> bool:
    try:
        return bool(int(getattr(path.lstat(), "st_file_attributes", 0)) & 0x400)
    except OSError:
        return False


@lru_cache(maxsize=1)
def _windows_system_directory() -> Path:
    if os.name != "nt":
        raise RuntimeError("Windows system directory lookup is only available on Windows")
    from ctypes import wintypes

    get_system_directory = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetSystemDirectoryW
    get_system_directory.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    get_system_directory.restype = wintypes.UINT
    capacity = 260
    while capacity <= 32_768:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = get_system_directory(buffer, capacity)
        if length == 0:
            raise SpoolUnsafeError("cannot resolve the Windows system directory")
        if length < capacity:
            directory = Path(buffer.value)
            try:
                info = directory.lstat()
            except OSError as exc:
                raise SpoolUnsafeError(
                    "Windows system directory is unavailable"
                ) from exc
            if (
                not directory.is_absolute()
                or directory.is_symlink()
                or _is_reparse_point(directory)
                or not stat.S_ISDIR(info.st_mode)
            ):
                raise SpoolUnsafeError("Windows system directory is unsafe")
            return directory
        capacity = length + 1
    raise SpoolUnsafeError("Windows system directory path is too long")


def _windows_system_executable(name: str) -> Path:
    if name not in {"icacls.exe", "whoami.exe"}:
        raise SpoolUnsafeError("Windows system executable is not allowlisted")
    executable = _windows_system_directory() / name
    try:
        info = executable.lstat()
    except OSError as exc:
        raise SpoolUnsafeError("Windows system executable is unavailable") from exc
    if (
        executable.is_symlink()
        or _is_reparse_point(executable)
        or not stat.S_ISREG(info.st_mode)
    ):
        raise SpoolUnsafeError("Windows system executable is unsafe")
    return executable


@lru_cache(maxsize=1)
def _windows_current_user_sid() -> str:
    if os.name != "nt":
        raise RuntimeError("Windows SID lookup is only available on Windows")
    completed = subprocess.run(
        [str(_windows_system_executable("whoami.exe")), "/user", "/fo", "csv", "/nh"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        creationflags=0x08000000,
    )
    if completed.returncode != 0:
        raise SpoolUnsafeError("cannot resolve the current Windows user SID")
    rows = list(csv.reader(completed.stdout.splitlines()))
    if len(rows) != 1 or len(rows[0]) < 2 or not rows[0][1].startswith("S-1-"):
        raise SpoolUnsafeError("current Windows user SID is malformed")
    return rows[0][1]


def _windows_security_descriptor(path: Path) -> str:
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_info = advapi32.GetNamedSecurityInfoW
    get_info.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_info.restype = wintypes.DWORD
    convert = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    convert.restype = wintypes.BOOL
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = get_info(
        str(path),
        1,
        0x00000001 | 0x00000004,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result != 0:
        raise SpoolUnsafeError("cannot inspect the Windows capture ACL")
    text_pointer = ctypes.c_void_p()
    try:
        if not convert(
            descriptor,
            1,
            0x00000001 | 0x00000004,
            ctypes.byref(text_pointer),
            None,
        ):
            raise SpoolUnsafeError("cannot serialize the Windows capture ACL")
        return ctypes.wstring_at(text_pointer)
    finally:
        if text_pointer:
            kernel32.LocalFree(text_pointer)
        if descriptor:
            kernel32.LocalFree(descriptor)


def windows_path_privacy_failure(path: Path) -> str | None:
    if os.name != "nt":
        return None
    try:
        sddl = _windows_security_descriptor(Path(path))
        current_sid = _windows_current_user_sid()
        return _windows_sddl_privacy_failure(sddl, current_sid)
    except (OSError, SpoolError, subprocess.SubprocessError):
        return "inspection_unavailable"


def windows_path_is_private(path: Path) -> bool:
    return windows_path_privacy_failure(path) is None


def _windows_sddl_privacy_failure(sddl: str, current_sid: str) -> str | None:
    owner = re.match(r"^O:(.*?)(?=G:|D:|S:)", sddl)
    if owner is None:
        return "owner_missing"
    owner_principal = owner.group(1)
    allowed_owner_sids = {current_sid, "S-1-5-32-544"}
    if owner_principal == "BA":
        owner_sid = "S-1-5-32-544"
    elif owner_principal.startswith("S-1-"):
        owner_sid = owner_principal
    elif os.name == "nt":
        try:
            owner_sid = _windows_sddl_alias_sid(owner_principal)
        except SpoolError:
            return "owner_alias_unresolved"
    else:
        return "owner_mismatch_alias"
    if owner_sid not in allowed_owner_sids:
        return "owner_mismatch"
    allowed_aliases = {"SY", "BA", "OW"}
    allowed_sids = {current_sid, "S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
    aces = re.findall(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)", sddl)
    if not aces:
        return "allow_ace_missing"
    principals: set[str] = set()
    for ace in aces:
        fields = ace.split(";")
        if len(fields) < 6:
            return "ace_malformed"
        ace_type = fields[0]
        principal = fields[5]
        if ace_type in {"D", "OD"}:
            continue
        if ace_type not in {"A", "OA"}:
            return "ace_type_unsupported"
        principals.add(principal)
    if not principals:
        return "allow_ace_missing"
    for principal in principals:
        if principal in allowed_aliases or principal in allowed_sids:
            continue
        if os.name == "nt" and not principal.startswith("S-1-"):
            try:
                if _windows_sddl_alias_sid(principal) in allowed_sids:
                    continue
            except SpoolError:
                pass
        return "foreign_allow_principal"
    return None


def _windows_sddl_is_private(sddl: str, current_sid: str) -> bool:
    return _windows_sddl_privacy_failure(sddl, current_sid) is None


def _windows_sddl_alias_sid(principal: str) -> str:
    """Resolve any valid SDDL trustee alias to its canonical SID string."""

    if os.name != "nt":  # pragma: no cover - Windows-only helper
        raise SpoolUnsafeError("Windows SDDL alias resolution is unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert_descriptor = (
        advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    )
    convert_descriptor.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert_descriptor.restype = wintypes.BOOL
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_dacl.restype = wintypes.BOOL
    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_ace.restype = wintypes.BOOL
    convert_sid = advapi32.ConvertSidToStringSidW
    convert_sid.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert_sid.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    descriptor = ctypes.c_void_p()
    sid_text = ctypes.c_void_p()
    try:
        sddl = f"D:(A;;GA;;;{principal})"
        if not convert_descriptor(sddl, 1, ctypes.byref(descriptor), None):
            raise SpoolUnsafeError(
                "cannot safely resolve a Windows ACL principal"
            )
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not get_dacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        ) or not present or not dacl:
            raise SpoolUnsafeError("cannot inspect a Windows ACL principal")
        ace = ctypes.c_void_p()
        if not get_ace(dacl, 0, ctypes.byref(ace)) or not ace:
            raise SpoolUnsafeError("cannot inspect a Windows ACL principal")
        # ACCESS_ALLOWED_ACE stores SidStart after ACE_HEADER and ACCESS_MASK.
        sid_pointer = ctypes.c_void_p(int(ace.value) + 8)
        if not convert_sid(sid_pointer, ctypes.byref(sid_text)):
            raise SpoolUnsafeError(
                "cannot serialize a Windows ACL principal"
            )
        return ctypes.wstring_at(sid_text)
    finally:
        if sid_text:
            kernel32.LocalFree(sid_text)
        if descriptor:
            kernel32.LocalFree(descriptor)


def _windows_foreign_allow_sids(sddl: str, current_sid: str) -> tuple[str, ...]:
    allowed_aliases = {"SY", "BA", "OW"}
    allowed_sids = {current_sid, "S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
    foreign: set[str] = set()
    for ace in re.findall(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)", sddl):
        fields = ace.split(";")
        if len(fields) < 6 or fields[0] not in {"A", "OA"}:
            continue
        principal = fields[5]
        if principal in allowed_aliases or principal in allowed_sids:
            continue
        if principal.startswith("S-1-"):
            foreign.add(principal)
            continue
        resolved = _windows_sddl_alias_sid(principal)
        if resolved not in allowed_sids:
            foreign.add(resolved)
    return tuple(sorted(foreign))


def _run_icacls(arguments: list[str]) -> None:
    completed = subprocess.run(
        [str(_windows_system_executable("icacls.exe")), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=0x08000000,
    )
    if completed.returncode != 0:
        raise SpoolUnsafeError("cannot enforce a private Windows capture ACL")


def ensure_windows_path_private(path: Path) -> None:
    """Remove inherited broad ACLs and grant only the current user and administrators."""

    if os.name != "nt" or windows_path_is_private(path):
        return
    sid = _windows_current_user_sid()
    inheritance = "(OI)(CI)F" if Path(path).is_dir() else "F"
    # Hosted runners and enterprise-managed temp roots may create children whose
    # owner is Administrators or a service account. Reaffirming an unchanged
    # owner can fail on otherwise valid owner-controlled roots, so only claim
    # ownership when the descriptor is genuinely owned by another principal.
    initial_sddl = _windows_security_descriptor(Path(path))
    owner = re.match(r"^O:(.*?)(?=G:|D:|S:)", initial_sddl)
    owner_sid = None
    if owner is not None:
        owner_principal = owner.group(1)
        if owner_principal == "BA":
            owner_sid = "S-1-5-32-544"
        elif owner_principal.startswith("S-1-"):
            owner_sid = owner_principal
        else:
            try:
                owner_sid = _windows_sddl_alias_sid(owner_principal)
            except SpoolError:
                owner_sid = None
    if owner_sid not in {sid, "S-1-5-32-544"}:
        _run_icacls([str(path), "/setowner", f"*{sid}"])
    _run_icacls([str(path), "/inheritance:r"])
    # Removing inheritance can delete broad ACEs outright. Inspect the resulting
    # descriptor so we only remove explicit foreign grants that still exist.
    sddl = _windows_security_descriptor(Path(path))
    for foreign_sid in _windows_foreign_allow_sids(sddl, sid):
        _run_icacls([str(path), "/remove:g", f"*{foreign_sid}"])
    _run_icacls(
        [
            str(path),
            "/grant:r",
            f"*{sid}:{inheritance}",
            f"*S-1-5-18:{inheritance}",
            f"*S-1-5-32-544:{inheritance}",
        ]
    )
    final_sddl = _windows_security_descriptor(Path(path))
    failure = _windows_sddl_privacy_failure(final_sddl, sid)
    if failure is not None:
        raise SpoolUnsafeError(
            f"cannot enforce a private Windows capture ACL: {failure}"
        )


def _harden_windows_directory(path: Path) -> None:
    ensure_windows_path_private(path)


def _ensure_private_directory(path: Path) -> None:
    created = False
    try:
        path.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    try:
        info = path.lstat()
    except OSError as exc:
        raise SpoolUnsafeError("capture spool directory is unavailable") from exc
    if path.is_symlink() or _is_reparse_point(path) or not stat.S_ISDIR(info.st_mode):
        raise SpoolUnsafeError("capture spool directory is linked or not a directory")
    if os.name == "nt":
        if created:
            _harden_windows_directory(path)
        elif not windows_path_is_private(path):
            raise SpoolUnsafeError("capture spool directory ACL is not private")
    else:
        if info.st_uid != os.getuid():
            raise SpoolUnsafeError("capture spool directory owner mismatch")
        if not created and info.st_mode & 0o077:
            raise SpoolUnsafeError("capture spool directory is not private")
        path.chmod(0o700)


def _directory_fsync(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_path(source: Path, destination: Path, *, replace: bool) -> None:
    if os.name != "nt":
        if replace:
            os.replace(source, destination)
            return
        libc = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            renameat2 = getattr(libc, "renameat2", None)
            if renameat2 is not None:
                renameat2.argtypes = [
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_int,
                    ctypes.c_char_p,
                    ctypes.c_uint,
                ]
                renameat2.restype = ctypes.c_int
                result = renameat2(
                    -100,
                    os.fsencode(source),
                    -100,
                    os.fsencode(destination),
                    1,  # RENAME_NOREPLACE
                )
                if result == 0:
                    return
                error = ctypes.get_errno()
                if error == errno.EEXIST:
                    raise FileExistsError(
                        error, "destination already exists", destination
                    )
                raise OSError(error, "exclusive POSIX rename failed", destination)
        elif sys.platform == "darwin":
            renamex_np = getattr(libc, "renamex_np", None)
            if renamex_np is not None:
                renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
                renamex_np.restype = ctypes.c_int
                if (
                    renamex_np(
                        os.fsencode(source), os.fsencode(destination), 0x00000004
                    )
                    == 0
                ):
                    return
                error = ctypes.get_errno()
                if error == errno.EEXIST:
                    raise FileExistsError(
                        error, "destination already exists", destination
                    )
                raise OSError(error, "exclusive macOS rename failed", destination)
        raise SpoolUnsafeError(
            "exclusive atomic rename is unavailable on this platform"
        )
    from ctypes import wintypes

    move_file = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
    move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move_file.restype = wintypes.BOOL
    flags = 0x00000008  # MOVEFILE_WRITE_THROUGH
    if replace:
        flags |= 0x00000001  # MOVEFILE_REPLACE_EXISTING
    if not move_file(str(source), str(destination), flags):
        error = ctypes.get_last_error()
        if error in {80, 183}:
            raise FileExistsError(
                errno.EEXIST, "destination already exists", destination
            )
        if error == 17:
            raise OSError(errno.EXDEV, "cross-device link", destination)
        raise OSError(error, "durable Windows rename failed", destination)


def _move_no_replace(source: Path, destination: Path) -> None:
    _replace_path(source, destination, replace=False)
    _directory_fsync(destination.parent)
    if destination.parent != source.parent:
        _directory_fsync(source.parent)


def _finish_interrupted_link_move(source: Path, destination: Path) -> bool:
    """Repair records stranded by the pre-v0.9 POSIX link/unlink move."""
    try:
        source_info = source.lstat()
        destination_info = destination.lstat()
    except FileNotFoundError:
        return False
    if (
        stat.S_ISLNK(source_info.st_mode)
        or stat.S_ISLNK(destination_info.st_mode)
        or not stat.S_ISREG(source_info.st_mode)
        or not stat.S_ISREG(destination_info.st_mode)
        or source_info.st_dev != destination_info.st_dev
        or source_info.st_ino != destination_info.st_ino
        or source_info.st_nlink != 2
        or destination_info.st_nlink != 2
    ):
        return False
    if destination.parent != source.parent:
        _directory_fsync(destination.parent)
    source.unlink()
    _directory_fsync(source.parent)
    return True


def _find_interrupted_link_destination(source: Path, directory: Path) -> Path | None:
    try:
        source_info = source.lstat()
    except FileNotFoundError:
        return None
    if (
        stat.S_ISLNK(source_info.st_mode)
        or not stat.S_ISREG(source_info.st_mode)
        or source_info.st_nlink != 2
    ):
        return None
    matched = None
    with os.scandir(directory) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False):
                continue
            destination_info = entry.stat(follow_symlinks=False)
            if (
                destination_info.st_dev == source_info.st_dev
                and destination_info.st_ino == source_info.st_ino
                and destination_info.st_nlink == 2
            ):
                if matched is not None:
                    raise SpoolUnsafeError(
                        "capture record has multiple linked destinations"
                    )
                matched = Path(entry.path)
    return matched


def _open_read_no_follow(path: Path) -> int:
    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        return os.open(path, flags)
    import msvcrt
    from ctypes import wintypes

    create_file = ctypes.WinDLL("kernel32", use_last_error=True).CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,  # GENERIC_READ
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,  # OPEN_EXISTING
        0x00000080 | 0x00200000,  # NORMAL | OPEN_REPARSE_POINT
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(
            ctypes.get_last_error(), "cannot safely open capture record", path
        )
    try:
        return msvcrt.open_osfhandle(
            int(handle),
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except BaseException:
        ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        raise


def _atomic_write(path: Path, data: bytes, *, durable: bool = True) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        committed = False
        try:
            _replace_path(temporary, path, replace=True)
            committed = True
        except OSError as exc:
            if exc.errno == getattr(os, "EXDEV", 18):
                raise SpoolUnsafeError(
                    "capture records must remain on the same filesystem"
                ) from exc
            raise
        if durable:
            try:
                _directory_fsync(path.parent)
            except OSError as exc:
                if committed:
                    raise SpoolPostCommitError(
                        "capture write committed before its durability barrier failed"
                    ) from exc
                raise
    finally:
        temporary.unlink(missing_ok=True)


def _validate_json_shape(value: Any, *, max_depth: int, max_items: int) -> None:
    pending = [(value, 1)]
    seen_items = 0
    while pending:
        current, depth = pending.pop()
        if depth > max_depth:
            raise ValueError("capture JSON exceeds the configured depth")
        if isinstance(current, Mapping):
            seen_items += len(current)
            if seen_items > max_items:
                raise ValueError("capture JSON exceeds the configured item count")
            for key, child in current.items():
                if not isinstance(key, str):
                    raise TypeError("capture JSON object keys must be strings")
                pending.append((child, depth + 1))
        elif isinstance(current, (list, tuple)):
            seen_items += len(current)
            if seen_items > max_items:
                raise ValueError("capture JSON exceeds the configured item count")
            pending.extend((child, depth + 1) for child in current)
        elif current is None or isinstance(current, (str, int, float, bool)):
            continue
        else:
            raise TypeError(f"unsupported capture JSON value: {type(current).__name__}")


def _sanitize_value(value: Any, *, key: str | None = None) -> Any:
    if key is not None and is_sensitive_field_name(key, include_containers=True):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for child_key, child in value.items():
            raw_key = str(child_key)
            sanitized_key = redact_sensitive_text(raw_key)[0]
            if sanitized_key in sanitized:
                raise ValueError("capture key collision after redaction")
            sanitized[sanitized_key] = _sanitize_value(child, key=raw_key)
        return sanitized
    if isinstance(value, (list, tuple)):
        return [_sanitize_value(child) for child in value]
    if isinstance(value, str):
        return redact_sensitive_text(value)[0]
    return value


def _sanitize_record(
    record: Mapping[str, Any],
    allowed_fields: Iterable[str] | None,
) -> dict[str, Any]:
    if allowed_fields is None or isinstance(allowed_fields, (str, bytes)):
        raise ValueError("capture publication requires an explicit field allowlist")
    fields = tuple(allowed_fields)
    if not fields or len(fields) > 1_000:
        raise ValueError("capture field allowlist must contain 1 to 1,000 fields")
    if any(
        not isinstance(field, str) or not field or len(field) > 200 for field in fields
    ):
        raise ValueError("capture field allowlist contains an invalid field")
    allowed = set(fields)
    return {
        str(key): _sanitize_value(value, key=str(key))
        for key, value in record.items()
        if str(key) in allowed
    }


class CaptureSpool:
    """Publish and consume bounded capture records without exposing source names."""

    def __init__(self, brain_path: Path, *, limits: SpoolLimits | None = None):
        self.brain_path = Path(brain_path).expanduser().resolve()
        self.root = capture_spool_root_path(self.brain_path)
        self.limits = limits or SpoolLimits()
        _ensure_private_directory(self.root.parent)
        _ensure_private_directory(self.root)
        self._cleanup_root_temporaries(older_than_seconds=30.0)
        registry = self.root / "registry.json"
        if registry.exists() and not is_safe_regular_file(registry):
            raise SpoolUnsafeError("capture registry is linked or unsafe")
        if not registry.exists():
            _atomic_write(
                registry,
                b'{"schema":"rta-smriti.capture-spool/v1"}\n',
            )
        self._usage_path = self.root / "usage.json"
        self._usage_lock_path = self.root / ".usage.lock"
        if not self._usage_path.exists():
            with self._usage_lock():
                if not self._usage_path.exists():
                    self._write_usage_locked(self._scan_usage())

    def ensure_source(
        self, source_id: str, *, project: str | None = None
    ) -> dict[str, Path]:
        token = source_token(source_id, project=project)
        root = self.root / token
        _ensure_private_directory(self.root)
        if not root.exists():
            with self._usage_lock():
                if not root.exists():
                    source_roots = self._source_roots()
                    if len(source_roots) >= self.limits.max_sources:
                        raise SpoolUnsafeError("capture source budget is full")
                    _ensure_private_directory(root)
        return self._validated_source_paths(root)

    def publish(
        self,
        source_id: str,
        record: Mapping[str, Any],
        *,
        project: str | None = None,
        allowed_fields: Iterable[str] | None = None,
    ) -> SpoolReceipt:
        try:
            return self.publish_strict(
                source_id,
                record,
                project=project,
                allowed_fields=allowed_fields,
            )
        except (TypeError, ValueError):
            token = (
                source_token(source_id, project=project)
                if isinstance(source_id, str) and source_id.strip()
                else "invalid"
            )
            return SpoolReceipt("rejected", token, reason="invalid_record")
        except SpoolBusyError:
            return SpoolReceipt(
                "unavailable", source_token(source_id, project=project), reason="spool_busy"
            )
        except (OSError, SpoolError, subprocess.SubprocessError) as exc:
            reason = "filesystem_unavailable"
            if isinstance(exc, SpoolUnsafeError) and not (
                isinstance(exc.__cause__, OSError)
                and exc.__cause__.errno
                in {getattr(os, "EXDEV", 18), errno.ENOSPC, errno.EACCES, errno.EPERM}
            ):
                reason = "unsafe_spool"
            return SpoolReceipt(
                "unavailable", source_token(source_id, project=project), reason=reason
            )

    def publish_strict(
        self,
        source_id: str,
        record: Mapping[str, Any],
        *,
        project: str | None = None,
        allowed_fields: Iterable[str] | None,
    ) -> SpoolReceipt:
        if not isinstance(record, Mapping):
            raise TypeError("capture record must be an object")
        _validate_json_shape(
            record,
            max_depth=self.limits.max_json_depth,
            max_items=self.limits.max_json_items,
        )
        sanitized = _sanitize_record(record, allowed_fields)
        _validate_json_shape(
            sanitized,
            max_depth=self.limits.max_json_depth,
            max_items=self.limits.max_json_items,
        )
        encoded = (canonical_json(sanitized) + "\n").encode("utf-8")
        token = source_token(source_id, project=project)
        if len(encoded) > self.limits.max_record_bytes:
            return SpoolReceipt(
                "rejected", token, stored_bytes=0, reason="record_too_large"
            )
        paths = self.ensure_source(source_id, project=project)
        with self._usage_lock():
            usage = self._load_usage_locked(persist_reconciliation=False)
            source_usage = self._ensure_usage_source(usage, token, paths["root"])
            if source_usage["records"] >= self.limits.max_source_records:
                return SpoolReceipt("full", token, reason="source_record_budget")
            if source_usage["bytes"] + len(encoded) > self.limits.max_source_bytes:
                return SpoolReceipt("full", token, reason="source_byte_budget")
            if usage["total_records"] >= self.limits.max_total_records:
                return SpoolReceipt("full", token, reason="total_record_budget")
            if usage["total_bytes"] + len(encoded) > self.limits.max_total_bytes:
                return SpoolReceipt("full", token, reason="total_byte_budget")
            record_id = uuid.uuid4().hex
            destination = paths["inbox"] / f"{record_id}.json"
            reservation = {
                "operation": "add",
                "source_token": token,
                "bytes": len(encoded),
            }
            usage["pending"][record_id] = reservation
            self._adjust_usage(usage, token, records=1, byte_count=len(encoded))
            self._write_usage_locked(usage)
            try:
                _atomic_write(destination, encoded)
            except SpoolPostCommitError:
                raise
            except BaseException:
                usage["pending"].pop(record_id, None)
                self._adjust_usage(usage, token, records=-1, byte_count=-len(encoded))
                self._refresh_usage_signature(usage, token, paths["root"])
                self._write_usage_locked(usage)
                raise
            usage["pending"].pop(record_id, None)
            self._refresh_usage_signature(usage, token, paths["root"])
            self._write_usage_locked(usage)
        return SpoolReceipt("stored", token, record_id, len(encoded))

    def claim_next(
        self, source_id: str, *, project: str | None = None
    ) -> SpoolClaim | None:
        paths = self.ensure_source(source_id, project=project)
        token = source_token(source_id, project=project)
        with os.scandir(paths["inbox"]) as entries:
            candidates = (Path(entry.path) for entry in entries)
            for candidate in candidates:
                if not _RECORD_RE.fullmatch(candidate.name):
                    self._quarantine_path(paths, candidate, "unsafe_filename")
                    continue
                processing = paths["processing"] / candidate.name
                with self._usage_lock():
                    if processing.exists():
                        if not _finish_interrupted_link_move(candidate, processing):
                            raise SpoolUnsafeError("duplicate processing record")
                    else:
                        if not is_safe_regular_file(candidate):
                            raise SpoolUnsafeError("capture record changed before claim")
                        try:
                            _move_no_replace(candidate, processing)
                        except FileExistsError as exc:
                            raise SpoolUnsafeError("duplicate processing record") from exc
                    usage = self._load_usage_locked(persist_reconciliation=False)
                    self._ensure_usage_source(usage, token, paths["root"])
                    self._refresh_usage_signature(usage, token, paths["root"])
                    self._write_usage_locked(usage)
                try:
                    data, identity = self._stable_read(processing)
                    payload = json.loads(data.decode("utf-8"))
                    if not isinstance(payload, dict):
                        raise TypeError("capture record must contain an object")
                    _validate_json_shape(
                        payload,
                        max_depth=self.limits.max_json_depth,
                        max_items=self.limits.max_json_items,
                    )
                except (
                    OSError,
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    TypeError,
                    ValueError,
                ):
                    self._quarantine_path(paths, processing, "malformed_record")
                    continue
                return SpoolClaim(
                    token,
                    candidate.stem,
                    processing,
                    payload,
                    identity,
                    hashlib.sha256(data).hexdigest(),
                )
        return None

    def complete(self, claim: SpoolClaim) -> SpoolReceipt:
        paths = self._paths_for_token(claim.source_token)
        if claim.path.parent != paths["processing"]:
            raise SpoolUnsafeError("claim path is outside its processing directory")
        receipt_payload = {
            "record_id": claim.record_id,
            "source_token": claim.source_token,
            "status": "complete",
        }
        receipt_bytes = (canonical_json(receipt_payload) + "\n").encode("ascii")
        receipt_path = paths["receipts"] / f"{claim.record_id}.json"
        with self._usage_lock():
            usage = self._load_usage_locked(persist_reconciliation=False)
            self._ensure_usage_source(usage, claim.source_token, paths["root"])
            if not receipt_path.exists():
                self._ensure_completed_receipt_capacity(
                    added_bytes=len(receipt_bytes),
                    preserve=receipt_path,
                )
            data, identity = self._stable_read(claim.path)
            if (
                identity != claim.identity
                or hashlib.sha256(data).hexdigest() != claim.content_sha256
            ):
                raise SpoolUnsafeError("capture record changed after it was claimed")
            _atomic_write(receipt_path, receipt_bytes)
            usage["pending"][claim.record_id] = {
                "operation": "remove",
                "source_token": claim.source_token,
                "bytes": len(data),
            }
            self._write_usage_locked(usage)
            removed = False
            try:
                claim.path.unlink()
                removed = True
                _directory_fsync(paths["processing"])
            except BaseException:
                if removed:
                    raise
                usage["pending"].pop(claim.record_id, None)
                self._refresh_usage_signature(usage, claim.source_token, paths["root"])
                self._write_usage_locked(usage)
                raise
            usage["pending"].pop(claim.record_id, None)
            self._adjust_usage(
                usage,
                claim.source_token,
                records=-1,
                byte_count=-len(data),
            )
            self._refresh_usage_signature(usage, claim.source_token, paths["root"])
            self._write_usage_locked(usage)
        return SpoolReceipt(
            "complete",
            claim.source_token,
            claim.record_id,
            stored_bytes=0,
            path=receipt_path,
        )

    def quarantine(self, claim: SpoolClaim, reason: str) -> SpoolReceipt:
        paths = self._paths_for_token(claim.source_token)
        return self._quarantine_path(paths, claim.path, reason, claim.record_id)

    def recover_abandoned(
        self,
        source_id: str,
        *,
        project: str | None = None,
        older_than_seconds: float,
        max_records: int = 100,
        max_seconds: float = 0.25,
        now: float | None = None,
    ) -> RecoveryReceipt:
        if older_than_seconds < 0:
            raise ValueError("older_than_seconds cannot be negative")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records <= 0
        ):
            raise ValueError("max_records must be a positive integer")
        if max_seconds <= 0:
            raise ValueError("max_seconds must be positive")
        paths = self.ensure_source(source_id, project=project)
        current = time.time() if now is None else float(now)
        recovered = quarantined = skipped = 0
        examined = 0
        limited = False
        started = time.monotonic()
        with os.scandir(paths["processing"]) as entries:
            candidates = (
                Path(entry.path) for entry in entries if entry.name.endswith(".json")
            )
            for candidate in candidates:
                if examined >= max_records or time.monotonic() - started >= max_seconds:
                    limited = True
                    break
                examined += 1
                if _RECORD_RE.fullmatch(candidate.name) and not is_safe_regular_file(
                    candidate
                ):
                    repaired = None
                    with self._usage_lock():
                        for outcome, directory_name in (
                            ("quarantined", "quarantine"),
                            ("recovered", "inbox"),
                        ):
                            destination = _find_interrupted_link_destination(
                                candidate,
                                paths[directory_name],
                            )
                            if destination is None:
                                continue
                            if not _finish_interrupted_link_move(
                                candidate, destination
                            ):
                                raise SpoolUnsafeError(
                                    "linked capture move changed during recovery"
                                )
                            usage = self._load_usage_locked(
                                persist_reconciliation=False
                            )
                            token = paths["root"].name
                            self._ensure_usage_source(usage, token, paths["root"])
                            self._refresh_usage_signature(usage, token, paths["root"])
                            self._write_usage_locked(usage)
                            repaired = outcome
                            break
                    if repaired == "quarantined":
                        quarantined += 1
                        continue
                    if repaired == "recovered":
                        recovered += 1
                        continue
                if not _RECORD_RE.fullmatch(candidate.name) or not is_safe_regular_file(
                    candidate
                ):
                    if is_safe_regular_file(candidate):
                        self._quarantine_path(
                            paths, candidate, "unsafe_processing_record"
                        )
                        quarantined += 1
                        continue
                    raise SpoolUnsafeError("processing record is linked or unsafe")
                try:
                    _, before = self._stable_read(candidate)
                    age = current - (candidate.stat().st_mtime_ns / 1_000_000_000)
                except OSError:
                    skipped += 1
                    continue
                if age < older_than_seconds:
                    skipped += 1
                    continue
                inbox = paths["inbox"] / candidate.name
                if inbox.exists():
                    self._quarantine_path(paths, candidate, "duplicate_recovery_record")
                    quarantined += 1
                    continue
                if self._identity(candidate) != before:
                    skipped += 1
                    continue
                conflict = False
                with self._usage_lock():
                    usage = self._load_usage_locked(persist_reconciliation=False)
                    token = paths["root"].name
                    self._ensure_usage_source(usage, token, paths["root"])
                    if self._identity(candidate) != before:
                        skipped += 1
                        continue
                    try:
                        _move_no_replace(candidate, inbox)
                    except FileExistsError:
                        conflict = True
                    if not conflict:
                        self._refresh_usage_signature(usage, token, paths["root"])
                        self._write_usage_locked(usage)
                if conflict:
                    self._quarantine_path(paths, candidate, "duplicate_recovery_record")
                    quarantined += 1
                    continue
                recovered += 1
        return RecoveryReceipt(recovered, quarantined, skipped, limited)

    def cleanup_temporary(
        self,
        source_id: str,
        *,
        project: str | None = None,
        older_than_seconds: float,
        max_records: int = 100,
        max_seconds: float = 0.25,
        now: float | None = None,
    ) -> int:
        if older_than_seconds < 0:
            raise ValueError("older_than_seconds cannot be negative")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records <= 0
        ):
            raise ValueError("max_records must be a positive integer")
        if max_seconds <= 0:
            raise ValueError("max_seconds must be positive")
        paths = self.ensure_source(source_id, project=project)
        current = time.time() if now is None else float(now)
        removed = 0
        started = time.monotonic()
        with self._usage_lock():
            self._load_usage_locked(persist_reconciliation=False)
            limited = False
            for directory_name in ("inbox", "processing", "receipts", "quarantine"):
                directory = paths[directory_name]
                removed_here = False
                for temporary in directory.glob("*.tmp"):
                    if (
                        removed >= max_records
                        or time.monotonic() - started >= max_seconds
                    ):
                        limited = True
                        break
                    if not is_safe_regular_file(temporary):
                        raise SpoolUnsafeError(
                            "temporary capture record is linked or unsafe"
                        )
                    before = self._identity(temporary)
                    age = current - (temporary.stat().st_mtime_ns / 1_000_000_000)
                    if age < older_than_seconds or self._identity(temporary) != before:
                        continue
                    temporary.unlink()
                    removed += 1
                    removed_here = True
                if removed_here:
                    _directory_fsync(directory)
                if limited:
                    break
            if removed:
                usage = self._load_usage_locked(persist_reconciliation=False)
                self._write_usage_locked(usage)
        return removed

    def usage_summary(self) -> dict[str, int]:
        """Return bounded numeric occupancy without exposing source or record content."""

        with self._usage_lock():
            usage = self._load_usage_locked(persist_reconciliation=False)
            return {
                "total_records": int(usage["total_records"]),
                "total_bytes": int(usage["total_bytes"]),
                "source_count": len(usage["sources"]),
            }

    def _paths_for_token(self, token: str) -> dict[str, Path]:
        if not _TOKEN_RE.fullmatch(token):
            raise SpoolUnsafeError("invalid source token")
        root = self.root / token
        return self._validated_source_paths(root)

    @staticmethod
    def _validated_source_paths(root: Path) -> dict[str, Path]:
        _ensure_private_directory(root)
        paths = {"root": root}
        for name in ("inbox", "processing", "quarantine", "receipts"):
            paths[name] = root / name
        for path in paths.values():
            _ensure_private_directory(path)
        return paths

    def _source_roots(self) -> list[Path]:
        roots: list[Path] = []
        ignored = {"registry.json", "usage.json", ".usage.lock"}
        for child in self.root.iterdir():
            if child.name in ignored:
                continue
            if _ROOT_TEMP_RE.fullmatch(child.name):
                raise SpoolBusyError("capture root contains an active temporary file")
            if not _TOKEN_RE.fullmatch(child.name):
                raise SpoolUnsafeError("unexpected entry in capture spool root")
            _ensure_private_directory(child)
            roots.append(child)
            if len(roots) > self.limits.max_sources:
                raise SpoolUnsafeError("capture source budget is full")
        return roots

    def _cleanup_root_temporaries(
        self,
        *,
        older_than_seconds: float,
        now: float | None = None,
    ) -> int:
        current = time.time() if now is None else float(now)
        removed = 0
        for child in self.root.iterdir():
            if not _ROOT_TEMP_RE.fullmatch(child.name):
                continue
            if not is_safe_regular_file(child):
                raise SpoolUnsafeError("capture root temporary is linked or unsafe")
            before = self._identity(child)
            age = current - (child.stat().st_mtime_ns / 1_000_000_000)
            if age < older_than_seconds or self._identity(child) != before:
                continue
            child.unlink()
            removed += 1
        if removed:
            _directory_fsync(self.root)
        return removed

    @contextmanager
    def _usage_lock(self, *, timeout_seconds: float = 0.5):
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        flags = os.O_CREAT | os.O_RDWR
        flags |= getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._usage_lock_path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SpoolUnsafeError("capture usage lock is linked or unsafe")
            if os.name == "nt":
                if not windows_path_is_private(self._usage_lock_path):
                    raise SpoolUnsafeError("capture usage lock ACL is not private")
            else:
                if info.st_uid != os.getuid():
                    raise SpoolUnsafeError("capture usage lock owner mismatch")
                os.fchmod(descriptor, 0o600)
            if info.st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            while not self._try_lock_descriptor(descriptor):
                if time.monotonic() >= deadline:
                    raise SpoolBusyError("capture usage ledger is busy")
                time.sleep(0.005)
            try:
                yield
            finally:
                self._unlock_descriptor(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _try_lock_descriptor(descriptor: int) -> bool:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            raise

    @staticmethod
    def _unlock_descriptor(descriptor: int) -> None:
        if os.name == "nt":
            import msvcrt

            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)

    def _read_bounded_json(self, path: Path, *, max_bytes: int) -> Any:
        try:
            data, _ = self._bounded_stable_read(path, max_bytes=max_bytes)
            return json.loads(data.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SpoolUnsafeError("capture state file is malformed") from exc

    def _scan_usage(self) -> dict[str, Any]:
        state: dict[str, Any] = {
            "schema": "rta-smriti.capture-usage/v1",
            "total_records": 0,
            "total_bytes": 0,
            "sources": {},
            "pending": {},
        }
        for child in self._source_roots():
            records, byte_count = self._scan_source_usage(child)
            inbox_ns, processing_ns = self._usage_signature(child)
            state["sources"][child.name] = {
                "records": records,
                "bytes": byte_count,
                "inbox_mtime_ns": inbox_ns,
                "processing_mtime_ns": processing_ns,
            }
            state["total_records"] += records
            state["total_bytes"] += byte_count
        return state

    def _scan_source_usage(self, source_root: Path) -> tuple[int, int]:
        count = size = 0
        for name in ("inbox", "processing"):
            directory = source_root / name
            _ensure_private_directory(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not (
                        entry.name.endswith(".json") or entry.name.endswith(".tmp")
                    ):
                        raise SpoolUnsafeError(
                            "unexpected entry in capture source queue"
                        )
                    path = Path(entry.path)
                    if not entry.is_file(
                        follow_symlinks=False
                    ) or not is_safe_regular_file(path):
                        raise SpoolUnsafeError("capture record is linked or unsafe")
                    info = entry.stat(follow_symlinks=False)
                    if info.st_size > self.limits.max_record_bytes:
                        raise SpoolUnsafeError(
                            "capture record exceeds the configured limit"
                        )
                    count += 1
                    size += int(info.st_size)
        return count, size

    def _load_usage_locked(
        self,
        *,
        persist_reconciliation: bool = True,
    ) -> dict[str, Any]:
        state = self._read_bounded_json(self._usage_path, max_bytes=2_097_152)
        if (
            not isinstance(state, dict)
            or state.get("schema") != "rta-smriti.capture-usage/v1"
        ):
            raise SpoolUnsafeError("capture usage ledger has an unsupported schema")
        sources = state.get("sources")
        pending = state.get("pending")
        if not isinstance(sources, dict) or not isinstance(pending, dict):
            raise SpoolUnsafeError("capture usage ledger has an invalid shape")
        for name in ("total_records", "total_bytes"):
            value = state.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SpoolUnsafeError("capture usage ledger has an invalid counter")
        for token, entry in sources.items():
            if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
                raise SpoolUnsafeError(
                    "capture usage ledger contains an invalid source token"
                )
            self._validate_usage_source(entry)
        changed = self._reconcile_pending(state)
        for source_root in self._source_roots():
            if source_root.name not in sources:
                self._ensure_usage_source(state, source_root.name, source_root)
                changed = True
        for token in list(sources):
            source_root = self.root / token
            _ensure_private_directory(source_root)
            entry = sources[token]
            signature = self._usage_signature(source_root)
            if signature != (entry["inbox_mtime_ns"], entry["processing_mtime_ns"]):
                previous_records = entry["records"]
                previous_bytes = entry["bytes"]
                records, byte_count = self._scan_source_usage(source_root)
                byte_count += self._pending_add_byte_floor(
                    state,
                    source_root.name,
                )
                entry.update(
                    records=records,
                    bytes=byte_count,
                    inbox_mtime_ns=signature[0],
                    processing_mtime_ns=signature[1],
                )
                state["total_records"] += records - previous_records
                state["total_bytes"] += byte_count - previous_bytes
                changed = True
        if state["total_records"] != sum(
            item["records"] for item in sources.values()
        ) or state["total_bytes"] != sum(item["bytes"] for item in sources.values()):
            raise SpoolUnsafeError(
                "capture usage ledger totals do not match its sources"
            )
        if changed and persist_reconciliation:
            self._write_usage_locked(state)
        return state

    @staticmethod
    def _validate_usage_source(entry: Any) -> None:
        if not isinstance(entry, dict):
            raise SpoolUnsafeError("capture usage source has an invalid shape")
        for name in ("records", "bytes", "inbox_mtime_ns", "processing_mtime_ns"):
            value = entry.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SpoolUnsafeError("capture usage source has an invalid counter")

    def _reconcile_pending(self, state: dict[str, Any]) -> bool:
        changed = False
        touched_tokens: set[str] = set()
        for record_id, operation in list(state["pending"].items()):
            if not _TOKEN_RE.fullmatch(record_id) or not isinstance(operation, dict):
                raise SpoolUnsafeError(
                    "capture usage ledger has an invalid reservation"
                )
            token = operation.get("source_token")
            byte_count = operation.get("bytes")
            kind = operation.get("operation")
            if (
                not isinstance(token, str)
                or not _TOKEN_RE.fullmatch(token)
                or isinstance(byte_count, bool)
                or not isinstance(byte_count, int)
                or byte_count < 0
                or kind not in {"add", "remove"}
            ):
                raise SpoolUnsafeError(
                    "capture usage ledger has an invalid reservation"
                )
            exists = self._active_record_exists(token, record_id)
            if (
                kind == "add"
                and not exists
                and self._publish_temporary_exists(token, record_id)
            ):
                continue
            if not exists:
                self._adjust_usage(
                    state,
                    token,
                    records=-1,
                    byte_count=-byte_count,
                )
            state["pending"].pop(record_id)
            touched_tokens.add(token)
            changed = True
        for token in touched_tokens:
            source_root = self.root / token
            if source_root.is_dir():
                self._refresh_usage_signature(state, token, source_root)
        return changed

    def _active_record_exists(self, token: str, record_id: str) -> bool:
        root = self.root / token
        return any(
            is_safe_regular_file(root / name / f"{record_id}.json")
            for name in ("inbox", "processing")
        )

    def _publish_temporaries(self, token: str, record_id: str) -> list[Path]:
        inbox = self.root / token / "inbox"
        prefix = f".{record_id}.json."
        matches: list[Path] = []
        with os.scandir(inbox) as entries:
            for entry in entries:
                if not (entry.name.startswith(prefix) and entry.name.endswith(".tmp")):
                    continue
                path = Path(entry.path)
                if not entry.is_file(follow_symlinks=False) or not is_safe_regular_file(
                    path
                ):
                    raise SpoolUnsafeError("capture temporary is linked or unsafe")
                matches.append(path)
        return matches

    def _publish_temporary_exists(self, token: str, record_id: str) -> bool:
        return bool(self._publish_temporaries(token, record_id))

    def _pending_add_byte_floor(self, state: dict[str, Any], token: str) -> int:
        floor = 0
        for record_id, operation in state["pending"].items():
            if (
                operation.get("operation") != "add"
                or operation.get("source_token") != token
                or self._active_record_exists(token, record_id)
            ):
                continue
            temporaries = self._publish_temporaries(token, record_id)
            if not temporaries:
                continue
            actual_bytes = sum(path.stat().st_size for path in temporaries)
            floor += max(0, int(operation["bytes"]) - actual_bytes)
        return floor

    def _ensure_usage_source(
        self,
        state: dict[str, Any],
        token: str,
        source_root: Path,
    ) -> dict[str, int]:
        entry = state["sources"].get(token)
        if entry is None:
            records, byte_count = self._scan_source_usage(source_root)
            inbox_ns, processing_ns = self._usage_signature(source_root)
            entry = {
                "records": records,
                "bytes": byte_count,
                "inbox_mtime_ns": inbox_ns,
                "processing_mtime_ns": processing_ns,
            }
            state["sources"][token] = entry
            state["total_records"] += records
            state["total_bytes"] += byte_count
        self._validate_usage_source(entry)
        return entry

    @staticmethod
    def _adjust_usage(
        state: dict[str, Any],
        token: str,
        *,
        records: int,
        byte_count: int,
    ) -> None:
        entry = state["sources"].get(token)
        if not isinstance(entry, dict):
            raise SpoolUnsafeError("capture usage source is missing")
        next_records = entry["records"] + records
        next_bytes = entry["bytes"] + byte_count
        next_total_records = state["total_records"] + records
        next_total_bytes = state["total_bytes"] + byte_count
        if min(next_records, next_bytes, next_total_records, next_total_bytes) < 0:
            raise SpoolUnsafeError("capture usage ledger would become negative")
        entry["records"] = next_records
        entry["bytes"] = next_bytes
        state["total_records"] = next_total_records
        state["total_bytes"] = next_total_bytes

    def _refresh_usage_signature(
        self,
        state: dict[str, Any],
        token: str,
        source_root: Path,
    ) -> None:
        inbox_ns, processing_ns = self._usage_signature(source_root)
        state["sources"][token]["inbox_mtime_ns"] = inbox_ns
        state["sources"][token]["processing_mtime_ns"] = processing_ns

    def _write_usage_locked(self, state: dict[str, Any]) -> None:
        encoded = (canonical_json(state) + "\n").encode("ascii")
        if len(encoded) > 2_097_152:
            raise SpoolUnsafeError("capture usage ledger exceeds its size limit")
        _atomic_write(self._usage_path, encoded, durable=False)

    def _aux_usage(
        self,
        directory: Path,
        *,
        max_records: int,
        max_bytes: int,
    ) -> tuple[int, int]:
        count = size = 0
        with os.scandir(directory) as entries:
            for entry in entries:
                if not (entry.name.endswith(".json") or entry.name.endswith(".tmp")):
                    raise SpoolUnsafeError(
                        "unexpected entry in capture auxiliary queue"
                    )
                path = Path(entry.path)
                if not entry.is_file(follow_symlinks=False) or not is_safe_regular_file(
                    path
                ):
                    raise SpoolUnsafeError(
                        "capture auxiliary record is linked or unsafe"
                    )
                info = entry.stat(follow_symlinks=False)
                count += 1
                size += int(info.st_size)
                if count >= max_records or size >= max_bytes:
                    break
        return count, size

    def _global_aux_usage(
        self,
        directory_name: str,
        *,
        max_records: int,
        max_bytes: int,
    ) -> tuple[int, int]:
        count = size = 0
        for source_root in self._source_roots():
            directory = source_root / directory_name
            _ensure_private_directory(directory)
            remaining_records = max(1, max_records - count)
            remaining_bytes = max(1, max_bytes - size)
            child_count, child_size = self._aux_usage(
                directory,
                max_records=remaining_records,
                max_bytes=remaining_bytes,
            )
            count += child_count
            size += child_size
            if count >= max_records or size >= max_bytes:
                break
        return count, size

    def _ensure_aux_capacity(
        self,
        directory: Path,
        *,
        added_bytes: int,
        max_records: int,
        max_bytes: int,
        label: str,
    ) -> None:
        count, size = self._global_aux_usage(
            directory.name,
            max_records=max_records,
            max_bytes=max_bytes,
        )
        if count >= max_records or size + added_bytes > max_bytes:
            raise SpoolUnsafeError(f"capture {label} budget is full")

    def _ensure_completed_receipt_capacity(
        self,
        *,
        added_bytes: int,
        preserve: Path,
    ) -> None:
        count = size = 0
        candidates: list[tuple[int, str, Path, int, tuple[int, int, int, int]]] = []
        for source_root in self._source_roots():
            directory = source_root / "receipts"
            _ensure_private_directory(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not (
                        entry.name.endswith(".json") or entry.name.endswith(".tmp")
                    ):
                        raise SpoolUnsafeError(
                            "unexpected entry in capture auxiliary queue"
                        )
                    path = Path(entry.path)
                    if not entry.is_file(
                        follow_symlinks=False
                    ) or not is_safe_regular_file(path):
                        raise SpoolUnsafeError(
                            "capture auxiliary record is linked or unsafe"
                        )
                    info = path.stat()
                    identity = self._stat_identity(info)
                    count += 1
                    size += int(info.st_size)
                    if _RECORD_RE.fullmatch(entry.name) and path != preserve:
                        candidates.append(
                            (
                                int(info.st_mtime_ns),
                                str(path),
                                path,
                                int(info.st_size),
                                identity,
                            )
                        )
                    if count > self.limits.max_receipt_records:
                        raise SpoolUnsafeError(
                            "capture receipt inventory exceeds its bounded scan"
                        )

        candidates.sort(key=lambda candidate: (candidate[0], candidate[1]))
        candidate_index = 0
        while (
            count >= self.limits.max_receipt_records
            or size + added_bytes > self.limits.max_receipt_bytes
        ):
            if candidate_index >= len(candidates):
                raise SpoolUnsafeError("capture receipt budget is full")
            _, _, path, candidate_size, identity = candidates[candidate_index]
            candidate_index += 1
            if not is_safe_regular_file(path) or self._identity(path) != identity:
                raise SpoolUnsafeError(
                    "completed capture receipt changed before retirement"
                )
            path.unlink()
            _directory_fsync(path.parent)
            count -= 1
            size -= candidate_size

    @staticmethod
    def _usage_signature(source_root: Path) -> tuple[int, int]:
        return tuple(
            int((source_root / name).stat().st_mtime_ns)
            for name in ("inbox", "processing")
        )

    def _stable_read(self, path: Path) -> tuple[bytes, tuple[int, int, int, int]]:
        return self._bounded_stable_read(
            path,
            max_bytes=self.limits.max_record_bytes,
        )

    def _bounded_stable_read(
        self,
        path: Path,
        *,
        max_bytes: int,
    ) -> tuple[bytes, tuple[int, int, int, int]]:
        if not is_safe_regular_file(path):
            raise SpoolUnsafeError("capture record is linked or unsafe")
        descriptor = _open_read_no_follow(path)
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or int(getattr(before, "st_file_attributes", 0)) & 0x400
            ):
                raise SpoolUnsafeError("capture record is not a private regular file")
            if os.name == "nt":
                if not windows_path_is_private(path):
                    raise SpoolUnsafeError("capture record ACL is not private")
            elif before.st_uid != os.getuid():
                raise SpoolUnsafeError("capture record owner mismatch")
            path_before = path.stat()
            if self._stat_identity(path_before) != self._stat_identity(before):
                raise SpoolUnsafeError("capture record changed before read")
            if before.st_size > max_bytes:
                raise SpoolUnsafeError("capture record exceeds the configured limit")
            data = b""
            while len(data) <= max_bytes:
                block = os.read(
                    descriptor,
                    min(65_536, max_bytes + 1 - len(data)),
                )
                if not block:
                    break
                data += block
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        before_identity = self._stat_identity(before)
        after_identity = self._stat_identity(after)
        try:
            path_after = self._identity(path)
        except OSError as exc:
            raise SpoolUnsafeError("capture record changed during read") from exc
        if os.name == "nt" and not windows_path_is_private(path):
            raise SpoolUnsafeError("capture record ACL changed during read")
        if (
            before_identity != after_identity
            or path_after != before_identity
            or len(data) != before.st_size
            or len(data) > max_bytes
        ):
            raise SpoolUnsafeError("capture record changed during read")
        return data, before_identity

    @staticmethod
    def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_size),
            int(info.st_mtime_ns),
        )

    def _identity(self, path: Path) -> tuple[int, int, int, int]:
        return self._stat_identity(path.stat())

    def _quarantine_path(
        self,
        paths: dict[str, Path],
        path: Path,
        reason: str,
        record_id: str | None = None,
    ) -> SpoolReceipt:
        safe_reason = (
            re.sub(r"[^a-z0-9_-]+", "_", str(reason).lower())[:64] or "unknown"
        )
        record_id = (
            record_id
            if record_id and _TOKEN_RE.fullmatch(record_id)
            else uuid.uuid4().hex
        )
        destination = paths["quarantine"] / f"{record_id}.json"
        if destination.exists():
            destination = paths["quarantine"] / f"{uuid.uuid4().hex}.json"
        active = path.parent in {paths["inbox"], paths["processing"]}
        byte_count = path.stat().st_size if active and is_safe_regular_file(path) else 0
        receipt_path = paths["receipts"] / f"{record_id}.quarantine.json"
        receipt_payload = {
            "record_id": record_id,
            "source_token": paths["root"].name,
            "status": "quarantined",
            "reason": safe_reason,
        }
        receipt_bytes = (canonical_json(receipt_payload) + "\n").encode("ascii")
        with self._usage_lock():
            usage = self._load_usage_locked(persist_reconciliation=False)
            token = paths["root"].name
            self._ensure_usage_source(usage, token, paths["root"])
            if not receipt_path.exists():
                self._ensure_aux_capacity(
                    paths["receipts"],
                    added_bytes=len(receipt_bytes),
                    max_records=self.limits.max_receipt_records,
                    max_bytes=self.limits.max_receipt_bytes,
                    label="receipt",
                )
            self._ensure_aux_capacity(
                paths["quarantine"],
                added_bytes=int(byte_count),
                max_records=self.limits.max_quarantine_records,
                max_bytes=self.limits.max_quarantine_bytes,
                label="quarantine",
            )
            if not is_safe_regular_file(path):
                raise SpoolUnsafeError("quarantined record is linked or unsafe")
            _atomic_write(receipt_path, receipt_bytes)
            _move_no_replace(path, destination)
            if active:
                self._adjust_usage(
                    usage, token, records=-1, byte_count=-int(byte_count)
                )
                self._refresh_usage_signature(usage, token, paths["root"])
            self._write_usage_locked(usage)
        return SpoolReceipt(
            "quarantined",
            paths["root"].name,
            record_id,
            reason=safe_reason,
            path=receipt_path,
        )
