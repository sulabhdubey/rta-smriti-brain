import argparse
import hashlib
import io
import os
import re
import stat
import string
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rta_brain.privacy import RELEASE_PATH_BYTE_PATTERNS, RELEASE_SECRET_BYTE_PATTERNS
from rta_brain.repository import run_git_inspection
from rta_brain.temporal_validators import stable_file_bytes

SECRET_PATTERNS = RELEASE_SECRET_BYTE_PATTERNS
PATH_PATTERNS = RELEASE_PATH_BYTE_PATTERNS

FORBIDDEN_SUFFIXES = {".db", ".key", ".log", ".pem", ".sqlite", ".sqlite-shm", ".sqlite-wal"}
FORBIDDEN_NAMES = {".env"}
MAX_SCAN_BYTES = 25 * 1024 * 1024
MAX_CONFIGURABLE_SCAN_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_TOTAL_BYTES = 100 * 1024 * 1024
MAX_SCAN_FILES = 100_000
MAX_SCAN_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SCAN_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
MAX_SCAN_SECONDS = 120.0
ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
VISUAL_MEDIA_SUFFIXES = {
    ".apng",
    ".avi",
    ".avif",
    ".bmp",
    ".gif",
    ".heic",
    ".heif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp4",
    ".mpeg",
    ".mpg",
    ".ogv",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webm",
    ".webp",
}
MAX_MEDIA_MANIFEST_BYTES = 1024 * 1024


@dataclass
class ScanBudget:
    deadline: float
    files: int = 0
    raw_bytes: int = 0
    expanded_bytes: int = 0
    archive_entries: int = 0

    def expired(self) -> bool:
        return time.monotonic() > self.deadline


class ScanFileLimitExceeded(RuntimeError):
    pass


class ScanDeadlineExceeded(RuntimeError):
    pass


def load_approved_media_digests(path: Path) -> set[str]:
    data = stable_file_bytes(path.expanduser(), maximum_bytes=MAX_MEDIA_MANIFEST_BYTES)
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("approved media manifest must be ASCII") from exc
    digests: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(maxsplit=1)
        digest = fields[0].lower()
        if len(fields) != 2 or len(digest) != 64 or any(character not in string.hexdigits for character in digest):
            raise ValueError(f"invalid approved media manifest entry at line {line_number}")
        digests.add(digest)
    if not digests:
        raise ValueError("approved media manifest contains no SHA-256 entries")
    return digests

KNOWN_PATH_DEFINITION_LINE_SHA256 = {
    "scripts/privacy_scan.py": {
        "9aacc06dbd65085e49e5e49d3039850e3261295d36ec5f036a7034e12dfdc2c5",
    },
    "rta_brain/privacy.py": {
        "c14eef0234cd796617e126dfbff1baa3c8c5e0636f247cb898122afe8ea5682f",
    },
    "tests/test_v11a_parser_continuity_security.py": {
        "2932306581be5cb1c9d10d3463eeea5847ca142889ac6ec69c27a91f3ee178ec",
    },
}


def path_scan_views(data: bytes) -> list[bytes]:
    """Expose text and metadata strings without interpreting compressed payloads."""
    views: list[bytes] = []
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        printable_runs = re.findall(rb"[\x20-\x7e]{4,}", data)
        if printable_runs:
            views.append(b"\n".join(printable_runs))
    else:
        views.append(data)

    prefixes = []
    for drive in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        prefixes.extend((f"{drive}:\\Users\\", f"{drive}:/Users/"))
    prefixes.extend(("/Users/", "/home/", "\\\\?\\UNC\\"))
    for prefix in prefixes:
        for encoding in ("utf-16-le", "utf-16-be"):
            marker = prefix.encode(encoding)
            start = data.find(marker)
            while start >= 0:
                decoded = data[start : start + 512].decode(encoding, errors="ignore").encode("utf-8", errors="ignore")
                if decoded:
                    views.append(decoded)
                start = data.find(marker, start + len(marker))
    return views


def is_placeholder_path(match: bytes) -> bool:
    lowered = match.lower()
    return any(marker in lowered for marker in (b"<real-name>", b"<username>", b"%userprofile%", b"$env:userprofile", b"{username}", b"[username]"))


def is_known_path_definition(relative: str, view: bytes, start: int, end: int) -> bool:
    normalized = relative.replace("\\", "/")
    canonical = next(
        (
            candidate
            for candidate in KNOWN_PATH_DEFINITION_LINE_SHA256
            if normalized == candidate or normalized.endswith(f"/{candidate}")
        ),
        None,
    )
    allowed = KNOWN_PATH_DEFINITION_LINE_SHA256.get(canonical or "")
    if not allowed:
        return False
    line_start = view.rfind(b"\n", 0, start) + 1
    line_end = view.find(b"\n", end)
    if line_end < 0:
        line_end = len(view)
    digest = hashlib.sha256(view[line_start:line_end].strip()).hexdigest()
    return digest in allowed


def _git_repository_root(root: Path) -> Path | None:
    result = run_git_inspection(
        root,
        "rev-parse",
        "--show-toplevel",
        max_output_bytes=4_096,
    )
    if result is None or result.returncode != 0:
        return None
    value = result.stdout.strip()
    if not value:
        return None
    try:
        return Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None


def candidate_files(root: Path, budget: ScanBudget) -> list[Path]:
    candidates: list[Path] = []

    def add_candidate(path: Path) -> None:
        if budget.expired():
            raise ScanDeadlineExceeded
        budget.files += 1
        if budget.files > MAX_SCAN_FILES:
            raise ScanFileLimitExceeded
        candidates.append(path)

    git_root = _git_repository_root(root)
    if git_root == root:
        result = run_git_inspection(
            root,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            max_output_bytes=MAX_ARCHIVE_TOTAL_BYTES,
        )
        if result is not None and result.returncode == 0:
            for item in result.stdout.split("\0"):
                if not item:
                    continue
                path = root / item
                if os.path.lexists(path):
                    add_candidate(path)
            return candidates

    directories = [root]
    while directories:
        if budget.expired():
            raise ScanDeadlineExceeded
        directory = directories.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if budget.expired():
                    raise ScanDeadlineExceeded
                path = Path(entry.path)
                if path.name == ".git" and directory == root:
                    continue
                if entry.is_symlink() or _is_reparse_point(path):
                    add_candidate(path)
                elif entry.is_dir(follow_symlinks=False):
                    directories.append(path)
                else:
                    add_candidate(path)
    return sorted(candidates)


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _looks_like_zip(data: bytes) -> bool:
    return data.startswith(ZIP_SIGNATURES)


def _looks_like_visual_media(name: str, data: bytes) -> bool:
    if Path(name).suffix.lower() in VISUAL_MEDIA_SUFFIXES:
        return True
    if data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM")):
        return True
    if data.startswith((b"II*\x00", b"MM\x00*", b"\x00\x00\x01\x00", b"\x1aE\xdf\xa3")):
        return True
    if len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] in {b"AVI ", b"WEBP"}:
        return True
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return True
    prefix = data[:4096].lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    return bool(
        re.match(
            rb"^(?:<\?xml[^>]*>\s*)?(?:<!--.*?-->\s*)*<svg(?:\s|>)",
            prefix,
            flags=re.IGNORECASE | re.DOTALL,
        )
    )


def _unsafe_archive_path(member: str) -> bool:
    if not member or any(ord(character) < 32 for character in member):
        return True
    normalized = member.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:($|/)", normalized):
        return True
    return ".." in normalized.split("/")


def _scan_data(
    relative: str,
    data: bytes,
    deny_patterns: list[tuple[str, re.Pattern[bytes]]],
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for label, pattern in [*SECRET_PATTERNS.items(), *deny_patterns]:
        if pattern.search(data):
            findings.append((relative, label))
    for label, pattern in PATH_PATTERNS.items():
        found = False
        for view in path_scan_views(data):
            for match in pattern.finditer(view):
                if is_placeholder_path(match.group(0)):
                    continue
                if is_known_path_definition(relative, view, match.start(), match.end()):
                    continue
                found = True
                break
            if found:
                break
        if found:
            findings.append((relative, label))
    return findings


def _scan_archive(
    archive_bytes: bytes,
    relative: str,
    deny_patterns: list[tuple[str, re.Pattern[bytes]]],
    budget: ScanBudget,
    *,
    require_approved_media: bool = False,
    approved_media_digests: set[str] | None = None,
    depth: int = 1,
) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    if depth > MAX_ARCHIVE_DEPTH:
        return [(relative, f"archive-over-{MAX_ARCHIVE_DEPTH}-levels")]
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except (OSError, ValueError, zipfile.BadZipFile):
        return [(relative, "invalid-release-archive")]
    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_ARCHIVE_ENTRIES:
            return [(relative, f"archive-over-{MAX_ARCHIVE_ENTRIES}-entries")]
        budget.archive_entries += len(entries)
        if budget.archive_entries > MAX_ARCHIVE_ENTRIES:
            return [(relative, f"scan-over-{MAX_ARCHIVE_ENTRIES}-archive-entries")]
        total_bytes = 0
        for entry in entries:
            if budget.expired():
                findings.append((relative, f"scan-over-{int(MAX_SCAN_SECONDS)}-seconds"))
                break
            member = entry.filename.replace("\\", "/")
            member_path = Path(member)
            member_relative = f"{relative}!{member}"
            if _unsafe_archive_path(member):
                findings.append((member_relative, "unsafe-archive-path"))
                continue
            mode = entry.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type == stat.S_IFLNK:
                findings.append((member_relative, "linked-archive-entry"))
                continue
            if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                findings.append((member_relative, "special-archive-entry"))
                continue
            if entry.is_dir() or file_type == stat.S_IFDIR:
                if entry.file_size or entry.compress_size:
                    findings.append((member_relative, "payload-bearing-archive-directory"))
                continue
            lower_name = member_path.name.lower()
            lower_suffixes = "".join(member_path.suffixes).lower()
            if lower_name in FORBIDDEN_NAMES or any(
                lower_suffixes.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES
            ):
                findings.append((member_relative, "forbidden-release-file"))
                continue
            total_bytes += entry.file_size
            budget.expanded_bytes += entry.file_size
            if entry.file_size > MAX_SCAN_BYTES:
                findings.append((member_relative, f"unscanned-file-over-{MAX_SCAN_BYTES}-bytes"))
                continue
            if total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                findings.append((relative, f"archive-over-{MAX_ARCHIVE_TOTAL_BYTES}-bytes"))
                break
            if budget.expanded_bytes > MAX_SCAN_EXPANDED_BYTES:
                findings.append((relative, f"scan-over-{MAX_SCAN_EXPANDED_BYTES}-expanded-bytes"))
                break
            try:
                with archive.open(entry) as source:
                    data = source.read(MAX_SCAN_BYTES + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                findings.append((member_relative, "unreadable-archive-entry"))
                continue
            if len(data) > MAX_SCAN_BYTES:
                findings.append((member_relative, f"unscanned-file-over-{MAX_SCAN_BYTES}-bytes"))
                continue
            if require_approved_media and _looks_like_visual_media(member, data):
                digest = hashlib.sha256(data).hexdigest()
                if digest not in (approved_media_digests or set()):
                    findings.append((member_relative, "unapproved-visual-media"))
            findings.extend(_scan_data(member_relative, data, deny_patterns))
            if _looks_like_zip(data):
                findings.extend(
                    _scan_archive(
                        data,
                        member_relative,
                        deny_patterns,
                        budget,
                        require_approved_media=require_approved_media,
                        approved_media_digests=approved_media_digests,
                        depth=depth + 1,
                    )
                )
    return findings


def scan(
    root: Path,
    deny_terms: list[str],
    *,
    max_file_bytes: int | None = None,
    require_approved_media: bool = False,
    approved_media_digests: set[str] | None = None,
) -> list[tuple[str, str]]:
    scan_file_bytes = MAX_SCAN_BYTES if max_file_bytes is None else max_file_bytes
    if (
        isinstance(scan_file_bytes, bool)
        or not isinstance(scan_file_bytes, int)
        or scan_file_bytes <= 0
        or scan_file_bytes > MAX_CONFIGURABLE_SCAN_BYTES
    ):
        return [(".", "invalid-max-file-bytes")]
    root = Path(root).expanduser().resolve()
    if not root.exists():
        return [(".", "missing-release-root")]
    if not root.is_dir() or root.is_symlink() or _is_reparse_point(root):
        return [(".", "invalid-release-root")]
    findings: list[tuple[str, str]] = []
    deny_patterns = [(f"private-term:{term}", re.compile(re.escape(term).encode(), re.IGNORECASE)) for term in deny_terms if term]
    budget = ScanBudget(deadline=time.monotonic() + MAX_SCAN_SECONDS)
    try:
        candidates = candidate_files(root, budget)
    except ScanFileLimitExceeded:
        return [(".", f"scan-over-{MAX_SCAN_FILES}-files")]
    except ScanDeadlineExceeded:
        return [(".", f"scan-over-{int(MAX_SCAN_SECONDS)}-seconds")]
    except OSError:
        return [(".", "unreadable-release-root")]
    if not candidates:
        return [(".", "empty-release-root")]
    if len(candidates) > MAX_SCAN_FILES:
        return [(".", f"scan-over-{MAX_SCAN_FILES}-files")]
    for path in candidates:
        if budget.expired():
            findings.append((".", f"scan-over-{int(MAX_SCAN_SECONDS)}-seconds"))
            break
        relative = path.relative_to(root).as_posix()
        lower_name = path.name.lower()
        lower_suffixes = "".join(path.suffixes).lower()
        if lower_name in FORBIDDEN_NAMES or any(lower_suffixes.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
            findings.append((relative, "forbidden-release-file"))
            continue
        try:
            metadata = path.lstat()
        except OSError:
            findings.append((relative, "unreadable-release-file"))
            continue
        if path.is_symlink() or _is_reparse_point(path) or metadata.st_nlink != 1:
            findings.append((relative, "linked-release-file"))
            continue
        if not stat.S_ISREG(metadata.st_mode):
            findings.append((relative, "special-release-file"))
            continue
        if metadata.st_size > scan_file_bytes:
            findings.append((relative, f"unscanned-file-over-{scan_file_bytes}-bytes"))
            continue
        budget.raw_bytes += metadata.st_size
        if budget.raw_bytes > MAX_SCAN_TOTAL_BYTES:
            findings.append((".", f"scan-over-{MAX_SCAN_TOTAL_BYTES}-raw-bytes"))
            break
        try:
            data = stable_file_bytes(path, maximum_bytes=scan_file_bytes)
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            findings.append((relative, "unstable-release-file"))
            continue
        if require_approved_media and _looks_like_visual_media(relative, data):
            digest = hashlib.sha256(data).hexdigest()
            if digest not in (approved_media_digests or set()):
                findings.append((relative, "unapproved-visual-media"))
        findings.extend(_scan_data(relative, data, deny_patterns))
        if path.suffix.lower() in {".whl", ".zip"} or _looks_like_zip(data):
            findings.extend(
                _scan_archive(
                    data,
                    relative,
                    deny_patterns,
                    budget,
                    require_approved_media=require_approved_media,
                    approved_media_digests=approved_media_digests,
                )
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan public-candidate files for credentials, local paths, and private names.")
    parser.add_argument("--deny-term", action="append", default=[], help="Private project, client, or product name that must not appear. Repeat as needed.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--max-file-bytes",
        type=int,
        default=MAX_SCAN_BYTES,
        help=(
            "Maximum bytes read from one top-level file. "
            f"Must be between 1 and {MAX_CONFIGURABLE_SCAN_BYTES}."
        ),
    )
    parser.add_argument(
        "--approved-media-manifest",
        type=Path,
        help="ASCII SHA256SUMS-style allowlist for image and video publication candidates.",
    )
    parser.add_argument(
        "--require-approved-media",
        action="store_true",
        help="Block every visual media file whose exact SHA-256 is not in the approved manifest.",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    approved_media_digests: set[str] | None = None
    if args.approved_media_manifest is not None:
        try:
            approved_media_digests = load_approved_media_digests(args.approved_media_manifest)
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            print(f"BLOCK invalid-approved-media-manifest: {exc}")
            return 1
    if args.require_approved_media and approved_media_digests is None:
        print("BLOCK missing-approved-media-manifest: visual publication requires exact SHA-256 approval")
        return 1
    findings = scan(
        root,
        args.deny_term,
        max_file_bytes=args.max_file_bytes,
        require_approved_media=args.require_approved_media,
        approved_media_digests=approved_media_digests,
    )
    print("privacy scan: completed")
    if findings:
        for path, category in findings:
            print(f"BLOCK {category}: {path}")
        return 1
    if args.require_approved_media:
        print(
            "privacy scan: PASS (visual media matched approved SHA-256 values; "
            "pixel contents are not OCR-scanned)"
        )
    else:
        print("privacy scan: PASS (no credential signatures, absolute user paths, forbidden files, or denied terms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
