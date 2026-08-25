import os
import re
import stat
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from package_release_artifacts import (
    assert_wheel_static_assets,
    clean_wheel_build,
    project_version,
)
from rta_brain.repository import run_git_inspection

BASELINE_REF = "v1.0.0-alpha"
BASELINE_COMMIT = "a1b05022aff6df3a066ae5abcad3877f6407eafb"
MAX_BASELINE_ARCHIVE_ENTRIES = 20_000
MAX_BASELINE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BASELINE_ENTRY_BYTES = 32 * 1024 * 1024


def run(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        rendered = subprocess.list2cmdline(command)
        raise RuntimeError(
            f"command failed ({result.returncode}): {rendered}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def extract_git_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir()
    destination = destination.resolve()
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_BASELINE_ARCHIVE_ENTRIES:
            raise RuntimeError("baseline archive contains too many entries")
        expanded_bytes = 0
        for entry in entries:
            member = entry.filename.replace("\\", "/")
            clean_member = member.rstrip("/")
            relative = PurePosixPath(clean_member)
            mode = entry.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if (
                not clean_member
                or any(ord(character) < 32 for character in member)
                or member.startswith("/")
                or re.match(r"^[A-Za-z]:($|/)", member)
                or relative.is_absolute()
                or ".." in relative.parts
                or file_type == stat.S_IFLNK
                or (file_type not in {0, stat.S_IFREG, stat.S_IFDIR})
            ):
                raise RuntimeError(f"baseline archive contains an unsafe entry: {entry.filename}")
            if entry.file_size > MAX_BASELINE_ENTRY_BYTES:
                raise RuntimeError(f"baseline archive entry is too large: {entry.filename}")
            expanded_bytes += entry.file_size
            if expanded_bytes > MAX_BASELINE_ARCHIVE_BYTES:
                raise RuntimeError("baseline archive expands beyond the allowed budget")
            target = destination.joinpath(*relative.parts).resolve(strict=False)
            if os.path.commonpath((str(destination), str(target))) != str(destination):
                raise RuntimeError(f"baseline archive contains an unsafe entry: {entry.filename}")
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source:
                payload = source.read(MAX_BASELINE_ENTRY_BYTES + 1)
            if len(payload) != entry.file_size or len(payload) > MAX_BASELINE_ENTRY_BYTES:
                raise RuntimeError(f"baseline archive entry failed bounded extraction: {entry.filename}")
            target.write_bytes(payload)


def build_baseline_archive(archive_path: Path) -> None:
    resolved = run_git_inspection(
        ROOT, "rev-parse", "--verify", f"{BASELINE_REF}^{{}}", max_output_bytes=1024,
    )
    if resolved is None or resolved.returncode or resolved.stdout.strip() != BASELINE_COMMIT:
        raise RuntimeError(
            f"baseline tag {BASELINE_REF} does not resolve to the reviewed commit {BASELINE_COMMIT}"
        )
    archived = run_git_inspection(
        ROOT,
        "archive",
        "--format=zip",
        f"--output={archive_path}",
        BASELINE_COMMIT,
        max_output_bytes=1024 * 1024,
    )
    if archived is None or archived.returncode or not archive_path.is_file():
        raise RuntimeError(f"trusted Git could not create the {BASELINE_REF} baseline archive")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="rta-smriti-wheel-build-") as tmp:
        smoke_root = Path(tmp)
        wheel_dir = smoke_root / "wheel"
        baseline_wheel_dir = smoke_root / "baseline-wheel"
        baseline_source = smoke_root / "baseline-source"
        baseline_archive = smoke_root / "baseline.zip"
        environment = smoke_root / "venv"
        wheel_dir.mkdir()
        baseline_wheel_dir.mkdir()

        clean_wheel_build()
        run([sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(wheel_dir), "."])
        build_baseline_archive(baseline_archive)
        extract_git_archive(baseline_archive, baseline_source)
        run([
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(baseline_wheel_dir),
            ".",
        ], cwd=baseline_source)
        venv.EnvBuilder(with_pip=True).create(environment)

        scripts = environment / ("Scripts" if sys.platform == "win32" else "bin")
        python = scripts / ("python.exe" if sys.platform == "win32" else "python")
        cli = scripts / ("rta-brain.exe" if sys.platform == "win32" else "rta-brain")
        wheel = next(wheel_dir.glob("*.whl"))
        baseline_wheel = next(baseline_wheel_dir.glob("*.whl"))
        assert_wheel_static_assets(wheel)

        run([str(python), "-m", "pip", "install", str(baseline_wheel)])
        baseline_version = run([
            str(python), "-c",
            "from importlib.metadata import version; print(version('rta-smriti-brain'))",
        ], cwd=smoke_root).stdout.strip()
        expected_version = project_version()
        if baseline_version == expected_version:
            raise AssertionError("baseline and candidate package versions are identical")

        run([str(python), "-m", "pip", "install", "--upgrade", str(wheel)])
        upgraded_version = run([
            str(python), "-c",
            "from importlib.metadata import version; print(version('rta-smriti-brain'))",
        ], cwd=smoke_root).stdout.strip()
        if upgraded_version != expected_version:
            raise AssertionError(
                f"upgrade installed {upgraded_version}, expected {expected_version} from {baseline_version}"
            )
        run([str(python), str(ROOT / "scripts" / "installed_distribution_smoke.py"), "--cli", str(cli)])
        version = run([str(cli), "--version"], cwd=smoke_root).stdout.strip()
        if expected_version not in version:
            raise AssertionError(f"upgraded CLI reported an unexpected version: {version}")

        run([str(python), "-m", "pip", "uninstall", "-y", "rta-smriti-brain"])
        import_probe = run([
            str(python), "-c",
            "import importlib.util; raise SystemExit(0 if importlib.util.find_spec('rta_brain') is None else 1)",
        ], cwd=smoke_root)
        if import_probe.returncode != 0 or cli.exists():
            raise AssertionError("uninstall left an importable package or CLI entry point")

        print(
            '{"status":"ok","lifecycle":["install-baseline","upgrade-candidate","uninstall"],'
            f'"baseline":"{baseline_version}","candidate":"{expected_version}"}}'
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
