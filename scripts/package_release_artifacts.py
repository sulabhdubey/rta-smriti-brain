"""Stage versioned release artifacts and a verified SHA-256 manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import string
import subprocess
import sys
import tomllib
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from rta_brain.temporal_validators import stable_file_bytes



ROOT = Path(__file__).resolve().parents[1]
MAX_SBOM_BYTES = 10 * 1024 * 1024
PROJECT_NAME = "rta-smriti-brain"
SBOM_ARTIFACT_PROPERTY_PREFIX = "rta-smriti:release-artifact-sha256:"
SBOM_RELEASE_SET_PROPERTY = "rta-smriti:release-set-sha256"


class _StaticAssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        reference = attributes.get("src") if tag == "script" else attributes.get("href") if tag == "link" else None
        if reference and reference.lstrip("/").startswith("assets/"):
            self.assets.add(reference.lstrip("/"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def platform_label() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise RuntimeError(f"unsupported release platform: {sys.platform}")


def architecture_label() -> str:
    machine = platform.machine().lower()
    return {
        "amd64": "x86_64",
        "x64": "x86_64",
        "aarch64": "arm64",
    }.get(machine, machine or "unknown")


def project_version() -> str:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(metadata["project"]["version"])


def run(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True, timeout=300)


def clean_wheel_build() -> None:
    build_dir = (ROOT / "build").resolve()
    if build_dir.parent != ROOT.resolve() or build_dir.name != "build" or build_dir.is_symlink():
        raise RuntimeError(f"refusing to clean unexpected wheel build path: {build_dir}")
    if build_dir.exists():
        shutil.rmtree(build_dir)


def referenced_static_assets() -> set[str]:
    parser = _StaticAssetParser()
    parser.feed((ROOT / "rta_brain" / "static" / "index.html").read_text(encoding="utf-8"))
    return {f"rta_brain/static/{asset}" for asset in parser.assets}


def assert_wheel_static_assets(wheel: Path) -> None:
    expected = referenced_static_assets()
    if not expected:
        raise RuntimeError("dashboard index does not reference any production assets")
    with zipfile.ZipFile(wheel) as archive:
        packaged = {name for name in archive.namelist() if name.startswith("rta_brain/static/assets/")}
    if packaged != expected:
        missing = sorted(expected - packaged)
        stale = sorted(packaged - expected)
        raise RuntimeError(f"wheel dashboard assets do not match index.html; missing={missing}, stale={stale}")


def _validated_artifact_digests(artifact_digests: dict[str, str]) -> dict[str, str]:
    if not artifact_digests:
        raise ValueError("SBOM requires at least one release artifact digest")
    validated: dict[str, str] = {}
    for name, digest in sorted(artifact_digests.items()):
        if not name or name in {".", ".."} or Path(name).name != name or "\\" in name:
            raise ValueError(f"invalid release artifact name for SBOM binding: {name!r}")
        if len(digest) != 64 or any(character not in string.hexdigits for character in digest):
            raise ValueError(f"release artifact digest must be SHA-256 hex: {name}")
        validated[name] = digest.lower()
    return validated


def _release_set_sha256(artifact_digests: dict[str, str]) -> str:
    canonical = json.dumps(artifact_digests, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def stage_sbom(
    sbom: Path,
    output: Path,
    *,
    version: str,
    artifact_digests: dict[str, str],
) -> Path:
    source = sbom.expanduser()
    data = stable_file_bytes(source, maximum_bytes=MAX_SBOM_BYTES)
    if not data:
        raise ValueError("SBOM must not be empty")
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("SBOM must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM must be a CycloneDX JSON object")
    digests = _validated_artifact_digests(artifact_digests)

    metadata = payload.setdefault("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("SBOM metadata must be a JSON object")
    component = metadata.setdefault("component", {})
    if not isinstance(component, dict):
        raise ValueError("SBOM root component must be a JSON object")
    expected_identity = {
        "type": "application",
        "name": PROJECT_NAME,
        "version": version,
        "bom-ref": f"pkg:pypi/{PROJECT_NAME}@{version}",
    }
    for field, expected in expected_identity.items():
        existing = component.get(field)
        if existing is not None and existing != expected:
            raise ValueError(f"SBOM root component {field} does not match release: {existing!r}")
        component[field] = expected

    properties = component.setdefault("properties", [])
    if not isinstance(properties, list) or any(not isinstance(item, dict) for item in properties):
        raise ValueError("SBOM root component properties must be a JSON array of objects")
    properties[:] = [
        item
        for item in properties
        if item.get("name") != SBOM_RELEASE_SET_PROPERTY
        and not (
            isinstance(item.get("name"), str)
            and item["name"].startswith(SBOM_ARTIFACT_PROPERTY_PREFIX)
        )
    ]
    properties.extend(
        {"name": f"{SBOM_ARTIFACT_PROPERTY_PREFIX}{name}", "value": digest}
        for name, digest in digests.items()
    )
    properties.append({"name": SBOM_RELEASE_SET_PROPERTY, "value": _release_set_sha256(digests)})

    staged_data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(staged_data) > MAX_SBOM_BYTES:
        raise ValueError(f"staged SBOM exceeds {MAX_SBOM_BYTES} bytes")
    target = output / (
        f"rta-smriti-brain-{version}-{platform_label()}-{architecture_label()}.cdx.json"
    )
    target.write_bytes(staged_data)
    return target


def stage_artifacts(output: Path, include_wheel: bool, sbom: Path | None = None) -> dict:
    output = output.resolve()
    if output.exists():
        raise FileExistsError(f"artifact output already exists: {output}")
    output.mkdir(parents=True)

    source_name = "rta-brain.exe" if os.name == "nt" else "rta-brain"
    source = (ROOT / "dist" / source_name).resolve()
    if not source.is_file() or source.is_symlink() or source.stat().st_nlink != 1:
        raise FileNotFoundError(f"standalone release binary is missing or linked: {source}")

    version = project_version()
    suffix = ".exe" if os.name == "nt" else ""
    target = output / f"rta-brain-{version}-{platform_label()}-{architecture_label()}{suffix}"
    shutil.copyfile(source, target)
    if os.name != "nt":
        target.chmod(0o755)

    version_output = run([str(target), "--version"], cwd=output).stdout.strip()
    if version not in version_output:
        raise RuntimeError(f"packaged binary reports an unexpected version: {version_output}")

    if include_wheel:
        clean_wheel_build()
        run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-build-isolation",
                "--no-deps",
                "--wheel-dir",
                str(output),
                ".",
            ]
        )
        wheels = list(output.glob("*.whl"))
        if len(wheels) != 1:
            raise RuntimeError(f"expected exactly one wheel, found {len(wheels)}")
        assert_wheel_static_assets(wheels[0])

    sbom_subjects = sorted(path for path in output.iterdir() if path.is_file())
    subject_digests = {path.name: file_sha256(path) for path in sbom_subjects}
    if sbom is not None:
        stage_sbom(sbom, output, version=version, artifact_digests=subject_digests)

    artifacts = sorted(path for path in output.iterdir() if path.is_file())
    manifest = output / "SHA256SUMS.txt"
    checksums = {path.name: file_sha256(path) for path in artifacts}
    for name, expected in subject_digests.items():
        if checksums.get(name) != expected:
            raise RuntimeError(f"release artifact changed while staging SBOM: {name}")
    manifest.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in checksums.items()),
        encoding="ascii",
        newline="\n",
    )
    for name, expected in checksums.items():
        if file_sha256(output / name) != expected:
            raise RuntimeError(f"checksum verification failed after staging: {name}")
    return {
        "status": "ok",
        "version": version,
        "platform": platform_label(),
        "architecture": architecture_label(),
        "artifacts": checksums,
        "manifest": str(manifest),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "release-artifacts")
    parser.add_argument("--include-wheel", action="store_true")
    parser.add_argument("--sbom", type=Path, help="Validated CycloneDX JSON SBOM to include and checksum")
    args = parser.parse_args()
    print(json.dumps(stage_artifacts(args.output, args.include_wheel, args.sbom), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
