"""Assemble an unpublished Windows pilot from checksum-verified release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

from scripts.package_release_artifacts import ROOT, file_sha256, project_version
from rta_brain.temporal_validators import stable_file_bytes

ATLAS_FILES = (
    "README.md", "pyproject.toml", "src/__init__.py", "src/api.py",
    "src/models.py", "src/service.py", "src/store.py", "tests/test_service.py",
)


def source_identity() -> dict:
    def git(*args: str) -> bytes:
        return subprocess.check_output(
            ["git", "-c", f"safe.directory={ROOT.as_posix()}", *args], cwd=ROOT, timeout=30,
        )
    digest = hashlib.sha256()
    names = sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    for name in names:
        path = ROOT / name.decode("utf-8")
        digest.update(name + b"\0")
        if path.exists():
            digest.update(hashlib.sha256(stable_file_bytes(path, maximum_bytes=128 * 1024 * 1024)).digest())
        else:
            digest.update(b"deleted")
    return {
        "base_commit": git("rev-parse", "HEAD").decode("ascii").strip(),
        "source_sha256": digest.hexdigest(),
        "uncommitted": bool(git("status", "--porcelain")),
    }


def package_pilot(artifacts: Path, target: Path) -> dict:
    if target.exists():
        raise FileExistsError("pilot bundle already exists")
    version = project_version()
    native = f"rta-brain-{version}-windows-x86_64.exe"
    wheel = f"rta_smriti_brain-{version}-py3-none-any.whl"
    allowed = {native, wheel, "SHA256SUMS.txt"}
    if {path.name for path in artifacts.iterdir()} != allowed:
        raise ValueError("missing or unexpected artifact; pilot requires only Windows x86_64, wheel, and checksums")
    lines = stable_file_bytes(artifacts / "SHA256SUMS.txt", maximum_bytes=4096).decode("ascii").splitlines()
    checksums = {}
    for line in lines:
        digest, name = line.split("  ", 1)
        if name not in {native, wheel} or name in checksums:
            raise ValueError("unexpected or duplicate checksum entry")
        checksums[name] = digest
    if set(checksums) != {native, wheel}:
        raise ValueError("missing artifact checksum")
    contents = {}
    for name, digest in checksums.items():
        data = stable_file_bytes(artifacts / name, maximum_bytes=512 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("artifact checksum mismatch")
        contents["rta-brain-pilot.exe" if name == native else name] = data
    before = source_identity()
    for name in ATLAS_FILES:
        contents[f"atlas-demo/{name}"] = stable_file_bytes(ROOT / "examples" / "atlas-demo" / name, maximum_bytes=1024 * 1024)
    for name, source in {"PILOT_GUIDE.md": "docs/PILOT_GUIDE.md", "LICENSE": "LICENSE"}.items():
        contents[name] = stable_file_bytes(ROOT / source, maximum_bytes=1024 * 1024)
    manifest = {
        "schema": "rta-smriti.local-pilot/v1", "status": "local_unpublished_candidate",
        "runtime_version": version, "source": before, "platform": "windows-x86_64",
        "host_activation_verified": False, "external_pilots_completed": 0,
        "capture_default": "off_in_dashboard", "public_release": False,
        "qualification": "See separate exact-artifact qualification report; packaging is not a test result.",
    }
    contents["PILOT_MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    contents["SHA256SUMS.txt"] = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(contents.items())
    ).encode("ascii")
    if source_identity() != before:
        raise ValueError("candidate source changed while assembling pilot")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as output:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(contents.items()):
                archive.writestr(name, data)
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(contents):
            raise ValueError("pilot archive verification failed")
        for name, data in contents.items():
            if hashlib.sha256(archive.read(name)).digest() != hashlib.sha256(data).digest():
                raise ValueError("pilot archive content changed")
    return {"bundle": str(target), "sha256": file_sha256(target), "files": len(contents), "source": before}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(package_pilot(args.artifacts, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
