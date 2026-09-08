"""Exercise managed federation through a built standalone executable."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path


def run_json(executable: Path, *arguments: str, cwd: Path) -> dict:
    completed = subprocess.run(
        [str(executable), *arguments],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            f"native federation command failed ({completed.returncode}): "
            f"{subprocess.list2cmdline([str(executable), *arguments])}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve(strict=True)

    with tempfile.TemporaryDirectory(prefix="rta-native-federation-") as tmp:
        root = Path(tmp)
        project_root = root / "atlas"
        brain_root = root / "brains"
        identity_root = root / "identity"
        relay_root = root / "relay"
        passphrase_file = root / "identity.passphrase"
        project_root.mkdir()
        relay_root.mkdir()
        (project_root / "README.md").write_text(
            "# Synthetic Atlas federation smoke\n", encoding="utf-8"
        )
        passphrase_file.write_text(
            "correct horse battery staple", encoding="utf-8"
        )

        bootstrap = run_json(
            executable,
            "--json", "bootstrap-project", str(project_root),
            "--project", "atlas", "--brain-dir", str(brain_root),
            cwd=root,
        )
        database = Path(bootstrap["db_path"])
        identity = run_json(
            executable,
            "--json", "federation", "identity", "create",
            "--identity-dir", str(identity_root),
            "--passphrase-file", str(passphrase_file),
            cwd=root,
        )
        peer_id = identity["identity_id"]

        def apply_operation(action: str, parameters: dict) -> dict:
            encoded = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
            plan = run_json(
                executable,
                "--db", str(database), "--json", "federation", "plan",
                "--project", "atlas", "--action", action,
                "--actor-peer-id", peer_id, "--parameters-json", encoded,
                cwd=root,
            )
            return run_json(
                executable,
                "--db", str(database), "--json", "federation", "apply",
                "--project", "atlas", "--action", action,
                "--parameters-json", encoded,
                "--identity-dir", str(identity_root),
                "--passphrase-file", str(passphrase_file),
                "--confirmation-digest", plan["confirmation_digest"],
                cwd=root,
            )

        space = apply_operation("space-create", {})["result"]
        scope = apply_operation(
            "scope-create",
            {"space_id": space["space_id"], "kind": "team", "label": "Atlas"},
        )["result"]
        common = (
            "--project", "atlas",
            "--space-id", space["space_id"],
            "--scope-id", scope["scope_id"],
            "--identity-dir", str(identity_root),
            "--passphrase-file", str(passphrase_file),
            "--relay-root", str(relay_root),
            "--interval", "2",
        )
        preview = run_json(
            executable,
            "--db", str(database), "--json", "federation", "sync",
            "daemon-preview", *common,
            cwd=root,
        )
        configured = run_json(
            executable,
            "--db", str(database), "--json", "federation", "sync",
            "daemon-configure", *common,
            "--confirmation-digest", preview["confirmation_digest"],
            cwd=root,
        )
        started = run_json(
            executable,
            "--db", str(database), "--json", "federation", "sync",
            "daemon-start", "--project", "atlas", "--timeout", "15",
            cwd=root,
        )
        try:
            deadline = time.monotonic() + 15
            status = started
            while time.monotonic() < deadline:
                status = run_json(
                    executable,
                    "--db", str(database), "--json", "federation", "sync",
                    "daemon-status", "--project", "atlas",
                    cwd=root,
                )
                if int(status.get("successful_cycles") or 0) >= 1:
                    break
                time.sleep(0.1)
            else:
                raise AssertionError("native federation worker did not complete a healthy cycle")
        finally:
            stopped = run_json(
                executable,
                "--db", str(database), "--json", "federation", "sync",
                "daemon-stop", "--project", "atlas", "--timeout", "15",
                cwd=root,
            )
        removed = run_json(
            executable,
            "--db", str(database), "--json", "federation", "sync",
            "daemon-remove", "--project", "atlas",
            cwd=root,
        )

        if configured["state"] != "configured":
            raise AssertionError("native federation configuration failed")
        if started["state"] != "running" or status["sync_state"] != "healthy":
            raise AssertionError("native federation service did not become healthy")
        if stopped["state"] != "configured" or removed["state"] != "not_configured":
            raise AssertionError("native federation cleanup failed")
        if not database.is_file() or not identity_root.is_dir() or not relay_root.is_dir():
            raise AssertionError("native federation removal deleted local user data")

        print(json.dumps({"status": "ok", "checks": 8}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
