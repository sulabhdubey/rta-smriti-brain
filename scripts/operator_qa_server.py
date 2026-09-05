"""Create a disposable brain and serve it for rendered operator acceptance."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))

from rta_brain.capture import append_event, register_policy, register_source
from rta_brain.capture_types import CapturePolicy, CaptureSource, NormalizedEvent
from rta_brain.console import create_dashboard_server
from rta_brain.db import connect, ingest_repo, init_project, remember, save_checkpoint
from rta_brain.governance import create_policy


def _write_fixture(repo: Path) -> None:
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "README.md").write_text(
        "# Operator demo\n\nA bounded queue uses retry budgets and backpressure.\n",
        encoding="utf-8",
    )
    (repo / "src" / "helpers.py").write_text(
        "def queue_budget():\n    return 3\n",
        encoding="utf-8",
    )
    (repo / "src" / "service.py").write_text(
        "from src.helpers import queue_budget\n\ndef run_queue():\n    return queue_budget()\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_service.py").write_text(
        "from src.service import run_queue\n\ndef test_queue():\n    assert run_queue() == 3\n",
        encoding="utf-8",
    )
    (repo / "service.json").write_text('{"retry_budget": 3}\n', encoding="utf-8")


def _init_git(repo: Path) -> None:
    commands = [
        ["git", "init", "-q"],
        ["git", "config", "user.email", "operator@example.invalid"],
        ["git", "config", "user.name", "Rta-Smriti Operator QA"],
        ["git", "add", "."],
        ["git", "commit", "-qm", "fixture"],
    ]
    for command in commands:
        subprocess.run(command, cwd=repo, check=True, capture_output=True, text=True)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: operator_qa_server.py TEMP_ROOT")
    root = Path(sys.argv[1]).resolve()
    repo = root / "operator-demo"
    brain_dir = root / "brains"
    repo.mkdir(parents=True)
    brain_dir.mkdir(parents=True)
    _write_fixture(repo)
    _init_git(repo)

    database = brain_dir / "operator-demo.sqlite"
    conn = connect(database)
    try:
        init_project(conn, "operator-demo", str(repo))
        ingest_repo(conn, repo, project="operator-demo")
        remember(
            conn,
            "Queue changes require the focused service test.",
            project="operator-demo",
            memory_type="decision",
            pramana="sabda",
            confidence=0.95,
            provenance={
                "source_path": "README.md",
                "source_hash": "a" * 64,
                "verification_status": "verified",
            },
        )
        save_checkpoint(
            conn,
            "operator-demo",
            "Validate the queue release",
            verified_evidence="The repository index and service test exist.",
            remaining_gaps="Run rendered operator acceptance.",
            next_action="Generate a bounded context pack.",
            prohibited_repetition="Do not bypass the release gate.",
        )
        create_policy(
            conn,
            project="operator-demo",
            kind="required_check",
            statement="Privacy proof is required before publication.",
            effect="block",
            action_contains="publish",
            required_check="privacy-proof",
            pramana="pratyaksha",
            confidence=0.95,
            provenance={
                "source_path": "README.md",
                "source_hash": "b" * 64,
                "verification_status": "verified",
            },
        )
        capture_policy = CapturePolicy.continuity()
        register_policy(
            conn,
            project="operator-demo",
            active_root=repo,
            policy_id="continuity",
            policy_version=1,
            policy=capture_policy,
        )
        capture_source = CaptureSource(
            source_id="codex-operator",
            adapter="codex-jsonl",
            adapter_version="1",
            installation_scope="transcript",
            config_fingerprint=hashlib.sha256(b"operator-qa-capture").hexdigest(),
        )
        register_source(
            conn,
            project="operator-demo",
            active_root=repo,
            source=capture_source,
            policy_digest=capture_policy.digest,
        )
        for cursor, name, attributes, gap_state in (
            ("1", "session.started.v1", {"status": "started"}, "none"),
            ("2", "capture.gap.v1", {"reason": "fixture-gap", "from_cursor": "1", "to_cursor": "3"}, "detected"),
            (
                "3",
                "turn.interrupted.v1",
                {
                    "reason": "restart",
                    "summary": (
                        "Resume the verified operator task. Never expose "
                        + "sk_" + "live_" + "Q" * 24
                    ),
                },
                "none",
            ),
        ):
            append_event(
                conn,
                project="operator-demo",
                active_root=repo,
                source_id=capture_source.source_id,
                event=NormalizedEvent(
                    event_name=name,
                    session_id="operator-session",
                    source_cursor=cursor,
                    observed_at=f"2026-08-22T09:00:0{cursor}+00:00",
                    occurred_at=f"2026-08-22T09:00:0{cursor}+00:00",
                    attributes=attributes,
                    actor_type="agent",
                    actor_id="operator-fixture",
                ),
                idempotency_key=f"operator:capture:{cursor}",
                cursor_kind="sequence",
                original_bytes=128,
                gap_state=gap_state,
            )
    finally:
        conn.close()

    server, _config, url = create_dashboard_server(
        TOOL_ROOT,
        brain_dir,
        default_db=database,
        default_project="operator-demo",
        host="127.0.0.1",
        port=0,
        instance_id="operator-qa",
        sessions_root=root / ".codex" / "sessions",
    )
    print(json.dumps({"url": url, "repo": str(repo), "database": str(database)}), flush=True)
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
