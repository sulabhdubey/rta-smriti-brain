"""Cross-platform trusted lifecycle soak with privacy-safe JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from rta_brain import db
from rta_brain.capture_daemon import capture_status, stop_capture
from rta_brain.console_daemon import console_status, stop_console
from rta_brain.continuity_daemon import continuity_status, stop_continuity
from rta_brain.trusted_lifecycle import (
    apply_lifecycle,
    inspect_lifecycle,
    plan_lifecycle,
    verify_lifecycle,
)
from rta_brain.watch_daemon import stop_watcher, watcher_status

SCHEMA = "rta-smriti.lifecycle-soak/v1"
PROJECT = "atlas-soak"
DEFAULT_DURATION_SECONDS = 60.0
DEFAULT_INTERVAL_SECONDS = 0.5
CI_DURATION_SECONDS = 12.0
CI_INTERVAL_SECONDS = 0.25
SAMPLE_CONVERGENCE_SECONDS = 2.0
SAMPLE_RETRY_SECONDS = 0.05


def _digest(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _aggregate(values: list[str]) -> str:
    return _digest(sorted(values))


def build_public_report(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Build a bounded report containing no paths, transcript text, or source text."""

    samples = [str(item) for item in facts.get("sample_digests", [])]
    failures = [str(item) for item in facts.get("failure_digests", [])]
    mutations = [str(item) for item in facts.get("mutation_digests", [])]
    restarts = [str(item) for item in facts.get("restart_digests", [])]
    cleanup = [str(item) for item in facts.get("cleanup_digests", [])]
    body = {
        "schema": SCHEMA,
        "status": "passed" if not failures and cleanup else "failed",
        "platform": {
            "system": str(facts["platform"]["system"]),
            "machine": str(facts["platform"]["machine"]),
        },
        "runtime": {
            "implementation": str(facts["runtime"]["implementation"]),
            "python": str(facts["runtime"]["python"]),
        },
        "configuration": {
            "duration_seconds": float(facts["configuration"]["duration_seconds"]),
            "interval_seconds": float(facts["configuration"]["interval_seconds"]),
            "console_enabled": bool(facts["configuration"]["console_enabled"]),
        },
        "samples": {"count": len(samples), "digest": _aggregate(samples)},
        "failures": {"count": len(failures), "digest": _aggregate(failures)},
        "mutations": {"count": len(mutations), "digest": _aggregate(mutations)},
        "restarts": {"count": len(restarts), "digest": _aggregate(restarts)},
        "cleanup": {
            "state": "complete" if cleanup else "failed",
            "count": len(cleanup),
            "digest": _aggregate(cleanup),
        },
    }
    return {**body, "report_digest": _digest(body)}


def _desired_state(*, running: bool, console_enabled: bool) -> dict[str, Any]:
    return {
        "watcher": running,
        "capture": running,
        "continuity": running,
        "console": running and console_enabled,
        "login_restoration": False,
        "mcp_hosts": [],
        "schema_policy": "current-only",
    }


def _confirm(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "approved": True,
        "plan_digest": plan["plan_digest"],
        "observed_state_digest": plan["observed_state_digest"],
    }


def _apply(request: Mapping[str, Any], desired: Mapping[str, Any]) -> dict[str, Any]:
    plan = plan_lifecycle(request, desired)
    if plan.get("blocked"):
        raise RuntimeError("lifecycle plan is blocked")
    result = apply_lifecycle(plan, _confirm(plan))
    if result.get("state") != "complete":
        raise RuntimeError("lifecycle apply did not complete")
    return {"plan": plan, "result": result}


def _service_ownership(request: Mapping[str, Any], console_enabled: bool) -> dict[str, int]:
    database = Path(request["db_path"])
    project = str(request["project"])
    states = {
        "watcher": watcher_status(database, project),
        "capture": capture_status(database),
        "continuity": continuity_status(database, project),
    }
    if console_enabled:
        states["console"] = console_status(Path(request["brain_dir"]))
    owners: dict[str, int] = {}
    for service, state in states.items():
        if state.get("state") not in {"running", "current"}:
            raise RuntimeError(f"{service} exited or is not healthy")
        if state.get("state") in {"stale", "live-unverifiable"}:
            raise RuntimeError(f"{service} ownership is not verifiable")
        if state.get("process_alive") is False:
            raise RuntimeError(f"{service} process exited")
        if service == "watcher" and state.get("process_identity_status") != "matched":
            raise RuntimeError("watcher ownership is not verifiable")
        if service in {"capture", "continuity"} and not state.get(
            "process_identity_matches"
        ):
            raise RuntimeError(f"{service} ownership is not verifiable")
        pid = int(state.get("pid") or 0)
        if pid <= 0:
            raise RuntimeError(f"{service} owner is unavailable")
        owners[service] = pid
    if len(set(owners.values())) != len(owners):
        raise RuntimeError("duplicate lifecycle process ownership detected")
    return owners


def _sample(request: Mapping[str, Any], console_enabled: bool) -> str:
    inspected = inspect_lifecycle(request)
    verified = verify_lifecycle(request, "process")
    expected = {
        "watcher": "running",
        "capture": "running",
        "continuity": "running",
        "console": "running" if console_enabled else "stopped",
    }
    for service, state in expected.items():
        if inspected["services"].get(service) not in {
            state,
            "current" if state == "running" else state,
        }:
            raise RuntimeError(f"{service} lifecycle state mismatch")
    if not verified.get("ready"):
        raise RuntimeError("trusted lifecycle process verification failed")
    _service_ownership(request, console_enabled)
    signature = {
        "services": inspected["services"],
        "health_axes": {
            key: value.get("state")
            for key, value in inspected["health_axes"].items()
        },
        "enrollment_state": inspected.get("enrollment_state"),
        "verification_state": verified.get("state"),
        "reason_codes": sorted(verified.get("reason_codes", [])),
    }
    return _digest(signature)


def _sample_with_convergence(
    request: Mapping[str, Any],
    console_enabled: bool,
    *,
    timeout_seconds: float = SAMPLE_CONVERGENCE_SECONDS,
    interval_seconds: float = SAMPLE_RETRY_SECONDS,
) -> str:
    """Require a stable lifecycle sample while tolerating one-observation races."""

    deadline = time.monotonic() + timeout_seconds
    last_error: RuntimeError | None = None
    while time.monotonic() < deadline:
        try:
            return _sample(request, console_enabled)
        except RuntimeError as error:
            last_error = error
        time.sleep(interval_seconds)
    raise RuntimeError("lifecycle sampling did not converge") from last_error


def _deep_freshness(request: Mapping[str, Any]) -> dict[str, Any]:
    connection = db.connect(Path(request["db_path"]))
    try:
        return db.stale_check(
            connection,
            str(request["project"]),
            deep=True,
            detail_limit=0,
            active_root=Path(request["root"]),
        )
    finally:
        connection.close()


def _wait_for_fresh_repository(
    request: Mapping[str, Any],
    *,
    timeout_seconds: float,
    interval_seconds: float,
) -> dict[str, Any]:
    """Require freshness to reconverge while tolerating a transient read race."""

    return _wait_for(
        lambda: (
            current
            if (current := _deep_freshness(request)).get("state") == "fresh"
            else None
        ),
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
        label="repository freshness",
    )


def _wait_for_continuity_caught_up(
    request: Mapping[str, Any],
    *,
    minimum_events: int,
    timeout_seconds: float,
    interval_seconds: float,
) -> dict[str, Any]:
    """Wait until the worker has published a post-capture zero-backlog cycle."""

    return _wait_for(
        lambda: (
            current
            if (
                int((current := continuity_status(
                    Path(request["db_path"]), str(request["project"])
                )).get("events_inserted") or 0) >= minimum_events
                and int(current.get("sessions_pending") or 0) == 0
            )
            else None
        ),
        timeout_seconds=timeout_seconds,
        interval_seconds=interval_seconds,
        label="continuity catch-up",
    )


def _wait_for(
    predicate,
    *,
    timeout_seconds: float,
    interval_seconds: float,
    label: str,
) -> Any:
    deadline = time.monotonic() + timeout_seconds
    last = None
    while time.monotonic() < deadline:
        last = predicate()
        if last:
            return last
        time.sleep(interval_seconds)
    raise RuntimeError(f"{label} did not converge")


def _failure_digest(phase: str, error: BaseException) -> str:
    return _digest({"phase": phase, "error_class": error.__class__.__name__})


def run_lifecycle_soak(
    *,
    duration_seconds: float = DEFAULT_DURATION_SECONDS,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    console_enabled: bool = False,
    temporary_parent: Path | None = None,
) -> dict[str, Any]:
    """Exercise an isolated trusted lifecycle and return only public-safe evidence."""

    duration = float(duration_seconds)
    interval = float(interval_seconds)
    if not 0.1 <= duration <= 86_400:
        raise ValueError("duration must be between 0.1 seconds and 24 hours")
    if not 0.05 <= interval <= min(duration, 60.0):
        raise ValueError("interval must be between 0.05 seconds and the duration")

    facts: dict[str, Any] = {
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "runtime": {
            "implementation": platform.python_implementation().casefold(),
            "python": platform.python_version(),
        },
        "configuration": {
            "duration_seconds": duration,
            "interval_seconds": interval,
            "console_enabled": console_enabled,
        },
        "sample_digests": [],
        "failure_digests": [],
        "mutation_digests": [],
        "restart_digests": [],
        "cleanup_digests": [],
    }
    temporary = tempfile.TemporaryDirectory(
        prefix="rta-smriti-lifecycle-soak-",
        dir=str(temporary_parent) if temporary_parent else None,
    )
    request: dict[str, Any] | None = None
    phase = "setup"
    try:
        base = Path(temporary.name)
        project_root = base / "atlas"
        sessions_root = base / "sessions"
        brain_dir = base / "brains"
        project_root.mkdir()
        sessions_root.mkdir()
        brain_dir.mkdir()
        source = project_root / "atlas.py"
        source.write_text("ATLAS_REVISION = 1\n", encoding="utf-8")
        session = sessions_root / "atlas.jsonl"
        session_rows = [
            {"type": "session_meta", "payload": {"id": "atlas-soak", "cwd": str(project_root)}},
            {"type": "response_item", "payload": {"type": "message", "role": "user", "content": "Verify Atlas lifecycle"}},
        ]
        session.write_text(
            "\n".join(json.dumps(row, sort_keys=True) for row in session_rows) + "\n",
            encoding="utf-8",
        )
        database = brain_dir / "atlas.sqlite"
        connection = db.connect(database)
        try:
            db.init_project(connection, PROJECT, project_root)
            db.ingest_repo(connection, project_root, project=PROJECT, force=True)
            db.save_checkpoint(
                connection,
                PROJECT,
                "Verify the synthetic Atlas lifecycle",
                verified_evidence="Synthetic fixture initialized",
                next_action="Run the lifecycle soak",
            )
        finally:
            connection.close()
        request = {
            "tool_root": REPOSITORY_ROOT,
            "brain_dir": brain_dir,
            "db_path": database,
            "project": PROJECT,
            "root": project_root,
            "sessions_root": sessions_root,
        }

        phase = "start"
        started = _apply(
            request,
            _desired_state(running=True, console_enabled=console_enabled),
        )
        first_owners = _service_ownership(request, console_enabled)
        _wait_for_continuity_caught_up(
            request,
            minimum_events=2,
            timeout_seconds=15.0,
            interval_seconds=min(interval, 0.5),
        )
        facts["sample_digests"].append(
            _sample_with_convergence(request, console_enabled)
        )

        phase = "idempotency"
        replay = apply_lifecycle(started["plan"], _confirm(started["plan"]))
        if not replay.get("idempotent_replay"):
            raise RuntimeError("lifecycle apply replay was not idempotent")
        if _service_ownership(request, console_enabled) != first_owners:
            raise RuntimeError("idempotent replay replaced a lifecycle owner")
        facts["sample_digests"].append(
            _sample_with_convergence(request, console_enabled)
        )

        phase = "repository-mutation"
        source.write_text("ATLAS_REVISION = 2\n", encoding="utf-8")
        freshness = _wait_for_fresh_repository(
            request,
            timeout_seconds=15.0,
            interval_seconds=min(interval, 0.5),
        )
        facts["mutation_digests"].append(
            _digest({"kind": "repository", "state": freshness["state"]})
        )

        phase = "session-mutation"
        with session.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(
                json.dumps(
                    {"type": "event_msg", "payload": {"type": "task_complete", "message": "Done"}},
                    sort_keys=True,
                )
                + "\n"
            )
        continuity = _wait_for(
            lambda: (
                current
                if int((current := continuity_status(database, PROJECT)).get("events_inserted") or 0) >= 3
                else None
            ),
            timeout_seconds=15.0,
            interval_seconds=min(interval, 0.5),
            label="continuity ingestion",
        )
        facts["mutation_digests"].append(
            _digest(
                {
                    "kind": "session",
                    "events_inserted": int(continuity.get("events_inserted") or 0),
                }
            )
        )

        phase = "restart-stop"
        _apply(
            request,
            _desired_state(running=False, console_enabled=console_enabled),
        )
        stopped = inspect_lifecycle(request)
        if any(
            stopped["services"].get(service) != "stopped"
            for service in ("watcher", "capture", "continuity", "console")
        ):
            raise RuntimeError("lifecycle stop left a service running")

        phase = "restart-start"
        _apply(
            request,
            _desired_state(running=True, console_enabled=console_enabled),
        )
        restarted_owners = _service_ownership(request, console_enabled)
        facts["restart_digests"].append(
            _digest(
                {
                    "services": sorted(restarted_owners),
                    "owners_replaced": all(
                        restarted_owners[name] != first_owners[name]
                        for name in restarted_owners
                    ),
                }
            )
        )

        phase = "steady-state"
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            facts["sample_digests"].append(
                _sample_with_convergence(request, console_enabled)
            )
            _wait_for_fresh_repository(
                request,
                timeout_seconds=min(15.0, max(1.0, interval)),
                interval_seconds=min(interval, 0.5),
            )
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(interval, remaining))
    except BaseException as error:  # noqa: BLE001 - report contains only class digest
        facts["failure_digests"].append(_failure_digest(phase, error))
    finally:
        cleanup_failures = 0
        if request is not None:
            cleanup_operations = (
                lambda: stop_console(Path(request["brain_dir"]), timeout=10.0),
                lambda: stop_continuity(Path(request["db_path"]), PROJECT, timeout=10.0),
                lambda: stop_capture(Path(request["db_path"]), timeout=10.0),
                lambda: stop_watcher(Path(request["db_path"]), PROJECT, timeout=10.0),
            )
            for operation in cleanup_operations:
                try:
                    operation()
                except BaseException as error:  # noqa: BLE001
                    cleanup_failures += 1
                    facts["failure_digests"].append(_failure_digest("cleanup", error))
            try:
                states = {
                    "watcher": watcher_status(Path(request["db_path"]), PROJECT).get("state"),
                    "capture": capture_status(Path(request["db_path"])).get("state"),
                    "continuity": continuity_status(Path(request["db_path"]), PROJECT).get("state"),
                    "console": console_status(Path(request["brain_dir"])).get("state"),
                }
                if any(state != "stopped" for state in states.values()):
                    raise RuntimeError("cleanup state verification failed")
                facts["cleanup_digests"].append(_digest(states))
            except BaseException as error:  # noqa: BLE001
                cleanup_failures += 1
                facts["failure_digests"].append(_failure_digest("cleanup-verify", error))
        try:
            temporary.cleanup()
        except BaseException as error:  # noqa: BLE001
            cleanup_failures += 1
            facts["failure_digests"].append(
                _failure_digest("temporary-cleanup", error)
            )
        if cleanup_failures:
            facts["cleanup_digests"].clear()
    return build_public_report(facts)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    duration = parser.add_mutually_exclusive_group()
    duration.add_argument(
        "--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS
    )
    duration.add_argument(
        "--local-hours",
        type=float,
        help="Run the steady-state phase for this many hours (maximum 24).",
    )
    duration.add_argument(
        "--ci-short",
        action="store_true",
        help="Use the bounded hosted-CI smoke duration and interval.",
    )
    parser.add_argument("--interval-seconds", type=float, default=None)
    parser.add_argument(
        "--with-console",
        action="store_true",
        help="Include the managed console; off by default to avoid port collisions.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.local_hours is not None:
        duration = args.local_hours * 3_600.0
    elif args.ci_short:
        duration = CI_DURATION_SECONDS
    else:
        duration = args.duration_seconds
    interval = (
        args.interval_seconds
        if args.interval_seconds is not None
        else (CI_INTERVAL_SECONDS if args.ci_short else DEFAULT_INTERVAL_SECONDS)
    )
    report = run_lifecycle_soak(
        duration_seconds=duration,
        interval_seconds=interval,
        console_enabled=args.with_console,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
