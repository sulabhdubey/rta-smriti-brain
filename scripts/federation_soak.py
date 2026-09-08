"""Exercise sustained governed federation sync, recovery, rotation, and cleanup."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rta_brain.db import init_schema
from rta_brain.federation import store_event
from rta_brain.federation_crypto import (
    PublicFederationIdentity,
    create_encrypted_event,
    create_identity,
    generate_scope_key,
)
from rta_brain.federation_governance import (
    add_peer,
    create_scope,
    create_space,
    grant_capabilities,
    rotate_scope_key,
    validate_and_accept_event,
)
from rta_brain.federation_invitation import (
    accept_invitation_bundle,
    create_invitation_bundle,
)
from rta_brain.federation_transport import (
    FederationTransportError,
    FilesystemFederationRelay,
    pull_and_validate_from_relay,
    push_to_relay,
)

PASSPHRASE = b"synthetic federation soak passphrase"


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_schema(conn)
    return conn


class _OneShotOutage:
    def __init__(self, relay: FilesystemFederationRelay) -> None:
        self.relay = relay
        self.failed = False

    def inventory(self, space_id: str, scope_id: str | None = None) -> list[str]:
        return self.relay.inventory(space_id, scope_id=scope_id)

    def put_event(self, envelope):
        if not self.failed:
            self.failed = True
            raise FederationTransportError("synthetic relay outage")
        return self.relay.put_event(envelope)

    def get_event(self, space_id: str, event_id: str):
        return self.relay.get_event(space_id, event_id)


def _event_ids(conn: sqlite3.Connection) -> set[str]:
    return {str(row[0]) for row in conn.execute("SELECT event_id FROM federation_events")}


def _relay_contains_plaintext(root: Path) -> bool:
    marker = b"synthetic-soak-memory"
    for path in root.rglob("*"):
        if path.is_file() and marker in path.read_bytes():
            return True
    return False


def run_soak(
    *,
    duration_seconds: float | None = None,
    cycles: int | None = None,
    cycle_seconds: float = 5.0,
    outage_every: int = 30,
    restart_every: int = 60,
    rotate_every: int = 120,
    assert_invariants: bool = False,
) -> dict[str, Any]:
    if cycles is None and (duration_seconds is None or duration_seconds <= 0):
        raise ValueError("duration_seconds must be positive when cycles is omitted")
    if cycles is not None and cycles < 1:
        raise ValueError("cycles must be positive")
    if cycle_seconds < 0:
        raise ValueError("cycle_seconds must not be negative")
    for name, value in (
        ("outage_every", outage_every),
        ("restart_every", restart_every),
        ("rotate_every", rotate_every),
    ):
        if value < 1:
            raise ValueError(f"{name} must be positive")

    started = time.monotonic()
    deadline = None if duration_seconds is None else started + duration_seconds
    temporary_root: Path | None = None
    report: dict[str, Any]
    with tempfile.TemporaryDirectory(prefix="rta-smriti-federation-soak-") as tmp:
        temporary_root = Path(tmp)
        source_path = temporary_root / "source.sqlite"
        destination_path = temporary_root / "destination.sqlite"
        relay_root = temporary_root / "relay"
        owner = create_identity(temporary_root / "owner", passphrase=PASSPHRASE)
        reader = create_identity(temporary_root / "reader", passphrase=PASSPHRASE)
        reader_public = PublicFederationIdentity(
            reader.identity_id,
            reader.signing_public_bytes,
            reader.envelope_public_bytes,
        )
        source = _connect(source_path)
        destination: sqlite3.Connection | None = None
        try:
            source.execute(
                "INSERT INTO projects(id, name, created_at) VALUES "
                "(1, 'synthetic-soak', '2026-09-07T00:00:00+00:00')"
            )
            source.commit()
            space = create_space(
                source,
                project_id=1,
                owner=owner,
                owner_key_reference="synthetic-owner",
            )
            scope = create_scope(
                source,
                project_id=1,
                space_id=space["space_id"],
                owner=owner,
                kind="team",
                label="Synthetic team",
            )
            add_peer(
                source,
                project_id=1,
                space_id=space["space_id"],
                author=owner,
                peer=reader,
                label="Synthetic reader",
            )
            grant_capabilities(
                source,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                subject_peer_id=reader.identity_id,
                capabilities=("read", "index", "sync"),
            )
            scope_key = generate_scope_key()
            epoch = rotate_scope_key(
                source,
                project_id=1,
                space_id=space["space_id"],
                scope_id=scope["scope_id"],
                author=owner,
                scope_key=scope_key,
            )["epoch"]
            destination = _connect(destination_path)
            source.backup(destination)
            relay = FilesystemFederationRelay(relay_root)
            completed = 0
            outages = 0
            restarts = 0
            rotations = 0
            previous_event_id: str | None = None

            while cycles is None or completed < cycles:
                if deadline is not None and completed > 0 and time.monotonic() >= deadline:
                    break
                completed += 1
                if completed % rotate_every == 0:
                    scope_key = generate_scope_key()
                    epoch = rotate_scope_key(
                        source,
                        project_id=1,
                        space_id=space["space_id"],
                        scope_id=scope["scope_id"],
                        author=owner,
                        scope_key=scope_key,
                    )["epoch"]
                    invitation = create_invitation_bundle(
                        source,
                        project_id=1,
                        space_id=space["space_id"],
                        author=owner,
                        recipient=reader_public,
                        scope_ids=(scope["scope_id"],),
                        expires_at=(datetime.now(UTC) + timedelta(days=1)).isoformat(),
                    )
                    accept_invitation_bundle(
                        destination,
                        project_id=1,
                        encoded=invitation,
                        recipient=reader,
                        recipient_key_reference="synthetic-reader",
                        _refresh_existing=True,
                    )
                    rotations += 1

                event = create_encrypted_event(
                    {
                        "event_type": "memory.asserted",
                        "object_id": f"soak-{completed}",
                        "text": f"synthetic-soak-memory-{completed}",
                        "valid_from": "2026-09-07T00:00:00+00:00",
                        "privacy_class": "internal",
                        "epistemic_state": "observed",
                    },
                    identity=owner,
                    scope_key=scope_key,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    epoch=epoch,
                    author_sequence=completed,
                    capability_event_id=space["bootstrap"]["event_id"],
                    parents=(() if previous_event_id is None else (previous_event_id,)),
                    received_at=datetime.now(UTC).isoformat(),
                )
                store_event(source, project_id=1, envelope=event)
                validate_and_accept_event(
                    source,
                    project_id=1,
                    envelope=event,
                    author_signing_public_key=owner.signing_public_bytes,
                    scope_key=scope_key,
                )
                previous_event_id = event.event_id

                if completed % outage_every == 0:
                    try:
                        push_to_relay(
                            source,
                            project_id=1,
                            space_id=space["space_id"],
                            scope_id=scope["scope_id"],
                            actor_peer_id=owner.identity_id,
                            relay=_OneShotOutage(relay),
                        )
                    except FederationTransportError as exc:
                        if str(exc) != "synthetic relay outage":
                            raise
                        outages += 1
                    else:
                        raise AssertionError("synthetic relay outage was not observed")

                push_to_relay(
                    source,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    actor_peer_id=owner.identity_id,
                    relay=relay,
                )
                pull_and_validate_from_relay(
                    destination,
                    project_id=1,
                    space_id=space["space_id"],
                    scope_id=scope["scope_id"],
                    actor=reader,
                    relay=relay,
                    transport_id="synthetic-soak-relay",
                )

                if _event_ids(source) != _event_ids(destination):
                    raise AssertionError("federation peers did not converge after recovery")

                if completed % restart_every == 0:
                    source.close()
                    destination.close()
                    source = _connect(source_path)
                    destination = _connect(destination_path)
                    relay = FilesystemFederationRelay(relay_root)
                    restarts += 1

                if completed % 60 == 0:
                    print(json.dumps({"cycles_completed": completed, "state": "running"}), flush=True)
                if cycle_seconds:
                    time.sleep(cycle_seconds)

            source_ids = _event_ids(source)
            destination_ids = _event_ids(destination)
            plaintext_absent = not _relay_contains_plaintext(relay_root)
            report = {
                "schema": "rta-smriti.federation-soak/v1",
                "state": "passed",
                "cycles_completed": completed,
                "duration_seconds": round(time.monotonic() - started, 3),
                "outages_recovered": outages,
                "database_restarts": restarts,
                "key_rotations": rotations,
                "source_event_count": len(source_ids),
                "destination_event_count": len(destination_ids),
                "converged": source_ids == destination_ids,
                "relay_plaintext_absent": plaintext_absent,
            }
            if assert_invariants and (
                not report["converged"]
                or not report["relay_plaintext_absent"]
                or report["cycles_completed"] < 1
            ):
                raise AssertionError("federation soak invariant failed")
        finally:
            source.close()
            if destination is not None:
                destination.close()

    report["temporary_state_removed"] = bool(
        temporary_root is not None and not temporary_root.exists()
    )
    if assert_invariants and not report["temporary_state_removed"]:
        raise AssertionError("federation soak did not clean up temporary state")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--cycles", type=int)
    parser.add_argument("--cycle-seconds", type=float, default=5.0)
    parser.add_argument("--outage-every", type=int, default=30)
    parser.add_argument("--restart-every", type=int, default=60)
    parser.add_argument("--rotate-every", type=int, default=120)
    parser.add_argument("--assert-invariants", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = run_soak(
        duration_seconds=args.duration_seconds,
        cycles=args.cycles,
        cycle_seconds=args.cycle_seconds,
        outage_every=args.outage_every,
        restart_every=args.restart_every,
        rotate_every=args.rotate_every,
        assert_invariants=args.assert_invariants,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8", newline="\n")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
