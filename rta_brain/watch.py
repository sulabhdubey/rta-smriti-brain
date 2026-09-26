"""Foreground polling watcher built on the incremental repository indexer."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from .db import ingest_repo


def watch_repository(
    conn,
    root: Path,
    project: str = "default",
    interval_seconds: float = 2.0,
    max_cycles: int | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
    writer_lease_factory=None,
) -> dict:
    if interval_seconds < 0:
        raise ValueError("watch interval must be zero or greater")
    cycles = 0
    updated_files = 0
    removed_files = 0
    events = []
    interrupted = False
    try:
        while max_cycles is None or cycles < max_cycles:
            result = ingest_repo(
                conn, root, project=project,
                _writer_lease_factory=writer_lease_factory,
                _initialize_schema=writer_lease_factory is None,
            )
            event = {
                "cycle": cycles + 1,
                "updated_files": result["updated_files"],
                "removed_files": result["removed_files"],
                "blocked_files": result.get("blocked_files", 0),
                "manifest_unchanged": result["manifest_unchanged"],
            }
            events.append(event)
            updated_files += event["updated_files"]
            removed_files += event["removed_files"]
            cycles += 1
            if max_cycles is None or cycles < max_cycles:
                sleep_fn(interval_seconds)
    except KeyboardInterrupt:
        interrupted = True
    return {
        "status": "ok", "project": project, "root": str(Path(root).resolve()), "cycles": cycles,
        "updated_files": updated_files, "removed_files": removed_files, "interrupted": interrupted, "events": events,
    }
