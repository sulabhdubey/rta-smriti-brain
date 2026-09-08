"""Private command-line entry point for the managed federation sync worker."""

from __future__ import annotations

import argparse
from pathlib import Path

from .federation_daemon import run_federation_sync_worker
from .runtime_control import detach_current_worker_session


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config-file", required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--stop-file", required=True)
    parser.add_argument("--lock-file", required=True)
    args = parser.parse_args()
    detach_current_worker_session()
    return run_federation_sync_worker(
        Path(args.config_file),
        Path(args.state_file),
        Path(args.stop_file),
        Path(args.lock_file),
    )


if __name__ == "__main__":
    raise SystemExit(main())
