"""Minimal entry point for the detached operator-console process."""

from __future__ import annotations

import argparse
from pathlib import Path

from .console_daemon import run_console_worker


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--tool-root", required=True)
    parser.add_argument("--brain-dir", required=True)
    parser.add_argument("--default-db")
    parser.add_argument("--default-project")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state-file", required=True)
    parser.add_argument("--stop-file", required=True)
    parser.add_argument("--lock-file", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--federation-identity-root")
    parser.add_argument("--federation-passphrase-file")
    args = parser.parse_args(argv)
    return run_console_worker(
        Path(args.tool_root),
        Path(args.brain_dir),
        Path(args.default_db) if args.default_db else None,
        args.default_project,
        args.host,
        args.port,
        Path(args.state_file),
        Path(args.stop_file),
        Path(args.lock_file),
        Path(args.token_file),
        Path(args.federation_identity_root) if args.federation_identity_root else None,
        Path(args.federation_passphrase_file) if args.federation_passphrase_file else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
