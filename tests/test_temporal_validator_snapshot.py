from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from rta_brain import temporal_validators


def _sqlite_file(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE evidence(value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence(value) VALUES ('approved')")
        connection.commit()
    finally:
        connection.close()


def test_sqlite_integrity_validates_a_stable_private_snapshot(tmp_path):
    target = tmp_path / "evidence.sqlite"
    _sqlite_file(target)
    real_connect = sqlite3.connect
    opened: list[str] = []

    def observed_connect(database, *args, **kwargs):
        opened.append(str(database))
        return real_connect(database, *args, **kwargs)

    with patch.object(temporal_validators.sqlite3, "connect", side_effect=observed_connect):
        status, evidence = temporal_validators.evaluate_validator(
            "sqlite_integrity",
            {"path": target.name},
            active_root=tmp_path,
            allow_command=False,
            trusted_executables=(),
        )

    assert status == "pass"
    assert evidence["quick_check"] == "ok"
    assert opened
    assert all(target.as_uri() not in database for database in opened)


def test_stable_read_rejects_changed_ancestor_identity(tmp_path):
    directory = tmp_path / "evidence"
    directory.mkdir()
    target = directory / "proof.txt"
    target.write_text("approved", encoding="utf-8")
    baseline = temporal_validators._ancestor_snapshot(target)
    changed = list(baseline)
    ancestor, identity = changed[-1]
    changed[-1] = (ancestor, (identity[0], identity[1] + 1))

    with pytest.raises(RuntimeError, match="ancestor"):
        temporal_validators._assert_stable_ancestors(tuple(changed))
