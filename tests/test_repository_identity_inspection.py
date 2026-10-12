"""Identity inspection must agree with canonical binding helpers."""
from unittest.mock import patch
from contextlib import closing
import subprocess

import pytest

from rta_brain import console, db, repository


def test_inspection_retains_git_checkout_with_preexisting_local_project_identity(tmp_path):
    (tmp_path / ".rta-smriti").mkdir()
    (tmp_path / ".rta-smriti" / "brain_id").write_text("a" * 32, encoding="ascii")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / repository.GIT_CHECKOUT_IDENTITY_FILE).write_text("b" * 32, encoding="ascii")
    layout = (tmp_path, git_dir, git_dir)
    with patch.object(repository, "verified_git_layout", return_value=layout):
        expected_repo = repository.repository_identity(tmp_path, create_marker=False)
        expected_checkout = repository.checkout_identity(tmp_path, create_marker=False)
        observed = repository.inspect_repository(tmp_path, include_worktree=False)
    assert observed.repository_identity == expected_repo
    assert observed.checkout_identity == expected_checkout


def test_unavailable_git_cannot_mint_fallback_identity_for_existing_git_tokens(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / repository.GIT_IDENTITY_FILE).write_text("a" * 32, encoding="ascii")
    (git_dir / repository.GIT_CHECKOUT_IDENTITY_FILE).write_text("b" * 32, encoding="ascii")
    with patch.object(repository, "verified_git_layout", return_value=None):
        with pytest.raises(ValueError, match="Git.*verif|identity.*unavailable"):
            repository.repository_identity(tmp_path)
        with pytest.raises(ValueError, match="Git.*verif|identity.*unavailable"):
            repository.checkout_identity(tmp_path)
    assert not (tmp_path / repository.IDENTITY_DIR).exists()


@pytest.mark.parametrize("mismatch", [None, "repository", "checkout"])
def test_health_uses_canonical_legacy_git_binding_without_writes(tmp_path, mismatch):
    root = tmp_path / "project"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    (root / "README.md").write_text("# Fictional binding fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                   check=True, capture_output=True)
    database = tmp_path / "brain.sqlite"
    with closing(db.connect(database)) as conn:
        db.init_project(conn, "fixture", str(root))
        legacy = repository.stable_git_identity(root)
        assert legacy and legacy.startswith("git:")
        conn.execute("UPDATE projects SET repository_identity=? WHERE name='fixture'",
                     ("git:" + "0" * 40 if mismatch == "repository" else legacy,))
        if mismatch == "checkout":
            conn.execute("UPDATE projects SET checkout_identity='git-checkout:wrong' WHERE name='fixture'")
        conn.commit()
    (root / ".git" / repository.GIT_IDENTITY_FILE).write_text("a" * 32, encoding="ascii")
    inspection = repository.inspect_repository(root, include_worktree=False)
    assert inspection.repository_identity.startswith("git-local:")
    with closing(console._open_db_read_only(database)) as conn:
        project = console._readonly_projects_list(conn)["projects"][0]
        with patch.object(db, "init_schema", side_effect=AssertionError("read-only health must not migrate")):
            expected = db.project_binding_status(conn, "fixture", repository_inspection=inspection,
                                                 initialize_schema=False)
            health = console._readonly_project_health(conn, project, inspection, database=database,
                                                       verify_database=False)
        assert health["integrity"]["binding"]["ready"] == expected["ready"] == (mismatch is None)
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
