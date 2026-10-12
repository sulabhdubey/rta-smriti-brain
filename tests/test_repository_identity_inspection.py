"""Identity inspection must agree with canonical binding helpers."""
from unittest.mock import patch

import pytest

from rta_brain import repository


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
