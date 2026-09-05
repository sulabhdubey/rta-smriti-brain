import os

import pytest

from rta_brain import console_daemon


def test_console_worker_removes_launch_credentials_after_capture(monkeypatch, tmp_path):
    credentials = {
        "RTA_SMIRTI_CONSOLE_LAUNCH_SECRET": "launch-secret",
        "RTA_SMIRTI_CONSOLE_CAPABILITY": "dashboard-capability",
        "RTA_SMIRTI_CONSOLE_INSTANCE_ID": "instance-nonce",
    }
    for name, value in credentials.items():
        monkeypatch.setenv(name, value)

    def inspect_worker_environment(_pid):
        assert not set(credentials).intersection(os.environ)
        return None

    monkeypatch.setattr(console_daemon, "detach_current_worker_session", lambda: None)
    monkeypatch.setattr(console_daemon, "process_identity", inspect_worker_environment)

    with pytest.raises(RuntimeError, match="process identity is unavailable"):
        console_daemon.run_console_worker(
            tmp_path,
            tmp_path,
            None,
            None,
            "127.0.0.1",
            0,
            tmp_path / "state.json",
            tmp_path / "stop.json",
            tmp_path / "launch.lock",
            tmp_path / "token",
        )
