import io
from pathlib import Path
from types import SimpleNamespace

from rta_brain import parsers


RTA_CREDENTIALS = {
    "RTA_SMIRTI_CONSOLE_CAPABILITY": "dashboard-secret",
    "RTA_SMIRTI_CONSOLE_LAUNCH_SECRET": "launch-secret",
    "RTA_SMIRTI_MCP_HOST_NONCE": "host-nonce",
    "RTA_OTHER_AUTHORITY_TOKEN": "authority-token",
}

PROCESS_CREDENTIALS = {
    "PGPASSWORD": "postgres-secret",
    "DATABASE_URL": "postgresql://operator:database-secret@localhost/brain",
    "HTTPS_PROXY": "https://proxy-user:proxy-secret@proxy.example.invalid:8443",
    "LC_PASSWORD": "locale-shaped-secret",
}

REQUIRED_RUNTIME_ENVIRONMENT = {
    "PATH": r"C:\Windows\System32",
    "SYSTEMROOT": r"C:\Windows",
    "TEMP": r"C:\Temp",
    "LANG": "en_US.UTF-8",
    "LC_MESSAGES": "en_US.UTF-8",
}


def test_parser_environment_uses_runtime_allowlist_and_drops_credentials():
    environment = {
        **REQUIRED_RUNTIME_ENVIRONMENT,
        **PROCESS_CREDENTIALS,
        "SAFE_PARENT_SETTING": "not-required-by-parser-runtime",
    }

    child = parsers.sanitized_parser_environment(environment)

    assert child == REQUIRED_RUNTIME_ENVIRONMENT


def test_explicit_parser_adapter_receives_sanitized_environment(monkeypatch, tmp_path):
    for name, value in RTA_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    for name, value in PROCESS_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    for name, value in REQUIRED_RUNTIME_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SAFE_PARENT_SETTING", "not-required-by-parser-runtime")
    observed = {}

    def fake_run(*_args, **kwargs):
        observed.update(kwargs["env"])
        return SimpleNamespace(
            returncode=0,
            stdout='{"symbols": [], "imports": [], "calls": []}',
        )

    monkeypatch.setattr(parsers.subprocess, "run", fake_run)
    parser = parsers.LspParser(command="trusted-parser")
    parser.parse(tmp_path / "sample.py", "pass\n")

    assert all(observed[name] == value for name, value in REQUIRED_RUNTIME_ENVIRONMENT.items())
    assert not set(RTA_CREDENTIALS).intersection(observed)
    assert not set(PROCESS_CREDENTIALS).intersection(observed)
    assert "SAFE_PARENT_SETTING" not in observed


def test_native_lsp_process_receives_sanitized_environment(monkeypatch, tmp_path):
    for name, value in RTA_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    for name, value in PROCESS_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    for name, value in REQUIRED_RUNTIME_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SAFE_PARENT_SETTING", "not-required-by-parser-runtime")
    observed = {}

    class FakeProcess:
        stdin = io.BytesIO()
        stdout = None

    def fake_popen(*_args, **kwargs):
        observed.update(kwargs["env"])
        return FakeProcess()

    monkeypatch.setattr(parsers.subprocess, "Popen", fake_popen)
    parsers._LspClient(["trusted-language-server"], Path(tmp_path))

    assert all(observed[name] == value for name, value in REQUIRED_RUNTIME_ENVIRONMENT.items())
    assert not set(RTA_CREDENTIALS).intersection(observed)
    assert not set(PROCESS_CREDENTIALS).intersection(observed)
    assert "SAFE_PARENT_SETTING" not in observed
