import json
import os
import shlex
import subprocess
import sys
import tomllib
from contextlib import closing
from pathlib import Path

import pytest

from rta_brain import db
from rta_brain.agent_setup import apply_setup, handle_hook, plan_setup, stop_setup


@pytest.fixture
def setup_brain(tmp_path, monkeypatch):
    root = tmp_path / "atlas"
    root.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    database = tmp_path / "private" / "brain.sqlite"
    database.parent.mkdir(mode=0o700)
    monkeypatch.setattr(
        "rta_brain.mcp_host_lifecycle._host_authority_root",
        lambda: tmp_path / "authority",
    )
    with closing(db.connect(database)) as conn:
        db.init_project(conn, "atlas", str(root))
    return {"database": database, "project": "atlas", "root": root, "home": home}


def install(options):
    plan = plan_setup(**options)
    result = apply_setup(
        plan,
        expected_digest=plan["plan_digest"],
        allow_capture=True,
        allow_model_context=True,
    )
    assert result["state"] == "installed"
    assert result["native_host_verified"] is False
    return result


def event(options, name, **extra):
    return {
        "hook_event_name": name,
        "session_id": "session-one",
        "cwd": str(options["root"]),
        **extra,
    }


def deliver(options, host, record):
    return handle_hook(
        options["database"], options["project"], host, record, cwd=options["root"]
    )


def test_unified_setup_is_preview_bound_and_preserves_unrelated_settings(setup_brain):
    options = setup_brain
    settings = options["home"] / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(
        json.dumps(
            {
                "theme": "light",
                "hooks": {
                    "Stop": [
                        {"hooks": [{"type": "command", "command": "existing-hook"}]}
                    ]
                },
            }
        )
    )
    original = settings.read_bytes()
    plan = plan_setup(**options)
    assert settings.read_bytes() == original
    assert not (options["home"] / ".codex" / "hooks.json").exists()
    with pytest.raises(ValueError, match="consent"):
        apply_setup(plan, expected_digest=plan["plan_digest"])
    install(options)
    document = json.loads(settings.read_text())
    assert document["theme"] == "light"
    assert len(document["hooks"]["Stop"]) == 2
    for path in (options["home"] / ".codex" / "hooks.json", settings):
        hooks = json.loads(path.read_text())["hooks"]
        assert {"SessionStart", "UserPromptSubmit", "Stop"} <= hooks.keys()
    second = install(options)
    assert second["idempotent"] is True
    assert len(json.loads(settings.read_text())["hooks"]["Stop"]) == 2


@pytest.mark.parametrize("name", ["rta-brain.exe", "rta-brain-1.1.0a12-windows-x86_64.exe"])
def test_frozen_setup_uses_native_mcp_entrypoint(setup_brain, monkeypatch, name):
    executable = setup_brain["home"] / name
    executable.write_bytes(b"synthetic native launcher identity; never executed")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    install(setup_brain)
    codex = tomllib.loads((setup_brain["home"] / ".codex/config.toml").read_text())
    claude = json.loads((setup_brain["home"] / ".claude.json").read_text())
    for servers in (codex["mcp_servers"], claude["mcpServers"]):
        server = next(iter(servers.values()))
        assert server["command"] == str(executable.resolve())
        assert server["args"][0] == "mcp-server"
        assert "-I" not in server["args"]
        assert "-m" not in server["args"]


def test_versioned_native_launcher_exception_is_bound_to_current_runtime(setup_brain, monkeypatch):
    from rta_brain.mcp_host_lifecycle import _canonicalize_launcher

    executable = setup_brain["home"] / "rta-brain-1.1.0a12-linux-x86_64"
    executable.write_bytes(b"synthetic current runtime; never executed")
    other = setup_brain["home"] / "rta-brain-1.1.0a12-macos-arm64"
    other.write_bytes(b"unrelated executable; never executed")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    with pytest.raises(ValueError, match="must execute"):
        _canonicalize_launcher(str(other), ["mcp-server"], None)
    with pytest.raises(ValueError, match="native MCP entrypoint"):
        _canonicalize_launcher(str(executable), ["-I", "-m", "rta_brain.mcp_server"], None)
    monkeypatch.setattr(sys, "frozen", False)
    with pytest.raises(ValueError, match="must execute"):
        _canonicalize_launcher(str(executable), ["mcp-server"], None)


@pytest.mark.parametrize("host,suffix,classification", [
    ("claude-code", ".claude.json", "local-or-user"),
    ("codex", ".codex/config.toml", "user"),
    ("cursor", ".cursor/mcp.json", "user"),
])
def test_host_policy_compares_canonical_system_home(setup_brain, monkeypatch, host, suffix, classification):
    from rta_brain import mcp_host_lifecycle as lifecycle

    home = setup_brain["home"]
    system_alias = home.parent / "trusted-system-home-alias"
    canonicalize = lifecycle.canonicalize_system_root_alias

    def canonicalize_home(path):
        return home if Path(path) == system_alias else canonicalize(path)

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: system_alias))
    monkeypatch.setattr(lifecycle, "canonicalize_system_root_alias", canonicalize_home)
    profile = lifecycle.host_profile(host)
    result = lifecycle._classify_target(profile, home / suffix)
    assert result["classification"] == classification
    foreign = home.parent / "another-home" / suffix
    if host == "claude-code":
        with pytest.raises(ValueError, match="documented Claude Code policy"):
            lifecycle._classify_target(profile, foreign)
    else:
        assert lifecycle._classify_target(profile, foreign)["classification"] == "project"


@pytest.mark.parametrize(
    "sender,receiver", [("codex", "claude-code"), ("claude-code", "codex")]
)
def test_complete_capture_to_recall_without_new_worker_or_checkpoint(
    setup_brain, sender, receiver
):
    options = setup_brain
    install(options)
    first = deliver(options, receiver, event(options, "SessionStart", source="startup"))
    assert first["state"] == "waiting_for_capture"
    prompt = event(
        options,
        "UserPromptSubmit",
        prompt="Use UTC timestamps, not local time",
        turn_id="turn-1",
    )
    assert deliver(options, sender, prompt)["state"] == "captured"
    deliver(options, sender, prompt)
    reply = event(
        options,
        "Stop",
        last_assistant_message="Timestamp change prepared. Tests are not run.",
        turn_id="turn-1",
    )
    assert deliver(options, sender, reply)["state"] == "captured"
    deliver(options, sender, reply)
    result = deliver(options, receiver, event(options, "SessionStart", source="resume"))
    context = result["output"]["hookSpecificOutput"]["additionalContext"]
    assert "Use UTC timestamps" in context
    assert "Tests are not run" in context
    assert "unverified" in context
    assert result["delivery_verified"] is False
    with closing(db.connect_readonly(options["database"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0] == 2
        assert db.latest_checkpoint(conn, "atlas", initialize_schema=False) is None


def test_stopped_setup_cannot_capture_or_recall(setup_brain):
    options = setup_brain
    install(options)
    stop_setup(options["database"], options["project"])
    assert (
        deliver(
            options, "codex", event(options, "UserPromptSubmit", prompt="Do not save")
        )["state"]
        == "not_enabled"
    )
    assert (
        deliver(
            options, "claude-code", event(options, "SessionStart", source="startup")
        )["state"]
        == "not_enabled"
    )
    with closing(db.connect_readonly(options["database"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0] == 0


def native_settings_change(options):
    codex = options["home"] / ".codex/config.toml"
    text = codex.read_text()
    marker = "# <<< rta-smriti managed"
    text = text.replace(marker, "[tui]\nscreen_reader_detection_done = true\n" + marker)
    codex.write_text(text)
    claude = options["home"] / ".claude.json"
    value = json.loads(claude.read_text())
    value["hasCompletedOnboarding"] = True
    claude.write_text(json.dumps(value))


def test_native_host_preferences_preserve_status_and_owned_removal(setup_brain):
    from rta_brain.agent_setup import plan_removal, remove_setup, setup_status

    install(setup_brain)
    native_settings_change(setup_brain)
    assert setup_status(setup_brain["database"], "atlas")["state"] == "waiting_for_capture"
    assert install(setup_brain)["idempotent"] is True
    plan = plan_removal(setup_brain["database"], "atlas")
    remove_setup(setup_brain["database"], "atlas", expected_digest=plan["plan_digest"])
    codex = tomllib.loads((setup_brain["home"] / ".codex/config.toml").read_text())
    assert codex["tui"]["screen_reader_detection_done"] is True
    assert not codex.get("mcp_servers")
    claude = json.loads((setup_brain["home"] / ".claude.json").read_text())
    assert claude["hasCompletedOnboarding"] is True
    assert not claude.get("mcpServers")


@pytest.mark.parametrize("mutation", ["args", "env", "removed"])
def test_native_preference_tolerance_still_rejects_owned_server_drift(setup_brain, mutation):
    from rta_brain.agent_setup import plan_removal, setup_status

    install(setup_brain)
    native_settings_change(setup_brain)
    target = setup_brain["home"] / ".claude.json"
    value = json.loads(target.read_text())
    alias = next(iter(value["mcpServers"]))
    if mutation == "removed":
        del value["mcpServers"][alias]
    elif mutation == "args":
        value["mcpServers"][alias]["args"].append("--allow-writes")
    else:
        value["mcpServers"][alias]["env"] = {"UNREVIEWED": "value"}
    target.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="binding|changed"):
        setup_status(setup_brain["database"], "atlas")
    with pytest.raises(ValueError, match="binding|changed"):
        plan_removal(setup_brain["database"], "atlas")


def test_owned_validation_does_not_weaken_strict_proof_or_receipt_authentication(setup_brain):
    from rta_brain.agent_setup import _load, setup_status
    from rta_brain.mcp_host_lifecycle import validate_installed_configuration

    install(setup_brain)
    native_settings_change(setup_brain)
    receipt = _load(setup_brain["database"], "atlas")
    path = Path(receipt["mcp"]["codex"]["receipt_path"])
    with pytest.raises(ValueError, match="binding"):
        validate_installed_configuration(path)
    result = validate_installed_configuration(path, allow_unrelated_changes=True)
    assert result["validation_scope"] == "owned_server"
    value = json.loads(path.read_text())
    value["owned_server_digest"] = "0" * 64
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="authentication"):
        setup_status(setup_brain["database"], "atlas")


def test_owned_removal_rejects_settings_change_after_review(setup_brain):
    from rta_brain.agent_setup import plan_removal, remove_setup

    install(setup_brain)
    native_settings_change(setup_brain)
    plan = plan_removal(setup_brain["database"], "atlas")
    target = setup_brain["home"] / ".claude.json"
    value = json.loads(target.read_text())
    value["anotherPreference"] = True
    target.write_text(json.dumps(value))
    before = target.read_bytes()
    with pytest.raises(ValueError, match="removal changed"):
        remove_setup(setup_brain["database"], "atlas", expected_digest=plan["plan_digest"])
    assert target.read_bytes() == before


def test_generated_commands_capture_and_recall_in_fresh_processes(setup_brain):
    options = setup_brain
    install(options)

    def run(host, record):
        path = options["home"] / (
            ".codex/hooks.json" if host == "codex" else ".claude/settings.json"
        )
        handler = json.loads(path.read_text())["hooks"][record["hook_event_name"]][0][
            "hooks"
        ][0]
        if "args" in handler:
            command = [handler["command"], *handler["args"]]
        elif os.name == "nt":
            command = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                handler["commandWindows"],
            ]
        else:
            command = shlex.split(handler["command"])
        result = subprocess.run(
            command,
            input=json.dumps(record),
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=15,
            cwd=options["root"],
            check=False,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    assert (
        run(
            "codex",
            event(options, "UserPromptSubmit", prompt="Preserve the original data"),
        )
        == {}
    )
    assert (
        run(
            "claude-code",
            event(
                options,
                "Stop",
                last_assistant_message="Backup verified; migration not performed",
            ),
        )
        == {}
    )
    result = run("claude-code", event(options, "SessionStart", source="startup"))
    assert (
        "Preserve the original data"
        in result["hookSpecificOutput"]["additionalContext"]
    )
    assert (
        "migration not performed" in result["hookSpecificOutput"]["additionalContext"]
    )


def test_changed_configuration_invalidates_review_before_any_write(setup_brain):
    options = setup_brain
    plan = plan_setup(**options)
    settings = options["home"] / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text('{"theme":"changed"}')
    with pytest.raises(ValueError, match="changed"):
        apply_setup(
            plan,
            expected_digest=plan["plan_digest"],
            allow_capture=True,
            allow_model_context=True,
        )
    assert not (options["home"] / ".codex" / "config.toml").exists()


def test_partial_install_disables_delivery_and_retries_without_duplicates(
    setup_brain, monkeypatch
):
    from rta_brain import agent_setup

    options = setup_brain
    original = agent_setup.install_adapter

    def fail_second(plan):
        if plan.adapter == "claude-code":
            raise OSError("synthetic interrupted install")
        return original(plan)

    monkeypatch.setattr(agent_setup, "install_adapter", fail_second)
    with pytest.raises(OSError, match="interrupted"):
        install(options)
    assert (
        deliver(
            options,
            "codex",
            event(options, "UserPromptSubmit", prompt="not authorized yet"),
        )["state"]
        == "not_enabled"
    )
    monkeypatch.setattr(agent_setup, "install_adapter", original)
    install(options)
    assert (
        deliver(
            options, "codex", event(options, "UserPromptSubmit", prompt="after repair")
        )["state"]
        == "captured"
    )


def test_busy_writer_queues_without_false_capture_claim_and_sync_recovers(setup_brain):
    from rta_brain.agent_setup import drain_setup
    from rta_brain.runtime_control import database_writer_lease

    options = setup_brain
    install(options)
    with database_writer_lease(options["database"], timeout_seconds=1):
        result = deliver(
            options,
            "codex",
            event(options, "UserPromptSubmit", prompt="Recover queued context"),
        )
    assert result["state"] == "queued"
    assert (
        deliver(
            options, "claude-code", event(options, "SessionStart", source="resume")
        )["state"]
        == "waiting_for_capture"
    )
    drain_setup(options["database"], options["project"])
    text = deliver(
        options, "claude-code", event(options, "SessionStart", source="resume")
    )["output"]
    assert "Recover queued context" in json.dumps(text)


def test_stop_and_reconsent_does_not_recall_old_capture(setup_brain):
    options = setup_brain
    install(options)
    deliver(
        options, "codex", event(options, "UserPromptSubmit", prompt="Old consent epoch")
    )
    stop_setup(options["database"], options["project"])
    install(options)
    result = deliver(
        options, "claude-code", event(options, "SessionStart", source="startup")
    )
    assert result["state"] == "waiting_for_capture"


def test_foreign_root_and_oversized_inputs_do_not_capture(setup_brain, tmp_path):
    options = setup_brain
    install(options)
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    record = event(options, "UserPromptSubmit", prompt="foreign", cwd=str(foreign))
    assert deliver(options, "codex", record)["state"] == "scope_mismatch"
    assert (
        deliver(
            options, "codex", event(options, "UserPromptSubmit", prompt="x" * 70000)
        )["state"]
        == "invalid_input"
    )
    with closing(db.connect_readonly(options["database"])) as conn:
        assert conn.execute("SELECT COUNT(*) FROM capture_events").fetchone()[0] == 0


def test_corrections_are_recalled_in_order_without_becoming_verified_decisions(
    setup_brain,
):
    options = setup_brain
    install(options)
    deliver(
        options,
        "codex",
        event(options, "UserPromptSubmit", prompt="Use the old parser", turn_id="one"),
    )
    deliver(
        options,
        "codex",
        event(
            options,
            "UserPromptSubmit",
            prompt="Correction: use the new parser",
            turn_id="two",
        ),
    )
    result = deliver(
        options, "claude-code", event(options, "SessionStart", source="resume")
    )
    text = result["output"]["hookSpecificOutput"]["additionalContext"]
    assert text.index("old parser") < text.index("Correction:")
    with closing(db.connect_readonly(options["database"])) as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM memories WHERE type='decision'"
            ).fetchone()[0]
            == 0
        )


def test_hook_does_not_drain_an_unselected_capture_source(setup_brain):
    from datetime import UTC, datetime

    from rta_brain.capture import register_policy, register_source
    from rta_brain.capture_daemon import (
        CAPTURE_INGRESS_FIELDS,
        prepare_capture_spool_record,
    )
    from rta_brain.capture_spool import CaptureSpool
    from rta_brain.capture_types import CapturePolicy, CaptureSource

    options = setup_brain
    install(options)
    with closing(db.connect(options["database"])) as conn:
        policy = CapturePolicy.continuity()
        register_policy(
            conn,
            project="atlas",
            active_root=options["root"],
            policy_id="other",
            policy_version=1,
            policy=policy,
        )
        register_source(
            conn,
            project="atlas",
            active_root=options["root"],
            policy_digest=policy.digest,
            source=CaptureSource(
                source_id="unselected",
                adapter="generic",
                adapter_version="1",
                installation_scope="api",
                config_fingerprint="a" * 64,
            ),
        )
        prepared = prepare_capture_spool_record(
            conn,
            project="atlas",
            active_root=options["root"],
            source_id="unselected",
            original_bytes=10,
            record={
                "source_cursor": "1",
                "session_id": "other",
                "cursor_kind": "sequence",
                "observed_at": datetime.now(UTC).isoformat(),
                "vendor_event": "prompt",
                "payload": {"text": "not in this operation"},
            },
        )
        CaptureSpool(options["database"]).publish(
            "unselected",
            prepared,
            project="atlas",
            allowed_fields=CAPTURE_INGRESS_FIELDS,
        )
    assert (
        deliver(
            options, "codex", event(options, "UserPromptSubmit", prompt="Selected")
        )["state"]
        == "captured"
    )
    with closing(db.connect_readonly(options["database"])) as conn:
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM capture_events WHERE source_id='unselected'"
            ).fetchone()[0]
            == 0
        )


def test_sync_refuses_stopped_or_unconfigured_setup(setup_brain):
    from rta_brain.agent_setup import drain_setup

    options = setup_brain
    assert drain_setup(options["database"], "atlas")["state"] == "not_enabled"
    install(options)
    stop_setup(options["database"], "atlas")
    assert drain_setup(options["database"], "atlas")["state"] == "not_enabled"


def test_existing_bridge_consent_is_not_silently_replaced(setup_brain):
    from rta_brain.continuity_bridge import enable_bridge, preview_bridge

    options = setup_brain
    with closing(db.connect(options["database"])) as conn:
        db.save_checkpoint(conn, "atlas", "Existing reviewed objective")
    args = {
        "database": options["database"],
        "project": "atlas",
        "root": options["root"],
        "host": "codex",
        "selection": {"checkpoint_fields": ["objective"]},
    }
    preview = preview_bridge(**args)
    enable_bridge(
        **args, expected_digest=preview["plan_digest"], allow_model_context=True
    )
    with pytest.raises(ValueError, match="existing bridge"):
        plan_setup(**options)


def test_existing_rta_server_is_not_duplicated_under_another_alias(setup_brain):
    options = setup_brain
    path = options["home"] / ".claude.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "existing-brain": {
                        "command": "python",
                        "args": [
                            "-m",
                            "rta_brain.mcp_server",
                            "--db",
                            str(options["database"]),
                        ],
                    }
                }
            }
        )
    )
    with pytest.raises(ValueError, match="existing Rta-Smriti"):
        plan_setup(**options)


def test_status_separates_installed_capture_and_native_host_proof(setup_brain):
    from rta_brain.agent_setup import setup_status

    options = setup_brain
    install(options)
    status = setup_status(options["database"], "atlas")
    assert status["state"] == "waiting_for_capture"
    assert status["capture_events"] == 0
    deliver(options, "codex", event(options, "UserPromptSubmit", prompt="Useful work"))
    status = setup_status(options["database"], "atlas")
    assert status["state"] == "recall_available"
    assert status["capture_events"] == 1
    assert status["native_host_verified"] is False
    assert status["model_use_verified"] is False
    assert "Useful work" not in json.dumps(status)


def test_hook_text_is_private_filtered_and_unicode_safe(setup_brain):
    options = setup_brain
    install(options)
    secret = "sk-" + "z" * 30
    prompt = "\ufeff\u0938\u094d\u092e\u0943\u0924\u093f " + secret
    assert (
        deliver(options, "codex", event(options, "UserPromptSubmit", prompt=prompt))[
            "state"
        ]
        == "captured"
    )
    text = deliver(
        options, "claude-code", event(options, "SessionStart", source="resume")
    )["output"]
    assert secret not in json.dumps(text)
    assert (
        "\u0938\u094d\u092e\u0943\u0924\u093f"
        in text["hookSpecificOutput"]["additionalContext"]
    )


def test_removal_is_reviewed_preserves_settings_and_can_be_repeated(setup_brain):
    from rta_brain.agent_setup import plan_removal, remove_setup

    options = setup_brain
    settings = options["home"] / ".claude" / "settings.json"
    settings.parent.mkdir()
    original = b'{ "theme": "light" }\n'
    settings.write_bytes(original)
    install(options)
    plan = plan_removal(options["database"], "atlas")
    with pytest.raises(ValueError, match="changed"):
        remove_setup(options["database"], "atlas", expected_digest="wrong")
    result = remove_setup(
        options["database"], "atlas", expected_digest=plan["plan_digest"]
    )
    assert result["state"] == "removed"
    assert settings.read_bytes() == original
    assert not (options["home"] / ".codex" / "config.toml").exists()
    assert not (options["home"] / ".claude.json").exists()
    assert (
        deliver(
            options, "codex", event(options, "UserPromptSubmit", prompt="disabled")
        )["state"]
        == "not_enabled"
    )
    again = plan_removal(options["database"], "atlas")
    assert (
        remove_setup(
            options["database"], "atlas", expected_digest=again["plan_digest"]
        )["state"]
        == "removed"
    )


def test_revocation_during_recall_discards_the_prepared_context(
    setup_brain, monkeypatch
):
    from rta_brain import agent_setup

    options = setup_brain
    install(options)
    deliver(
        options,
        "codex",
        event(options, "UserPromptSubmit", prompt="Withdraw this handoff"),
    )
    original = agent_setup.recall_bridge

    def revoke_after_read(*args, **kwargs):
        result = original(*args, **kwargs)
        stop_setup(options["database"], "atlas")
        return result

    monkeypatch.setattr(agent_setup, "recall_bridge", revoke_after_read)
    result = deliver(
        options, "claude-code", event(options, "SessionStart", source="resume")
    )
    assert result["state"] == "consent_changed"
    assert "Withdraw this handoff" not in json.dumps(result)


def test_out_of_scope_hook_is_quiet(setup_brain, tmp_path):
    options = setup_brain
    install(options)
    elsewhere = tmp_path / "another-project"
    elsewhere.mkdir()
    result = handle_hook(
        options["database"],
        "atlas",
        "codex",
        event(options, "UserPromptSubmit", cwd=str(elsewhere), prompt="unrelated"),
        cwd=elsewhere,
    )
    assert result["state"] == "scope_mismatch"
    assert result["output"] == {}
