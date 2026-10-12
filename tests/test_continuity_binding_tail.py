"""Binding must depend on the latest safe context, not decoding old turns."""
import hashlib
import io
import json
import random
from unittest.mock import patch

import pytest

from rta_brain import continuity_daemon as daemon
from rta_brain import db


def record(kind, **payload):
    return (json.dumps({"type": kind, "payload": payload}) + "\n").encode()


def test_recent_binding_does_not_decode_historical_turns(tmp_path):
    session = tmp_path / "session.jsonl"
    meta = record("session_meta", id="fixture", cwd=str(tmp_path))
    history = record("event_msg", message="historical content" * 100) * 2000
    context = record("turn_context", cwd=str(tmp_path))
    session.write_bytes(meta + history + context + record("event_msg", message="recent"))
    with patch.object(daemon.json, "loads", wraps=json.loads) as decode:
        binding = daemon._session_binding(session, tmp_path)
    assert binding["binding_offset"] == len(meta + history)
    assert decode.call_count <= 4


@pytest.mark.parametrize("padding", [0, 1, 65_534, 65_535, 65_536, 65_537, 131_070])
@pytest.mark.parametrize("ending", [b"", b"\n", b"\r\n"])
def test_reverse_line_offsets_match_forward_byte_oracle(padding, ending):
    content = b"first\r\n\n" + b"x" * padding + b"\nlast" + ending
    expected, offset = [], 0
    for line in io.BytesIO(content):
        expected.append((offset, line))
        offset += len(line)
    actual = list(daemon._reverse_session_lines(io.BytesIO(content), 0, len(content)))
    assert actual == expected[::-1]


def test_binding_matches_independent_forward_oracle(tmp_path):
    root, foreign = tmp_path / "local", tmp_path / "foreign"
    root.mkdir()
    foreign.mkdir()
    meta = record("session_meta", id="oracle", cwd=str(root))
    options = [
        record("turn_context", cwd=str(root)),
        record("turn_context", cwd=str(foreign)),
        record("turn_context", cwd=str(root / "child")),
        record("turn_context", note="missing cwd"),
        record("event_msg", message='escaped \\" type: turn_context \\n \u03a9'),
        b'{"type":"event_msg","payload":{"type":"turn_context","cwd":"foreign"}}\n',
        b'{"type":"turn_context","payload":null}\n',
        b'{"broken":\n', b"\n", b"\xff\n", b"[]\n",
    ]
    rng = random.Random(1082026)
    session = tmp_path / "oracle.jsonl"
    for case in range(600):
        rows = [meta] + rng.choices(options, k=rng.randrange(40))
        matching, ambiguous, binding_offset, offset = True, False, 0, 0
        for raw in rows:
            try:
                row = json.loads(raw)
            except (ValueError, UnicodeError):
                ambiguous = True
            else:
                if not isinstance(row, dict):
                    ambiguous = True
                elif row.get("type") == "turn_context" and isinstance(row.get("payload"), dict):
                    cwd = row["payload"].get("cwd")
                    if cwd:
                        ambiguous = False
                        matching = cwd in {str(root), str(root / "child")}
                        if matching:
                            binding_offset = offset
            offset += len(raw)
        session.write_bytes(b"".join(rows))
        actual = daemon._session_binding(session, root)
        if ambiguous or not matching:
            assert actual is None, case
        else:
            assert actual is not None, case
            assert actual["binding_offset"] == binding_offset, case
            assert actual["binding_mode"] == ("turn_context" if binding_offset else "session_meta")


@pytest.mark.parametrize("bad", [b"{" * 200, b"x" * 1_000_001, b'{"type":', b"[]"],
                         ids=["deep", "oversized", "partial", "non-object"])
def test_ambiguous_tail_blocks_until_later_valid_context(tmp_path, bad):
    session = tmp_path / "unsafe.jsonl"
    meta = record("session_meta", id="fixture", cwd=str(tmp_path))
    context = record("turn_context", cwd=str(tmp_path))
    before = meta + context + bad + b"\n"
    session.write_bytes(before)
    assert daemon._session_binding(session, tmp_path) is None
    session.write_bytes(before + context)
    assert daemon._session_binding(session, tmp_path)["binding_offset"] == len(before)


def test_tail_boundary_cannot_use_a_partial_context(tmp_path):
    session = tmp_path / "limited.jsonl"
    meta = record("session_meta", id="fixture", cwd=str(tmp_path))
    context = record("turn_context", cwd=str(tmp_path))
    tail = record("event_msg", message="recent")
    session.write_bytes(meta + context + tail)
    with patch.object(daemon, "MAX_SESSION_REBIND_SCAN_BYTES", len(context + tail) - 1):
        assert daemon._session_binding(session, tmp_path) is None
    with patch.object(daemon, "MAX_SESSION_REBIND_SCAN_BYTES", len(context + tail) + 1):
        assert daemon._session_binding(session, tmp_path)["binding_offset"] == len(meta)


def test_reverse_scan_rejects_truncated_read_and_yields_during_long_line():
    with pytest.raises(ValueError, match="changed"):
        list(daemon._reverse_session_lines(io.BytesIO(b"short"), 0, 100))
    checkpoints = []
    data = b"x" * 900_000
    assert list(daemon._reverse_session_lines(
        io.BytesIO(data), 0, len(data), work_checkpoint=lambda: checkpoints.append(True),
    )) == [(0, data)]
    assert len(checkpoints) >= 13
    with pytest.raises(InterruptedError):
        list(daemon._reverse_session_lines(
            io.BytesIO(data), 0, len(data),
            work_checkpoint=lambda: (_ for _ in ()).throw(InterruptedError()),
        ))


@pytest.mark.parametrize("becomes_active", [False, True])
def test_empty_worker_does_not_connect_and_resumes_for_new_session(tmp_path, becomes_active):
    root = tmp_path / "repo"
    root.mkdir()
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    database = tmp_path / "brain.sqlite"
    conn = db.connect(database)
    db.init_project(conn, "demo", str(root))
    conn.close()
    transcript = sessions / "fixture.jsonl"
    transcript.write_bytes(record("session_meta", id="fixture", cwd=str(root)) +
                           record("turn_context", cwd=str(root)) +
                           record("response_item", type="message", role="user", content="Capture after idle"))
    inventory = daemon.discover_codex_sessions(sessions, root)
    paths = daemon.continuity_paths(database, "demo")
    paths["directory"].mkdir(exist_ok=True)
    token = "test-only-launch-token"
    paths["lock"].write_text(hashlib.sha256(token.encode("ascii")).hexdigest(), encoding="ascii")
    states = []
    connections_after_cycles = []

    def connect(*args, **kwargs):
        connections_after_cycles.append(states[-1]["cycles"])
        return db.connect(*args, **kwargs)

    def stop(_path):
        return bool(states and states[-1]["cycles"] >= 2)

    with (
        patch.dict(daemon.os.environ, {"RTA_SMIRTI_CONTINUITY_TOKEN": token}),
        patch.object(daemon, "process_identity", return_value="fixture-identity"),
        patch.object(daemon.signal, "signal"),
        patch.object(daemon, "_write_json", side_effect=lambda _, state: states.append(dict(state))),
        patch.object(daemon, "_stop_requested", side_effect=stop),
        patch.object(daemon, "discover_codex_sessions", side_effect=[[], inventory if becomes_active else []]),
        patch.object(daemon, "connect", side_effect=connect),
    ):
        result = daemon.run_continuity_worker(database, root, "demo", sessions,
            paths["state"], paths["stop"], paths["lock"], 0.1, 900, 2, 2_000_000)
    assert result == 0
    assert states[-1]["errors"] == 0
    if becomes_active:
        assert connections_after_cycles and min(connections_after_cycles) >= 1
        assert states[-1]["events_inserted"] > 0
        assert states[-1]["sessions_discovered"] == 1
    else:
        assert connections_after_cycles == []
        assert states[-1]["events_inserted"] == 0
        assert states[-1]["sessions_discovered"] == 0
