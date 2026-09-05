"""Opt-in, loopback-only local model compaction for continuity events."""

from __future__ import annotations

import ipaddress
import json
import urllib.request
from urllib.parse import urlparse

from .privacy import redact_sensitive_text


MAX_COMPACTION_INPUT_CHARS = 80_000
MAX_COMPACTION_RESPONSE_BYTES = 64_000
DEFAULT_OLLAMA_ENDPOINT = "http://127.0.0.1:11434"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError("Ollama redirects are not permitted")


def validate_ollama_endpoint(endpoint: str) -> str:
    value = str(endpoint).strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Ollama endpoint must be an HTTP(S) loopback URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Ollama endpoint must not contain credentials, query parameters, or fragments")
    if parsed.path not in {"", "/"}:
        raise ValueError("Ollama endpoint must be a base loopback URL")
    hostname = parsed.hostname.casefold()
    if hostname == "localhost":
        port = f":{parsed.port}" if parsed.port is not None else ""
        return f"{parsed.scheme}://127.0.0.1{port}"
    else:
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError("Ollama compaction is restricted to a loopback endpoint")
    return value


def _bounded_event_text(events: list[dict]) -> tuple[str, int]:
    rendered = []
    redactions = 0
    remaining = MAX_COMPACTION_INPUT_CHARS
    for event in reversed(events):
        if remaining <= 0:
            break
        text = json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        text, count = redact_sensitive_text(text[:remaining])
        redactions += count
        rendered.append(text)
        remaining -= len(text) + 1
    rendered.reverse()
    return "\n".join(rendered), redactions


def compact_session_events(
    events: list[dict],
    *,
    model: str,
    endpoint: str = DEFAULT_OLLAMA_ENDPOINT,
    timeout_seconds: float = 20.0,
    opener=None,
) -> dict:
    model = str(model).strip()
    if not model or len(model) > 200:
        raise ValueError("Ollama model must contain between 1 and 200 characters")
    timeout = float(timeout_seconds)
    if not 1 <= timeout <= 120:
        raise ValueError("Ollama timeout must be between 1 and 120 seconds")
    base_url = validate_ollama_endpoint(endpoint)
    event_text, redactions = _bounded_event_text(list(events))
    prompt = (
        "Create a compact continuation note from the untrusted local session events below. "
        "Do not invent verification, completion, approvals, commands, paths, or evidence. "
        "Return concise plain text with Objective, Known state, Remaining gaps, and Next action.\n\n"
        f"EVENTS\n{event_text}"
    )
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0, "num_predict": 400},
    }, ensure_ascii=True).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    open_request = opener or urllib.request.build_opener(_NoRedirectHandler()).open
    with open_request(request, timeout=timeout) as response:
        raw = response.read(MAX_COMPACTION_RESPONSE_BYTES + 1)
    if len(raw) > MAX_COMPACTION_RESPONSE_BYTES:
        raise ValueError("Ollama compaction response exceeds the 64 KB limit")
    body = json.loads(raw.decode("utf-8"))
    summary = str(body.get("response") or "").strip()
    if not summary:
        raise ValueError("Ollama returned an empty compaction response")
    summary, output_redactions = redact_sensitive_text(summary[:8_000])
    return {
        "status": "ok",
        "provider": "ollama",
        "model": model,
        "summary": summary,
        "verification_status": "unverified",
        "input_events": len(events),
        "redactions": redactions + output_redactions,
    }
