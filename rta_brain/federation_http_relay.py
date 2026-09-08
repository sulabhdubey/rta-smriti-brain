"""Minimal opaque HTTP transport for a self-hosted federation relay."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .federation_transport import (
    MAX_RELAY_OBJECTS,
    FederationTransportError,
    FilesystemFederationRelay,
)
from .federation_types import (
    FederationEventEnvelope,
    canonical_json_bytes,
    parse_event_envelope,
)

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address,
        handler,
        *,
        worker_limit: int,
        request_timeout: float,
    ) -> None:
        self.worker_limit = int(worker_limit)
        self.request_timeout = float(request_timeout)
        self._worker_slots = threading.BoundedSemaphore(self.worker_limit)
        super().__init__(server_address, handler)

    def process_request(self, request, client_address) -> None:
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            request.settimeout(self.request_timeout)
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


def _identifier(name: str, value: str) -> str:
    selected = str(value)
    if (
        len(selected) != 64
        or any(char not in "0123456789abcdef" for char in selected)
        or set(selected) == {"0"}
    ):
        raise ValueError(f"{name} must be a non-zero lower-case SHA-256 identifier")
    return selected


def _capability(value: str) -> str:
    selected = str(value)
    if not 32 <= len(selected) <= 256 or "\0" in selected:
        raise ValueError("relay capability must contain 32 to 256 characters")
    return selected


class FederationHttpRelayServer:
    """Quiet threaded relay; TLS and remote exposure belong at a hardened proxy."""

    def __init__(
        self,
        root: Path,
        *,
        space_capabilities: dict[str, str],
        host: str = "127.0.0.1",
        port: int = 0,
        allow_remote: bool = False,
        max_blob_bytes: int = 2 * 1024 * 1024,
        max_objects_per_space: int = MAX_RELAY_OBJECTS,
        max_requests_per_minute: int = 600,
        max_workers: int = 16,
        request_timeout: float = 15.0,
    ) -> None:
        if host not in {"127.0.0.1", "::1", "localhost"} and not allow_remote:
            raise ValueError("non-loopback relay binding requires explicit opt-in")
        if not 1 <= int(max_objects_per_space) <= MAX_RELAY_OBJECTS:
            raise ValueError("relay object quota is outside the supported range")
        if not 10 <= int(max_requests_per_minute) <= 100_000:
            raise ValueError("relay rate limit is outside the supported range")
        if not 1 <= int(max_workers) <= 64:
            raise ValueError("relay worker limit is outside the supported range")
        if not 0.5 <= float(request_timeout) <= 60.0:
            raise ValueError("relay request timeout is outside the supported range")
        self._relay = FilesystemFederationRelay(root, max_blob_bytes=max_blob_bytes)
        self._capabilities = {
            _identifier("space_id", space_id): _capability(capability)
            for space_id, capability in space_capabilities.items()
        }
        if not self._capabilities:
            raise ValueError("relay requires at least one space capability")
        self._max_objects = int(max_objects_per_space)
        self._max_requests = int(max_requests_per_minute)
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._storage_lock = threading.Lock()
        self.worker_limit = int(max_workers)
        self.request_timeout_seconds = float(request_timeout)
        self.audit_log: list[dict[str, Any]] = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "RtaSmritiRelay/1"
            sys_version = ""

            def log_message(self, format: str, *args: object) -> None:
                return

            def _reply(self, status: int, payload: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(payload)

            def _json(self, status: int, payload: dict[str, Any]) -> None:
                self._reply(status, canonical_json_bytes(payload), "application/json")

            def _route(self) -> tuple[str, str | None] | None:
                parts = self.path.split("?", 1)[0].split("/")
                if len(parts) == 5 and parts[:3] == ["", "v1", "spaces"] and parts[4] == "inventory":
                    return _identifier("space_id", parts[3]), None
                if len(parts) == 6 and parts[:3] == ["", "v1", "spaces"] and parts[4] == "events":
                    return _identifier("space_id", parts[3]), _identifier("event_id", parts[5])
                return None

            def _authorized(self, space_id: str) -> bool:
                supplied = self.headers.get("X-Rta-Space-Capability", "")
                expected = owner._capabilities.get(space_id)
                if expected is None or not secrets.compare_digest(supplied, expected):
                    owner._audit("authorization_denied", 403, 0)
                    self._json(403, {"error": "authorization_denied"})
                    return False
                now = time.monotonic()
                with owner._lock:
                    requests = owner._requests[space_id]
                    while requests and requests[0] <= now - 60:
                        requests.popleft()
                    if len(requests) >= owner._max_requests:
                        owner._audit_unlocked("rate_limited", 429, 0)
                        self._json(429, {"error": "rate_limited"})
                        return False
                    requests.append(now)
                return True

            def do_GET(self) -> None:
                if self.path.split("?", 1)[0] == "/health":
                    owner._audit("health", 200, 0)
                    self._json(200, {"schema": "rta-smriti.relay-health/v1", "state": "healthy"})
                    return
                try:
                    route = self._route()
                except ValueError:
                    route = None
                if route is None:
                    self._json(404, {"error": "not_found"})
                    return
                space_id, event_id = route
                if not self._authorized(space_id):
                    return
                try:
                    if event_id is None:
                        query = urllib.parse.parse_qs(
                            urllib.parse.urlsplit(self.path).query,
                            keep_blank_values=True,
                        )
                        if set(query) - {"scope_id"} or len(query.get("scope_id", [])) > 1:
                            raise ValueError("invalid inventory query")
                        scope_id = (
                            _identifier("scope_id", query["scope_id"][0])
                            if query.get("scope_id")
                            else None
                        )
                        inventory = owner._relay.inventory(
                            space_id, scope_id=scope_id
                        )
                        payload = canonical_json_bytes({"event_ids": inventory})
                        owner._audit("inventory", 200, len(payload))
                        self._reply(200, payload, "application/json")
                    else:
                        encoded = owner._relay.get_event(space_id, event_id).encoded
                        owner._audit("get", 200, len(encoded))
                        self._reply(200, encoded, "application/octet-stream")
                except (FederationTransportError, ValueError):
                    owner._audit("read_error", 404, 0)
                    self._json(404, {"error": "not_found"})

            def do_PUT(self) -> None:
                try:
                    route = self._route()
                except ValueError:
                    route = None
                if route is None or route[1] is None:
                    self._json(404, {"error": "not_found"})
                    return
                space_id, event_id = route
                if not self._authorized(space_id):
                    return
                try:
                    length = int(self.headers.get("Content-Length", "-1"))
                except ValueError:
                    length = -1
                if not 1 <= length <= owner._relay.max_blob_bytes:
                    owner._audit("size_rejected", 413, max(length, 0))
                    self._json(413, {"error": "size_limit"})
                    return
                encoded = self.rfile.read(length)
                if len(encoded) != length:
                    owner._audit("size_rejected", 413, len(encoded))
                    self._json(413, {"error": "size_limit"})
                    return
                try:
                    envelope = parse_event_envelope(encoded)
                    if envelope.space_id != space_id or envelope.event_id != event_id:
                        raise ValueError("routing mismatch")
                    with owner._storage_lock:
                        inventory = owner._relay.inventory(space_id)
                        if event_id not in inventory and len(inventory) >= owner._max_objects:
                            owner._audit("quota_rejected", 413, len(encoded))
                            self._json(413, {"error": "object_quota"})
                            return
                        receipt = owner._relay.put_event(envelope)
                    payload = canonical_json_bytes(
                        {"bytes": int(receipt["bytes"]), "state": str(receipt["state"])}
                    )
                    owner._audit("put", 200, len(encoded))
                    self._reply(200, payload, "application/json")
                except (FederationTransportError, ValueError):
                    owner._audit("invalid_event", 400, len(encoded))
                    self._json(400, {"error": "invalid_event"})

        self._httpd = _BoundedThreadingHTTPServer(
            (host, int(port)),
            Handler,
            worker_limit=self.worker_limit,
            request_timeout=self.request_timeout_seconds,
        )
        self._thread: threading.Thread | None = None

    def _audit_unlocked(self, operation: str, status: int, byte_count: int) -> None:
        self.audit_log.append(
            {"operation": operation, "status": int(status), "bytes": int(byte_count)}
        )
        if len(self.audit_log) > 10_000:
            del self.audit_log[: len(self.audit_log) - 10_000]

    def _audit(self, operation: str, status: int, byte_count: int) -> None:
        with self._lock:
            self._audit_unlocked(operation, status, byte_count)

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        selected = "127.0.0.1" if host in {"0.0.0.0", "::"} else host  # nosec B104 - display URL, not a bind
        return f"http://{selected}:{port}"

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="rta-smriti-http-relay",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


class FederationHttpRelay:
    """Bounded client implementing the opaque relay methods used by sync."""

    def __init__(self, base_url: str, *, capability: str, timeout: float = 10.0) -> None:
        selected = str(base_url).rstrip("/")
        if not selected or "\\" in selected or any(ord(char) < 32 for char in selected):
            raise ValueError("relay URL is invalid")
        parsed = urllib.parse.urlsplit(selected)
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("relay URL has an invalid port") from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("relay URL must be an unambiguous HTTP or HTTPS endpoint")
        self.base_url = urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
        )
        self.capability = _capability(capability)
        self.timeout = max(0.1, min(float(timeout), 60.0))

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        authorized: bool = True,
    ) -> tuple[bytes, str]:
        headers = {"Accept": "application/json"}
        if authorized:
            headers["X-Rta-Space-Capability"] = self.capability
        if data is not None:
            headers["Content-Type"] = "application/octet-stream"
        request = urllib.request.Request(
            self.base_url + path, data=data, headers=headers, method=method
        )
        try:
            opener = urllib.request.build_opener(_NoRedirectHandler())
            with opener.open(request, timeout=self.timeout) as response:  # nosec B310 - constructor restricts schemes to HTTP(S)
                content_length = int(response.headers.get("Content-Length", "-1"))
                if not 0 <= content_length <= _MAX_RESPONSE_BYTES:
                    raise FederationTransportError("relay response exceeds the bounded size")
                payload = response.read(content_length + 1)
                if len(payload) != content_length:
                    raise FederationTransportError("relay response length is invalid")
                return payload, response.headers.get("Content-Type", "")
        except urllib.error.HTTPError as exc:
            reason = {
                403: "relay authorization failed",
                413: "relay quota or size limit exceeded",
                429: "relay rate limit exceeded",
            }.get(exc.code, f"relay request failed with status {exc.code}")
            raise FederationTransportError(reason) from exc
        except urllib.error.URLError as exc:
            raise FederationTransportError("relay is unavailable") from exc

    def health(self) -> dict[str, Any]:
        encoded, _ = self._request("/health", authorized=False)
        value = json.loads(encoded)
        if not isinstance(value, dict) or value.get("state") != "healthy":
            raise FederationTransportError("relay health response is invalid")
        return value

    def put_event(self, envelope: FederationEventEnvelope) -> dict[str, str | int]:
        encoded, _ = self._request(
            f"/v1/spaces/{envelope.space_id}/events/{envelope.event_id}",
            method="PUT",
            data=envelope.encoded,
        )
        value = json.loads(encoded)
        if not isinstance(value, dict) or value.get("state") not in {"stored", "already_present"}:
            raise FederationTransportError("relay write receipt is invalid")
        return {
            "state": str(value["state"]),
            "event_id": envelope.event_id,
            "bytes": int(value["bytes"]),
        }

    def inventory(
        self, space_id: str, *, scope_id: str | None = None
    ) -> list[str]:
        selected = _identifier("space_id", space_id)
        suffix = ""
        if scope_id is not None:
            suffix = "?scope_id=" + urllib.parse.quote(
                _identifier("scope_id", scope_id), safe=""
            )
        encoded, _ = self._request(f"/v1/spaces/{selected}/inventory{suffix}")
        value = json.loads(encoded)
        event_ids = value.get("event_ids") if isinstance(value, dict) else None
        if not isinstance(event_ids, list) or len(event_ids) > MAX_RELAY_OBJECTS:
            raise FederationTransportError("relay inventory response is invalid")
        return sorted(_identifier("event_id", item) for item in event_ids)

    def missing(self, space_id: str, known_event_ids: tuple[str, ...]) -> list[str]:
        if not isinstance(known_event_ids, tuple) or len(known_event_ids) > MAX_RELAY_OBJECTS:
            raise ValueError("known_event_ids must be a bounded tuple")
        known = {_identifier("event_id", item) for item in known_event_ids}
        return sorted(set(self.inventory(space_id)) - known)

    def get_event(self, space_id: str, event_id: str) -> FederationEventEnvelope:
        selected_space = _identifier("space_id", space_id)
        selected_event = _identifier("event_id", event_id)
        encoded, _ = self._request(
            f"/v1/spaces/{selected_space}/events/{selected_event}"
        )
        try:
            envelope = parse_event_envelope(encoded)
        except (TypeError, ValueError) as exc:
            raise FederationTransportError("relay event response is invalid") from exc
        if envelope.space_id != selected_space or envelope.event_id != selected_event:
            raise FederationTransportError("relay event routing identity is invalid")
        if hashlib.sha256(envelope.ciphertext).hexdigest() != envelope.ciphertext_sha256:
            raise FederationTransportError("relay event ciphertext digest is invalid")
        return envelope
