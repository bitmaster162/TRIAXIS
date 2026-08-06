"""Standard-library HTTP boundary for the v3.30 completion WORM anchor."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .completion_worm_anchor import CompletionWORMAnchorError, SQLiteCompletionWORMAnchor
from .crypto_trust import TrustKeyRegistry


class CompletionWORMAnchorHTTPApplication:
    def __init__(
        self,
        anchor: SQLiteCompletionWORMAnchor,
        *,
        clock: Callable[[], int],
        client_token_sha256: str | None,
        provider_registry: TrustKeyRegistry,
        expected_provider_signer_id: str,
        expected_provider_trust_domain: str,
        response_ttl: int = 10,
        max_provider_receipt_age: int = 30,
    ) -> None:
        if client_token_sha256 is not None and (
            len(client_token_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in client_token_sha256)
        ):
            raise ValueError("client_token_sha256 must be lowercase SHA-256")
        for name, value in (
            ("expected_provider_signer_id", expected_provider_signer_id),
            ("expected_provider_trust_domain", expected_provider_trust_domain),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty")
        if type(response_ttl) is not int or response_ttl < 1:
            raise ValueError("response_ttl must be integer >= 1")
        if type(max_provider_receipt_age) is not int or max_provider_receipt_age < 0:
            raise ValueError("max_provider_receipt_age must be integer >= 0")
        self.anchor = anchor
        self.clock = clock
        self.client_token_sha256 = client_token_sha256
        self.provider_registry = provider_registry
        self.expected_provider_signer_id = expected_provider_signer_id
        self.expected_provider_trust_domain = expected_provider_trust_domain
        self.response_ttl = response_ttl
        self.max_provider_receipt_age = max_provider_receipt_age

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if self.client_token_sha256 is None:
            return False
        value = headers.get("authorization") or headers.get("Authorization") or ""
        if not value.startswith("Bearer "):
            return False
        observed = hashlib.sha256(value[7:].encode("utf-8")).hexdigest()
        return hmac.compare_digest(observed, self.client_token_sha256)

    def handle(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        headers = headers or {}
        try:
            if method == "GET" and path == "/healthz":
                return 200, {
                    "status": "ok",
                    "process_id": os.getpid(),
                    "authority_id": self.anchor.authority_id,
                    "service_id": self.anchor.service_id,
                    "signer_id": self.anchor.signer_id,
                    "key_id": self.anchor.key_id,
                    "trust_domain": self.anchor.trust_domain,
                    "anchor": self.anchor.health_snapshot(),
                }

            if method == "POST" and path == "/v1/effects/status/challenge":
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                requested_at = body.get("requested_at")
                if type(requested_at) is not int:
                    return 400, {"error": "requested_at_integer_required"}
                now = self.clock()
                signed = self.anchor.issue_status(
                    effect_id=str(body.get("effect_id", "")),
                    expected_payload_sha256=str(body.get("payload_sha256", "")),
                    challenge=str(body.get("challenge", "")),
                    verifier_id=str(body.get("verifier_id", "")),
                    verifier_epoch_sha256=str(body.get("verifier_epoch_sha256", "")),
                    requested_at=requested_at,
                    issued_at=now,
                    valid_until=now + self.response_ttl,
                )
                return 200, {"signed_completion_worm_anchor_status": signed}

            if method == "POST" and path == "/v1/outcomes/ingest":
                if not self._authorized(headers):
                    return 403, {"error": "client_authorization_required"}
                if not isinstance(body, Mapping) or not isinstance(
                    body.get("signed_provider_receipt"), Mapping
                ):
                    return 400, {"error": "signed_provider_receipt_required"}
                result = self.anchor.ingest_provider_outcome(
                    body["signed_provider_receipt"],
                    provider_registry=self.provider_registry,
                    expected_provider_signer_id=self.expected_provider_signer_id,
                    expected_provider_trust_domain=self.expected_provider_trust_domain,
                    evaluation_tick=self.clock(),
                    max_provider_receipt_age=self.max_provider_receipt_age,
                )
                payload = {
                    "status": result["status"],
                    "idempotent_replay": result["idempotent_replay"],
                    "effect": result["effect"],
                }
                if "signed_anchor_event" in result:
                    payload["signed_anchor_event"] = result["signed_anchor_event"]
                return 200, payload

            return 404, {"error": "not_found"}
        except CompletionWORMAnchorError as exc:
            return 409, {"error": exc.code, "detail": exc.detail}
        except (TypeError, ValueError, KeyError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)}
        except Exception as exc:
            return 500, {"error": "internal_error", "detail": type(exc).__name__}


def build_completion_worm_anchor_http_server(
    host: str,
    port: int,
    app: CompletionWORMAnchorHTTPApplication,
) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TRIAXISCompletionWORMAnchor/1"

        def _send(self, status: int, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def _body(self) -> Any:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return None
            if length > 16 * 1024 * 1024:
                raise ValueError("request body too large")
            return json.loads(self.rfile.read(length).decode("utf-8"))

        def do_GET(self) -> None:  # noqa: N802
            status, payload = app.handle("GET", self.path, headers=dict(self.headers))
            self._send(status, payload)

        def do_POST(self) -> None:  # noqa: N802
            try:
                body = self._body()
            except Exception:
                self._send(400, {"error": "invalid_json"})
                return
            status, payload = app.handle("POST", self.path, body, dict(self.headers))
            self._send(status, payload)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return HTTPServer((host, port), Handler)


__all__ = [
    "CompletionWORMAnchorHTTPApplication",
    "build_completion_worm_anchor_http_server",
]
