"""Standard-library HTTP boundary for the v3.28 reference idempotent provider."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .idempotent_effect_provider import ProviderEffectError, SQLiteIdempotentEffectProvider


class IdempotentEffectProviderHTTPApplication:
    def __init__(
        self,
        provider: SQLiteIdempotentEffectProvider,
        *,
        clock: Callable[[], int],
        client_token_sha256: str | None,
        response_ttl: int = 10,
    ) -> None:
        if client_token_sha256 is not None and (
            len(client_token_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in client_token_sha256)
        ):
            raise ValueError("client_token_sha256 must be lowercase SHA-256")
        if type(response_ttl) is not int or response_ttl < 1:
            raise ValueError("response_ttl must be integer >= 1")
        self.provider = provider
        self.clock = clock
        self.client_token_sha256 = client_token_sha256
        self.response_ttl = response_ttl

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
                    "provider_id": self.provider.provider_id,
                    "service_id": self.provider.service_id,
                    "signer_id": self.provider.signer_id,
                    "key_id": self.provider.key_id,
                    "trust_domain": self.provider.trust_domain,
                    "effect_count": self.provider.effect_count(),
                }

            if method == "POST" and path == "/v1/effects/status/challenge":
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                requested_at = body.get("requested_at")
                if type(requested_at) is not int:
                    return 400, {"error": "requested_at_integer_required"}
                now = self.clock()
                signed = self.provider.issue_status(
                    effect_id=str(body.get("effect_id", "")),
                    expected_payload_sha256=str(body.get("payload_sha256", "")),
                    challenge=str(body.get("challenge", "")),
                    verifier_id=str(body.get("verifier_id", "")),
                    verifier_epoch_sha256=str(body.get("verifier_epoch_sha256", "")),
                    requested_at=requested_at,
                    issued_at=now,
                    valid_until=now + self.response_ttl,
                )
                return 200, {"signed_provider_effect_status": signed}

            if method == "POST" and path in {
                "/v1/effects/begin", "/v1/effects/outcome", "/v1/effects/reconcile"
            }:
                if not self._authorized(headers):
                    return 403, {"error": "client_authorization_required"}
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                now = self.clock()
                if path == "/v1/effects/begin":
                    result = self.provider.begin(
                        effect_id=str(body.get("effect_id", "")),
                        payload_sha256=str(body.get("payload_sha256", "")),
                        provider_request_id=str(body.get("provider_request_id", "")),
                        now_tick=now,
                    )
                elif path == "/v1/effects/outcome":
                    result = self.provider.record_outcome(
                        effect_id=str(body.get("effect_id", "")),
                        provider_request_id=str(body.get("provider_request_id", "")),
                        outcome=str(body.get("outcome", "")),
                        provider_response_sha256=body.get("provider_response_sha256"),
                        evidence_sha256=str(body.get("evidence_sha256", "")),
                        now_tick=now,
                    )
                else:
                    result = self.provider.reconcile_unknown(
                        effect_id=str(body.get("effect_id", "")),
                        provider_request_id=str(body.get("provider_request_id", "")),
                        outcome=str(body.get("outcome", "")),
                        provider_response_sha256=body.get("provider_response_sha256"),
                        evidence_sha256=str(body.get("evidence_sha256", "")),
                        now_tick=now,
                    )
                return 200, result

            return 404, {"error": "not_found"}
        except ProviderEffectError as exc:
            return 409, {"error": exc.code, "detail": exc.detail}
        except (TypeError, ValueError, KeyError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)}
        except Exception as exc:
            return 500, {"error": "internal_error", "detail": type(exc).__name__}


def build_idempotent_effect_provider_http_server(
    host: str,
    port: int,
    app: IdempotentEffectProviderHTTPApplication,
) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TRIAXISIdempotentProvider/1"

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
            if length > 8 * 1024 * 1024:
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


__all__ = ["IdempotentEffectProviderHTTPApplication", "build_idempotent_effect_provider_http_server"]
