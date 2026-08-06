"""Standard-library HTTP boundary for the TRIAXIS v3.27 execution ledger.

The adapter authenticates state-changing requests with a transport bearer token.
That token is not TRIAXIS action authority.  Domain validation and signed
idempotency receipts remain inside ``SQLiteExternalExecutionLedger``.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from typing import Any
from urllib.parse import unquote, urlsplit

from .external_execution_ledger import ExecutionLedgerError, SQLiteExternalExecutionLedger


class ExecutionLedgerHTTPApplication:
    def __init__(
        self,
        ledger: SQLiteExternalExecutionLedger,
        *,
        clock: Callable[[], int],
        client_token_sha256: str,
    ) -> None:
        if not isinstance(client_token_sha256, str) or len(client_token_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in client_token_sha256):
            raise ValueError("client_token_sha256 must be lowercase SHA-256")
        self.ledger = ledger
        self.clock = clock
        self.client_token_sha256 = client_token_sha256

    def _authorized(self, headers: Mapping[str, str]) -> bool:
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
        parsed = urlsplit(path)
        route = parsed.path
        try:
            if method == "GET" and route == "/healthz":
                sequence, head = self.ledger._meta()
                return 200, {
                    "status": "ok",
                    "process_id": os.getpid(),
                    "ledger_id": self.ledger.ledger_id,
                    "authority_id": self.ledger.authority_id,
                    "key_id": self.ledger.key_id,
                    "signer_id": self.ledger.signer_id,
                    "trust_domain": self.ledger.trust_domain,
                    "sequence": sequence,
                    "head_event_sha256": head,
                }

            if method == "GET" and route.startswith("/v1/effects/"):
                if not self._authorized(headers):
                    return 403, {"error": "client_authentication_required"}
                effect_id = unquote(route[len("/v1/effects/"):])
                effect = self.ledger.get_effect(effect_id)
                return (200, {"effect": effect}) if effect is not None else (404, {"error": "unknown_effect_id"})

            if method == "POST":
                if not self._authorized(headers):
                    return 403, {"error": "client_authentication_required"}
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                now = self.clock()
                if route == "/v1/effects/reserve":
                    result = self.ledger.reserve(
                        body.get("intent", {}),
                        attempt_id=str(body.get("attempt_id", "")),
                        dispatch_id=str(body.get("dispatch_id", "")),
                        now_tick=now,
                    )
                    return (200 if result["status"] == "PASS" else 409), result
                if route == "/v1/effects/start":
                    result = self.ledger.start(
                        str(body.get("effect_id", "")),
                        attempt_id=str(body.get("attempt_id", "")),
                        dispatch_id=str(body.get("dispatch_id", "")),
                        now_tick=now,
                    )
                    return 200, result
                if route == "/v1/effects/release":
                    result = self.ledger.release_before_effect(
                        str(body.get("effect_id", "")),
                        attempt_id=str(body.get("attempt_id", "")),
                        dispatch_id=str(body.get("dispatch_id", "")),
                        evidence_sha256=str(body.get("evidence_sha256", "")),
                        now_tick=now,
                    )
                    return 200, result
                if route == "/v1/effects/outcome":
                    result = self.ledger.record_outcome(
                        str(body.get("effect_id", "")),
                        attempt_id=str(body.get("attempt_id", "")),
                        dispatch_id=str(body.get("dispatch_id", "")),
                        outcome=str(body.get("outcome", "")),
                        evidence_sha256=str(body.get("evidence_sha256", "")),
                        now_tick=now,
                    )
                    return 200, result
                if route == "/v1/effects/reconcile":
                    result = self.ledger.reconcile_unknown(
                        str(body.get("effect_id", "")),
                        attempt_id=str(body.get("attempt_id", "")),
                        dispatch_id=str(body.get("dispatch_id", "")),
                        outcome=str(body.get("outcome", "")),
                        evidence_sha256=str(body.get("evidence_sha256", "")),
                        now_tick=now,
                    )
                    return 200, result
                if route == "/v1/head":
                    return 200, {"signed_head": self.ledger.head(now_tick=now)}

            return 404, {"error": "not_found"}
        except ExecutionLedgerError as exc:
            return 409, {"error": exc.code, "detail": exc.detail}
        except (TypeError, ValueError, KeyError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)}
        except Exception as exc:  # fail closed; do not expose traceback
            return 500, {"error": "internal_error", "detail": type(exc).__name__}


def build_execution_ledger_http_server(host: str, port: int, app: ExecutionLedgerHTTPApplication) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TRIAXISExecutionLedger/1"

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


__all__ = ["ExecutionLedgerHTTPApplication", "build_execution_ledger_http_server"]
