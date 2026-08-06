"""Standard-library HTTP boundary for the v3.28 execution-ledger head authority."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .execution_ledger_head_authority import (
    ExecutionLedgerHeadError,
    SQLiteExecutionLedgerHeadAuthority,
)


class ExecutionLedgerHeadHTTPApplication:
    def __init__(
        self,
        authority: SQLiteExecutionLedgerHeadAuthority,
        *,
        clock: Callable[[], int],
        admin_token_sha256: str | None,
        response_ttl: int = 10,
    ) -> None:
        if admin_token_sha256 is not None and (
            len(admin_token_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in admin_token_sha256)
        ):
            raise ValueError("admin_token_sha256 must be lowercase SHA-256")
        if type(response_ttl) is not int or response_ttl < 1:
            raise ValueError("response_ttl must be integer >= 1")
        self.authority = authority
        self.clock = clock
        self.admin_token_sha256 = admin_token_sha256
        self.response_ttl = response_ttl

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if self.admin_token_sha256 is None:
            return False
        value = headers.get("authorization") or headers.get("Authorization") or ""
        if not value.startswith("Bearer "):
            return False
        observed = hashlib.sha256(value[7:].encode("utf-8")).hexdigest()
        return hmac.compare_digest(observed, self.admin_token_sha256)

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
                    "authority_id": self.authority.authority_id,
                    "service_id": self.authority.service_id,
                    "signer_id": self.authority.signer_id,
                    "key_id": self.authority.key_id,
                    "trust_domain": self.authority.trust_domain,
                    "ledgers": self.authority.health_snapshot(),
                }

            if method == "POST" and path == "/v1/heads/install":
                if not self._authorized(headers):
                    return 403, {"error": "administrative_authorization_required"}
                if not isinstance(body, Mapping) or not isinstance(body.get("signed_head"), Mapping):
                    return 400, {"error": "signed_head_required"}
                signed_events = body.get("signed_events", [])
                if not isinstance(signed_events, list):
                    return 400, {"error": "signed_events_array_required"}
                installed = self.authority.install_advance(
                    body["signed_head"], signed_events, evaluation_tick=self.clock()
                )
                head = installed["signed_head"]["inner_contract"]
                return 200, {
                    "status": "installed",
                    "idempotent_replay": installed["idempotent_replay"],
                    "accepted_event_count": installed.get("accepted_event_count", 0),
                    "head": {
                        "ledger_id": head["ledger_id"],
                        "sequence": head["sequence"],
                        "head_event_sha256": head["head_event_sha256"],
                        "state_root_sha256": head["state_root_sha256"],
                    },
                }

            if method == "POST" and path == "/v1/head/challenge":
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                requested_at = body.get("requested_at")
                if type(requested_at) is not int:
                    return 400, {"error": "requested_at_integer_required"}
                now = self.clock()
                signed = self.authority.issue_head(
                    ledger_id=str(body.get("ledger_id", "")),
                    challenge=str(body.get("challenge", "")),
                    verifier_id=str(body.get("verifier_id", "")),
                    verifier_epoch_sha256=str(body.get("verifier_epoch_sha256", "")),
                    requested_at=requested_at,
                    issued_at=now,
                    valid_until=now + self.response_ttl,
                )
                return 200, {"signed_execution_ledger_head": signed}

            return 404, {"error": "not_found"}
        except ExecutionLedgerHeadError as exc:
            return 409, {"error": exc.code, "detail": exc.detail}
        except (TypeError, ValueError, KeyError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)}
        except Exception as exc:
            return 500, {"error": "internal_error", "detail": type(exc).__name__}


def build_execution_ledger_head_http_server(
    host: str,
    port: int,
    app: ExecutionLedgerHeadHTTPApplication,
) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TRIAXISExecutionLedgerHead/1"

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


__all__ = ["ExecutionLedgerHeadHTTPApplication", "build_execution_ledger_head_http_server"]
