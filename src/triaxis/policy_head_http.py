"""Minimal standard-library HTTP adapter for the external Policy Head Authority.

The adapter keeps security-sensitive decisions in the domain service. It does
not implement TLS, reverse-proxy authentication, rate limiting, or production
secret custody; those belong to the deployment boundary.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .policy_head_authority import PolicyHeadAuthorityError, SQLitePolicyHeadAuthorityService


class PolicyHeadHTTPApplication:
    def __init__(
        self,
        service: SQLitePolicyHeadAuthorityService,
        *,
        clock: Callable[[], int],
        response_ttl: int = 10,
        admin_token_sha256: str | None = None,
    ) -> None:
        if type(response_ttl) is not int or response_ttl < 1:
            raise ValueError("response_ttl must be integer >= 1")
        if admin_token_sha256 is not None and (
            len(admin_token_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in admin_token_sha256)
        ):
            raise ValueError("admin_token_sha256 must be lowercase SHA-256")
        self.service = service
        self.clock = clock
        self.response_ttl = response_ttl
        self.admin_token_sha256 = admin_token_sha256

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
                head = self.service.policy_store.head()
                return 200, {
                    "status": "ok",
                    "authority_id": self.service.authority_id,
                    "policy_head": head,
                }
            if method == "POST" and path == "/v1/head/challenge":
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                now = self.clock()
                signed = self.service.issue_head_response(
                    challenge=str(body.get("challenge", "")),
                    verifier_id=str(body.get("verifier_id", "")),
                    verifier_epoch_sha256=str(body.get("verifier_epoch_sha256", "")),
                    requested_at=body.get("requested_at"),
                    issued_at=now,
                    valid_until=now + self.response_ttl,
                )
                return 200, {"signed_policy_head": signed}
            if method == "POST" and path == "/v1/policies/install":
                if not self._authorized(headers):
                    return 403, {"error": "administrative_authorization_required"}
                if not isinstance(body, Mapping) or not isinstance(body.get("signed_policy"), Mapping):
                    return 400, {"error": "signed_policy_required"}
                result = self.service.install_policy(body["signed_policy"], self.clock())
                return 200, {"status": "installed", "head": result}
            return 404, {"error": "not_found"}
        except PolicyHeadAuthorityError as exc:
            return 409, {"error": exc.code, "detail": exc.detail}
        except (TypeError, ValueError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)}
        except Exception as exc:  # fail closed; do not leak traceback through HTTP
            return 500, {"error": "internal_error", "detail": type(exc).__name__}


def build_http_server(host: str, port: int, app: PolicyHeadHTTPApplication) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TRIAXISPolicyHead/1"

        def _send(self, status: int, payload: Mapping[str, Any]) -> None:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _body(self) -> Any:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return None
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

    return ThreadingHTTPServer((host, port), Handler)


__all__ = ["PolicyHeadHTTPApplication", "build_http_server"]
