"""Standard-library HTTP boundary for a Gossip Head Authority.

This adapter exposes the v3.16 SQLiteGossipHeadAuthority as a small network
service. Security-sensitive validation remains inside the domain object. The
adapter intentionally does not claim TLS termination, production rate limiting,
secret custody, physical independence, or administrator independence.

Production deployments must place this service behind mutually authenticated
transport and keep its Ed25519 private key in an external KMS/HSM or equivalent
secret boundary.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .policy_head_authority import PolicyHeadAuthorityError
from .policy_transparency_gossip_head import SQLiteGossipHeadAuthority


class GossipHeadHTTPApplication:
    """Pure request handler used by both unit tests and the HTTP server."""

    def __init__(
        self,
        authority: SQLiteGossipHeadAuthority,
        *,
        clock: Callable[[], int],
        response_ttl: int = 10,
        admin_token_sha256: str | None = None,
    ) -> None:
        if type(response_ttl) is not int or response_ttl < 1:
            raise ValueError("response_ttl must be integer >= 1")
        if admin_token_sha256 is not None and (
            len(admin_token_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in admin_token_sha256)
        ):
            raise ValueError("admin_token_sha256 must be lowercase SHA-256")
        self.authority = authority
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
                store_id = None
                current = None
                row = self.authority._conn.execute(
                    "SELECT store_id,signed_json FROM accepted_gossip_checkpoints "
                    "ORDER BY store_id LIMIT 1"
                ).fetchone()
                if row is not None:
                    store_id = row[0]
                    signed = json.loads(row[1])
                    inner = signed.get("inner_contract", {})
                    current = {
                        "store_id": store_id,
                        "checkpoint_sequence": inner.get("checkpoint_sequence"),
                        "checkpoint_sha256": inner.get("checkpoint_sha256"),
                        "gossip_sequence": inner.get("gossip_sequence"),
                    }
                return 200, {
                    "status": "ok",
                    "process_id": os.getpid(),
                    "authority_id": self.authority.authority_id,
                    "service_id": self.authority.service_id,
                    "signer_id": self.authority.signer_id,
                    "key_id": self.authority.key_id,
                    "trust_domain": self.authority.trust_domain,
                    "current": current,
                }

            if method == "POST" and path == "/v1/checkpoints/install":
                if not self._authorized(headers):
                    return 403, {"error": "administrative_authorization_required"}
                if not isinstance(body, Mapping) or not isinstance(body.get("signed_checkpoint"), Mapping):
                    return 400, {"error": "signed_checkpoint_required"}
                installed = self.authority.install(body["signed_checkpoint"], self.clock())
                cp = installed["inner_contract"]
                return 200, {
                    "status": "installed",
                    "checkpoint": {
                        "store_id": cp["store_id"],
                        "checkpoint_sequence": cp["checkpoint_sequence"],
                        "checkpoint_sha256": cp["checkpoint_sha256"],
                        "gossip_sequence": cp["gossip_sequence"],
                    },
                }

            if method == "POST" and path == "/v1/head/challenge":
                if not isinstance(body, Mapping):
                    return 400, {"error": "invalid_json_object"}
                now = self.clock()
                requested_at = body.get("requested_at")
                if type(requested_at) is not int:
                    return 400, {"error": "requested_at_integer_required"}
                signed = self.authority.issue_head(
                    store_id=str(body.get("store_id", "")),
                    challenge=str(body.get("challenge", "")),
                    verifier_id=str(body.get("verifier_id", "")),
                    verifier_epoch_sha256=str(body.get("verifier_epoch_sha256", "")),
                    requested_at=requested_at,
                    issued_at=now,
                    valid_until=now + self.response_ttl,
                )
                return 200, {"signed_gossip_head": signed}

            return 404, {"error": "not_found"}
        except PolicyHeadAuthorityError as exc:
            return 409, {"error": exc.code, "detail": exc.detail}
        except (TypeError, ValueError, KeyError) as exc:
            return 400, {"error": "invalid_request", "detail": str(exc)}
        except Exception as exc:  # fail closed; do not expose traceback
            return 500, {"error": "internal_error", "detail": type(exc).__name__}


def build_gossip_head_http_server(
    host: str,
    port: int,
    app: GossipHeadHTTPApplication,
) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TRIAXISGossipHead/1"

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


__all__ = ["GossipHeadHTTPApplication", "build_gossip_head_http_server"]
