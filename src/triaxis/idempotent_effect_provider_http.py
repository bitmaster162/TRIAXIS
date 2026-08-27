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
from .provider_transparency_guard import (
    ProviderTransparencyGuardError,
    verify_authenticated_terminal_external_effect_guard,
)


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(ch in "0123456789abcdef" for ch in value)
    )


class IdempotentEffectProviderHTTPApplication:
    """Legacy/reference v3.28 HTTP application.

    Mutation routes are protected only by the configured transport Bearer secret.
    This class is intentionally retained for compatibility and is not authenticated
    RHE action authority.
    """

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
                "/v1/effects/begin", "/v1/effects/outcome", "/v1/effects/reconcile",
                "/v1/effects/outcome-receipt"
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
                elif path == "/v1/effects/outcome-receipt":
                    signed = self.provider.issue_outcome_receipt(
                        effect_id=str(body.get("effect_id", "")),
                        issued_at=now,
                        valid_until=now + self.response_ttl,
                    )
                    return 200, {"signed_provider_outcome_receipt": signed}
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


class AuthenticatedIdempotentEffectProviderHTTPApplication(
    IdempotentEffectProviderHTTPApplication
):
    """Authenticated RHE transport mode for effect initiation.

    ``/v1/effects/begin`` requires both transport Bearer authentication and a
    successful ``verify_authenticated_terminal_external_effect_guard`` result.
    The provider effect identity and payload are derived from authenticated
    evidence rather than trusted from caller-supplied ``effect_id`` or
    ``payload_sha256`` fields.

    Outcome/reconciliation routes retain the historical transport-authenticated
    semantics; this R2 class closes effect initiation only.
    """

    def __init__(
        self,
        provider: SQLiteIdempotentEffectProvider,
        *,
        clock: Callable[[], int],
        client_token_sha256: str | None,
        authorization_registry: Any,
        v331_guard_kwargs: Mapping[str, Any],
        provider_status_kwargs: Mapping[str, Any],
        transparency_kwargs: Mapping[str, Any],
        response_ttl: int = 10,
    ) -> None:
        super().__init__(
            provider,
            clock=clock,
            client_token_sha256=client_token_sha256,
            response_ttl=response_ttl,
        )
        self.authorization_registry = authorization_registry
        self.v331_guard_kwargs = self._pin_server_provider_identity(
            v331_guard_kwargs,
            provider_id=provider.provider_id,
            service_id=provider.service_id,
            provider_id_field="expected_provider_id",
            service_id_field="expected_provider_service_id",
        )
        self.provider_status_kwargs = self._pin_server_provider_identity(
            provider_status_kwargs,
            provider_id=provider.provider_id,
            service_id=provider.service_id,
            provider_id_field="expected_provider_id",
            service_id_field="expected_service_id",
        )
        self.transparency_kwargs = self._pin_server_provider_identity(
            transparency_kwargs,
            provider_id=provider.provider_id,
            service_id=provider.service_id,
            provider_id_field="expected_provider_id",
            service_id_field="expected_provider_service_id",
        )

    @staticmethod
    def _pin_server_provider_identity(
        values: Mapping[str, Any],
        *,
        provider_id: str,
        service_id: str,
        provider_id_field: str,
        service_id_field: str,
    ) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise TypeError("authenticated guard kwargs must be mappings")
        pinned = dict(values)
        if provider_id_field in pinned and pinned[provider_id_field] != provider_id:
            raise ValueError(f"{provider_id_field} must match provider identity")
        if service_id_field in pinned and pinned[service_id_field] != service_id:
            raise ValueError(f"{service_id_field} must match provider service identity")
        pinned[provider_id_field] = provider_id
        pinned[service_id_field] = service_id
        return pinned

    @staticmethod
    def _required_authenticated_begin_fields(body: Mapping[str, Any]) -> list[str]:
        required = (
            "signed_authorization_token",
            "signed_risk_mediation_receipt",
            "intent",
            "signed_in_flight_receipt",
            "signed_provider_status",
            "signed_local_anchor_head",
            "signed_transparency_responses",
            "provider_request_id",
        )
        return [field for field in required if field not in body]

    def _handle_authenticated_begin(
        self,
        body: Any,
        headers: Mapping[str, str],
    ) -> tuple[int, dict[str, Any]]:
        if not self._authorized(headers):
            return 403, {"error": "client_authorization_required"}
        if not isinstance(body, Mapping):
            return 400, {"error": "invalid_json_object"}

        missing = self._required_authenticated_begin_fields(body)
        if missing:
            return 403, {
                "error": "authenticated_terminal_effect_guard_required",
                "missing": missing,
            }

        provider_request_id = body.get("provider_request_id")
        if not isinstance(provider_request_id, str) or not provider_request_id:
            return 400, {"error": "provider_request_id_required"}

        now = self.clock()
        if type(now) is not int or now < 0:
            return 500, {"error": "invalid_server_clock"}

        try:
            guard = verify_authenticated_terminal_external_effect_guard(
                signed_authorization_token=body["signed_authorization_token"],
                signed_risk_mediation_receipt=body["signed_risk_mediation_receipt"],
                authorization_registry=self.authorization_registry,
                evaluation_tick=now,
                intent=body["intent"],
                signed_in_flight_receipt=body["signed_in_flight_receipt"],
                v331_guard_kwargs=self.v331_guard_kwargs,
                signed_provider_status=body["signed_provider_status"],
                provider_status_kwargs=self.provider_status_kwargs,
                signed_local_anchor_head=body["signed_local_anchor_head"],
                signed_transparency_responses=body["signed_transparency_responses"],
                transparency_kwargs=self.transparency_kwargs,
            )
        except ProviderTransparencyGuardError as exc:
            return 403, {"error": exc.code, "detail": exc.detail}
        except Exception as exc:
            return 403, {
                "error": "authenticated_terminal_effect_guard_failed",
                "detail": type(exc).__name__,
            }

        if (
            not isinstance(guard, Mapping)
            or guard.get("status") != "PASS"
            or guard.get("external_effect_permitted") is not True
            or guard.get("authority_granted") not in (False, None)
            or guard.get("authenticated_terminal_effect_bridge") is not True
        ):
            return 403, {"error": "authenticated_terminal_effect_guard_required"}

        effect_id = guard.get("effect_id")
        if not _is_sha256(effect_id):
            return 403, {"error": "provider_effect_binding_invalid"}

        signed_token = body["signed_authorization_token"]
        if not isinstance(signed_token, Mapping):
            return 403, {"error": "authenticated_authorization_shape_invalid"}
        token = signed_token.get("inner_contract")
        payload_sha256 = token.get("payload_sha256") if isinstance(token, Mapping) else None
        if not _is_sha256(payload_sha256):
            return 403, {"error": "provider_payload_binding_invalid"}

        if "effect_id" in body and body.get("effect_id") != effect_id:
            return 403, {"error": "provider_effect_binding_mismatch"}
        if "payload_sha256" in body and body.get("payload_sha256") != payload_sha256:
            return 403, {"error": "provider_payload_binding_mismatch"}

        result = self.provider.begin(
            effect_id=effect_id,
            payload_sha256=payload_sha256,
            provider_request_id=provider_request_id,
            now_tick=now,
        )
        response = dict(result)
        response["authenticated_terminal_effect_bridge"] = True
        response["authenticated_effect_id"] = effect_id
        return 200, response

    def handle(
        self,
        method: str,
        path: str,
        body: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> tuple[int, dict[str, Any]]:
        headers = headers or {}
        if method == "POST" and path == "/v1/effects/begin":
            try:
                return self._handle_authenticated_begin(body, headers)
            except ProviderEffectError as exc:
                return 409, {"error": exc.code, "detail": exc.detail}
            except (TypeError, ValueError, KeyError) as exc:
                return 400, {"error": "invalid_request", "detail": str(exc)}
            except Exception as exc:
                return 500, {"error": "internal_error", "detail": type(exc).__name__}
        return super().handle(method, path, body, headers)


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


__all__ = [
    "AuthenticatedIdempotentEffectProviderHTTPApplication",
    "IdempotentEffectProviderHTTPApplication",
    "build_idempotent_effect_provider_http_server",
]
