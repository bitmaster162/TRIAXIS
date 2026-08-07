"""HTTP boundary for TRIAXIS v3.32 provider-native idempotency reference."""
from __future__ import annotations
from collections.abc import Callable, Mapping
import hashlib, hmac, json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from .provider_native_idempotency import FilesystemProviderNativeIdempotencyReference, ProviderNativeIdempotencyError


class ProviderNativeIdempotencyHTTPApplication:
    def __init__(self, provider: FilesystemProviderNativeIdempotencyReference, *, clock: Callable[[], int], client_token_sha256: str | None, policy: Mapping[str, Any]) -> None:
        self.provider = provider
        self.clock = clock
        self.client_token_sha256 = client_token_sha256
        self.policy = dict(policy)

    def _authorized(self, headers: Mapping[str, str]) -> bool:
        if self.client_token_sha256 is None:
            return False
        value = headers.get("authorization") or headers.get("Authorization") or ""
        if not value.startswith("Bearer "):
            return False
        return hmac.compare_digest(hashlib.sha256(value[7:].encode()).hexdigest(), self.client_token_sha256)

    def handle(self, method: str, path: str, body: Any = None, headers: Mapping[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        headers = headers or {}
        try:
            if method == "GET" and path == "/healthz":
                return 200, {"status":"ok","process_id":os.getpid(),"provider_id":self.provider.provider_id,"service_id":self.provider.service_id,"namespace_id":self.provider.namespace_id,"signer_id":self.provider.signer_id,"key_id":self.provider.key_id,"trust_domain":self.provider.trust_domain,"local_reference":True,"real_provider_integration":False}
            if method == "GET" and path == "/v1/head":
                return 200, {"signed_provider_native_head": self.provider.signed_head(now_tick=self.clock())}
            if method == "POST" and path == "/v1/status/challenge":
                if not isinstance(body, Mapping): return 400, {"error":"invalid_json_object"}
                now=self.clock()
                signed=self.provider.signed_status(effect_id=str(body.get("effect_id","")), payload_sha256=str(body.get("payload_sha256","")), challenge=str(body.get("challenge","")), verifier_id=str(body.get("verifier_id","")), verifier_epoch_sha256=str(body.get("verifier_epoch_sha256","")), policy=self.policy, now_tick=now)
                return 200, {"signed_provider_native_status": signed}
            if method == "POST" and path == "/v1/effects/begin":
                if not self._authorized(headers): return 403, {"error":"client_authorization_required"}
                if not isinstance(body, Mapping): return 400, {"error":"invalid_json_object"}
                return 200, self.provider.begin(effect_id=str(body.get("effect_id","")), payload_sha256=str(body.get("payload_sha256","")), provider_request_id=str(body.get("provider_request_id","")), now_tick=self.clock())
            if method == "POST" and path == "/v1/effects/outcome":
                if not self._authorized(headers): return 403, {"error":"client_authorization_required"}
                if not isinstance(body, Mapping): return 400, {"error":"invalid_json_object"}
                return 200, self.provider.record_outcome(effect_id=str(body.get("effect_id","")), state=str(body.get("state","")), provider_response_sha256=str(body.get("provider_response_sha256","")), evidence_sha256=str(body.get("evidence_sha256","")), now_tick=self.clock())
            return 404, {"error":"not_found"}
        except ProviderNativeIdempotencyError as exc:
            return 409, {"error":exc.code,"detail":exc.detail}
        except Exception as exc:
            return 400, {"error":"invalid_request","detail":str(exc)}


def build_provider_native_idempotency_http_server(host: str, port: int, app: ProviderNativeIdempotencyHTTPApplication) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version="TRIAXISProviderNative/1"
        def _send(self,status:int,payload:Mapping[str,Any])->None:
            data=json.dumps(payload,sort_keys=True,separators=(",",":")).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data)
        def _body(self):
            n=int(self.headers.get("Content-Length","0")); return None if n<=0 else json.loads(self.rfile.read(n).decode())
        def do_GET(self):
            status,payload=app.handle("GET",self.path,headers=dict(self.headers)); self._send(status,payload)
        def do_POST(self):
            try: body=self._body()
            except Exception: self._send(400,{"error":"invalid_json"}); return
            status,payload=app.handle("POST",self.path,body,dict(self.headers)); self._send(status,payload)
        def log_message(self,*args): return
    return HTTPServer((host,port),Handler)

__all__=["ProviderNativeIdempotencyHTTPApplication","build_provider_native_idempotency_http_server"]
