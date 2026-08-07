"""HTTP boundary for TRIAXIS v3.32 completion transparency authority."""
from __future__ import annotations
from collections.abc import Callable, Mapping
import hashlib,hmac,json,os
from http.server import BaseHTTPRequestHandler,HTTPServer
from typing import Any
from .completion_immutable_anchor import CompletionImmutableAnchorError, verify_completion_immutable_anchor_head
from .completion_transparency_quorum import CompletionTransparencyError, SQLiteCompletionTransparencyAuthority
from .crypto_trust import TrustKeyRegistry

class CompletionTransparencyHTTPApplication:
    def __init__(self, authority: SQLiteCompletionTransparencyAuthority, *, clock: Callable[[],int], client_token_sha256: str|None, anchor_registry: TrustKeyRegistry, anchor_expectations: Mapping[str,str]) -> None:
        self.authority=authority; self.clock=clock; self.client_token_sha256=client_token_sha256; self.anchor_registry=anchor_registry; self.anchor_expectations=dict(anchor_expectations)
    def _authorized(self,headers:Mapping[str,str])->bool:
        if self.client_token_sha256 is None:return False
        value=headers.get("authorization") or headers.get("Authorization") or ""
        return value.startswith("Bearer ") and hmac.compare_digest(hashlib.sha256(value[7:].encode()).hexdigest(),self.client_token_sha256)
    def handle(self,method:str,path:str,body:Any=None,headers:Mapping[str,str]|None=None)->tuple[int,dict[str,Any]]:
        headers=headers or {}
        try:
            if method=="GET" and path=="/healthz":
                return 200,{"status":"ok","process_id":os.getpid(),"authority_id":self.authority.authority_id,"service_id":self.authority.service_id,"anchor_id":self.authority.anchor_id,"signer_id":self.authority.signer_id,"key_id":self.authority.key_id,"trust_domain":self.authority.trust_domain,"checkpoint":self.authority.checkpoint()}
            if method=="POST" and path=="/v1/checkpoints/observe":
                if not self._authorized(headers):return 403,{"error":"client_authorization_required"}
                if not isinstance(body,Mapping) or not isinstance(body.get("signed_anchor_head"),Mapping):return 400,{"error":"signed_anchor_head_required"}
                now=self.clock(); result=verify_completion_immutable_anchor_head(body["signed_anchor_head"],registry=self.anchor_registry,evaluation_tick=now,checkpoint_ledger=None,max_head_age=60,**self.anchor_expectations)
                return 200,self.authority.observe_verified_head(result["head"],observed_at=now)
            if method=="POST" and path=="/v1/head/challenge":
                if not isinstance(body,Mapping):return 400,{"error":"invalid_json_object"}
                now=self.clock(); signed=self.authority.signed_response(challenge=str(body.get("challenge","")),verifier_id=str(body.get("verifier_id","")),verifier_epoch_sha256=str(body.get("verifier_epoch_sha256","")),requested_at=int(body.get("requested_at",now)),now_tick=now)
                return 200,{"signed_completion_transparency_response":signed}
            return 404,{"error":"not_found"}
        except (CompletionTransparencyError,CompletionImmutableAnchorError) as exc:
            return 409,{"error":exc.code,"detail":exc.detail}
        except Exception as exc:
            return 400,{"error":"invalid_request","detail":str(exc)}

def build_completion_transparency_http_server(host:str,port:int,app:CompletionTransparencyHTTPApplication)->HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version="TRIAXISCompletionTransparency/1"
        def _send(self,status:int,payload:Mapping[str,Any])->None:
            data=json.dumps(payload,sort_keys=True,separators=(",",":")).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(data)
        def _body(self):
            n=int(self.headers.get("Content-Length","0")); return None if n<=0 else json.loads(self.rfile.read(n).decode())
        def do_GET(self): status,payload=app.handle("GET",self.path,headers=dict(self.headers)); self._send(status,payload)
        def do_POST(self):
            try:body=self._body()
            except Exception:self._send(400,{"error":"invalid_json"});return
            status,payload=app.handle("POST",self.path,body,dict(self.headers));self._send(status,payload)
        def log_message(self,*args):return
    return HTTPServer((host,port),Handler)

__all__=["CompletionTransparencyHTTPApplication","build_completion_transparency_http_server"]
