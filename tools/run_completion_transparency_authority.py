#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,signal,threading,time
from pathlib import Path
from triaxis.completion_transparency_quorum import SQLiteCompletionTransparencyAuthority
from triaxis.completion_transparency_http import CompletionTransparencyHTTPApplication, build_completion_transparency_http_server
from triaxis.crypto_trust import TrustKeyRegistry

def req(name:str)->str:
    value=os.environ.get(name)
    if not value:raise RuntimeError(f"missing environment variable: {name}")
    return value.strip()

def main()->int:
    records=json.loads(Path(req("TRIAXIS_CTA_ANCHOR_KEYS_JSON")).read_text())
    registry=TrustKeyRegistry(records)
    authority=SQLiteCompletionTransparencyAuthority(req("TRIAXIS_CTA_DB"),authority_id=req("TRIAXIS_CTA_AUTHORITY_ID"),service_id=req("TRIAXIS_CTA_SERVICE_ID"),anchor_id=req("TRIAXIS_CTA_ANCHOR_ID"),key_id=req("TRIAXIS_CTA_KEY_ID"),signer_id=req("TRIAXIS_CTA_SIGNER_ID"),trust_domain=req("TRIAXIS_CTA_TRUST_DOMAIN"),private_key_b64=req("TRIAXIS_CTA_PRIVATE_KEY_B64"),response_ttl=int(os.environ.get("TRIAXIS_CTA_RESPONSE_TTL","30")))
    token=req("TRIAXIS_CTA_CLIENT_TOKEN")
    expectations={
      "expected_anchor_id":req("TRIAXIS_CTA_ANCHOR_ID"),
      "expected_authority_id":req("TRIAXIS_CTA_EXPECTED_ANCHOR_AUTHORITY_ID"),
      "expected_service_id":req("TRIAXIS_CTA_EXPECTED_ANCHOR_SERVICE_ID"),
      "expected_signer_id":req("TRIAXIS_CTA_EXPECTED_ANCHOR_SIGNER_ID"),
      "expected_trust_domain":req("TRIAXIS_CTA_EXPECTED_ANCHOR_TRUST_DOMAIN"),
      "expected_provider_id":req("TRIAXIS_CTA_EXPECTED_PROVIDER_ID"),
      "expected_provider_service_id":req("TRIAXIS_CTA_EXPECTED_PROVIDER_SERVICE_ID"),
      "expected_retention_policy_id":req("TRIAXIS_CTA_EXPECTED_RETENTION_POLICY_ID"),
    }
    app=CompletionTransparencyHTTPApplication(authority,clock=lambda:int(time.time()),client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),anchor_registry=registry,anchor_expectations=expectations)
    server=build_completion_transparency_http_server(os.environ.get("TRIAXIS_CTA_HOST","127.0.0.1"),int(os.environ.get("TRIAXIS_CTA_PORT","0")),app)
    def stop(*_):threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    print(json.dumps({"status":"listening","process_id":os.getpid(),"authority_id":authority.authority_id,"service_id":authority.service_id,"anchor_id":authority.anchor_id,"signer_id":authority.signer_id,"key_id":authority.key_id,"trust_domain":authority.trust_domain,"host":server.server_address[0],"port":server.server_address[1],"db":authority.path,"local_reference":True,"physical_independence":False},sort_keys=True),flush=True)
    try:server.serve_forever(poll_interval=.1)
    finally:server.server_close();authority.close()
    return 0
if __name__=="__main__":raise SystemExit(main())
