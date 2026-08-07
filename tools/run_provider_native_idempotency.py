#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,os,signal,threading,time
from pathlib import Path
from triaxis.provider_native_idempotency import FilesystemProviderNativeIdempotencyReference, make_provider_native_policy
from triaxis.provider_native_idempotency_http import ProviderNativeIdempotencyHTTPApplication, build_provider_native_idempotency_http_server

def req(name:str)->str:
    value=os.environ.get(name)
    if not value: raise RuntimeError(f"missing environment variable: {name}")
    return value.strip()

def main()->int:
    root=Path(req("TRIAXIS_PNI_ROOT")).resolve(); root.mkdir(parents=True,exist_ok=True)
    token=req("TRIAXIS_PNI_CLIENT_TOKEN")
    provider=FilesystemProviderNativeIdempotencyReference(root,provider_id=req("TRIAXIS_PNI_PROVIDER_ID"),service_id=req("TRIAXIS_PNI_SERVICE_ID"),namespace_id=req("TRIAXIS_PNI_NAMESPACE_ID"),key_id=req("TRIAXIS_PNI_KEY_ID"),signer_id=req("TRIAXIS_PNI_SIGNER_ID"),trust_domain=req("TRIAXIS_PNI_TRUST_DOMAIN"),private_key_b64=req("TRIAXIS_PNI_PRIVATE_KEY_B64"),response_ttl=int(os.environ.get("TRIAXIS_PNI_RESPONSE_TTL","30")))
    now=int(time.time())
    policy=make_provider_native_policy(policy_id=req("TRIAXIS_PNI_POLICY_ID"),provider_id=provider.provider_id,service_id=provider.service_id,namespace_id=provider.namespace_id,valid_from=int(os.environ.get("TRIAXIS_PNI_POLICY_VALID_FROM","0")),valid_until=int(os.environ.get("TRIAXIS_PNI_POLICY_VALID_UNTIL",str(now+86400))))
    app=ProviderNativeIdempotencyHTTPApplication(provider,clock=lambda:int(time.time()),client_token_sha256=hashlib.sha256(token.encode()).hexdigest(),policy=policy)
    server=build_provider_native_idempotency_http_server(os.environ.get("TRIAXIS_PNI_HOST","127.0.0.1"),int(os.environ.get("TRIAXIS_PNI_PORT","0")),app)
    def stop(*_):threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    print(json.dumps({"status":"listening","process_id":os.getpid(),"provider_id":provider.provider_id,"service_id":provider.service_id,"namespace_id":provider.namespace_id,"signer_id":provider.signer_id,"key_id":provider.key_id,"trust_domain":provider.trust_domain,"host":server.server_address[0],"port":server.server_address[1],"root":str(root),"local_reference":True,"real_provider_integration":False},sort_keys=True),flush=True)
    try:server.serve_forever(poll_interval=.1)
    finally:server.server_close()
    return 0
if __name__=="__main__":raise SystemExit(main())
