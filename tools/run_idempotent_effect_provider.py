#!/usr/bin/env python3
"""Run the TRIAXIS v3.28 reference idempotent-effect provider.

This service models provider-side idempotency and authoritative reconciliation
keyed by stable ``effect_id``. It performs no real external vendor action. The
reference server is intentionally sequential and not production-qualified.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

from triaxis.idempotent_effect_provider import SQLiteIdempotentEffectProvider
from triaxis.idempotent_effect_provider_http import (
    IdempotentEffectProviderHTTPApplication,
    build_idempotent_effect_provider_http_server,
)


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing environment variable: {name}")
    return value.strip()


def secret(env_name: str, credential_env_name: str) -> str:
    value = os.environ.get(env_name)
    if value:
        return value.strip()
    credential_name = os.environ.get(credential_env_name)
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if credential_name and credential_dir:
        path = Path(credential_dir) / credential_name
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    raise RuntimeError(
        f"configure {env_name} or {credential_env_name} with CREDENTIALS_DIRECTORY"
    )


def main() -> int:
    db_path = Path(required("TRIAXIS_IDP_DB")).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = secret(
        "TRIAXIS_IDP_PRIVATE_KEY_B64",
        "TRIAXIS_IDP_PRIVATE_KEY_CREDENTIAL_NAME",
    )
    client_token = secret(
        "TRIAXIS_IDP_CLIENT_TOKEN",
        "TRIAXIS_IDP_CLIENT_TOKEN_CREDENTIAL_NAME",
    )
    host = os.environ.get("TRIAXIS_IDP_HOST", "127.0.0.1")
    port = int(os.environ.get("TRIAXIS_IDP_PORT", "18875"))
    response_ttl = int(os.environ.get("TRIAXIS_IDP_RESPONSE_TTL", "10"))
    if not (0 <= port <= 65535):
        raise ValueError("TRIAXIS_IDP_PORT must be between 0 and 65535")

    with SQLiteIdempotentEffectProvider(
        db_path,
        provider_id=required("TRIAXIS_IDP_PROVIDER_ID"),
        service_id=required("TRIAXIS_IDP_SERVICE_ID"),
        key_id=required("TRIAXIS_IDP_KEY_ID"),
        signer_id=required("TRIAXIS_IDP_SIGNER_ID"),
        trust_domain=required("TRIAXIS_IDP_TRUST_DOMAIN"),
        private_key_b64=private_key,
        response_ttl=response_ttl,
    ) as provider:
        app = IdempotentEffectProviderHTTPApplication(
            provider,
            clock=lambda: int(time.time()),
            client_token_sha256=hashlib.sha256(client_token.encode("utf-8")).hexdigest(),
            response_ttl=response_ttl,
        )
        server = build_idempotent_effect_provider_http_server(host, port, app)

        def stop(*_: object) -> None:
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print(
            json.dumps(
                {
                    "status": "listening",
                    "process_id": os.getpid(),
                    "provider_id": provider.provider_id,
                    "service_id": provider.service_id,
                    "signer_id": provider.signer_id,
                    "key_id": provider.key_id,
                    "trust_domain": provider.trust_domain,
                    "host": server.server_address[0],
                    "port": server.server_address[1],
                    "db_path": str(db_path),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        try:
            server.serve_forever(poll_interval=0.1)
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            json.dumps(
                {"status": "failed", "error": type(exc).__name__, "detail": str(exc)},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise
