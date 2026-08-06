#!/usr/bin/env python3
"""Run the TRIAXIS v3.29 external completion witness reference service."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

from triaxis.crypto_trust import TrustKeyRegistry
from triaxis.external_completion_witness import SQLiteExternalCompletionWitness
from triaxis.external_completion_witness_http import (
    ExternalCompletionWitnessHTTPApplication,
    build_external_completion_witness_http_server,
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
        value = (Path(credential_dir) / credential_name).read_text(encoding="utf-8").strip()
        if value:
            return value
    raise RuntimeError(
        f"configure {env_name} or {credential_env_name} with CREDENTIALS_DIRECTORY"
    )


def main() -> int:
    records_path = Path(required("TRIAXIS_ECW_PROVIDER_KEYS_JSON")).resolve()
    records = json.loads(records_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("provider keys JSON must be an array")
    provider_registry = TrustKeyRegistry(records)

    db_path = Path(required("TRIAXIS_ECW_DB")).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = secret(
        "TRIAXIS_ECW_PRIVATE_KEY_B64",
        "TRIAXIS_ECW_PRIVATE_KEY_CREDENTIAL_NAME",
    )
    client_token = secret(
        "TRIAXIS_ECW_CLIENT_TOKEN",
        "TRIAXIS_ECW_CLIENT_TOKEN_CREDENTIAL_NAME",
    )
    host = os.environ.get("TRIAXIS_ECW_HOST", "127.0.0.1")
    port = int(os.environ.get("TRIAXIS_ECW_PORT", "18876"))
    response_ttl = int(os.environ.get("TRIAXIS_ECW_RESPONSE_TTL", "10"))
    max_provider_receipt_age = int(os.environ.get("TRIAXIS_ECW_MAX_PROVIDER_RECEIPT_AGE", "30"))
    if not (0 <= port <= 65535):
        raise ValueError("TRIAXIS_ECW_PORT must be between 0 and 65535")

    with SQLiteExternalCompletionWitness(
        db_path,
        witness_id=required("TRIAXIS_ECW_WITNESS_ID"),
        authority_id=required("TRIAXIS_ECW_AUTHORITY_ID"),
        service_id=required("TRIAXIS_ECW_SERVICE_ID"),
        key_id=required("TRIAXIS_ECW_KEY_ID"),
        signer_id=required("TRIAXIS_ECW_SIGNER_ID"),
        trust_domain=required("TRIAXIS_ECW_TRUST_DOMAIN"),
        private_key_b64=private_key,
        receipt_ttl=response_ttl,
    ) as witness:
        app = ExternalCompletionWitnessHTTPApplication(
            witness,
            clock=lambda: int(time.time()),
            client_token_sha256=hashlib.sha256(client_token.encode("utf-8")).hexdigest(),
            provider_registry=provider_registry,
            expected_provider_signer_id=required("TRIAXIS_ECW_EXPECTED_PROVIDER_SIGNER_ID"),
            expected_provider_trust_domain=required("TRIAXIS_ECW_EXPECTED_PROVIDER_TRUST_DOMAIN"),
            response_ttl=response_ttl,
            max_provider_receipt_age=max_provider_receipt_age,
        )
        server = build_external_completion_witness_http_server(host, port, app)

        def stop(*_: object) -> None:
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print(
            json.dumps(
                {
                    "status": "listening",
                    "process_id": os.getpid(),
                    "witness_id": witness.witness_id,
                    "authority_id": witness.authority_id,
                    "service_id": witness.service_id,
                    "signer_id": witness.signer_id,
                    "key_id": witness.key_id,
                    "trust_domain": witness.trust_domain,
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
