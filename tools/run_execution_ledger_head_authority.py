#!/usr/bin/env python3
"""Run the TRIAXIS v3.28 external execution-ledger head authority.

The service keeps monotonic ledger-head memory outside the execution-ledger
SQLite file. Public ledger trust records are loaded from JSON. Private signing
material and the administrative token must come from environment variables or
systemd credentials. This standard-library server is a reference boundary, not
an Internet-facing production service.
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

from triaxis.crypto_trust import TrustKeyRegistry
from triaxis.execution_ledger_head_authority import SQLiteExecutionLedgerHeadAuthority
from triaxis.execution_ledger_head_http import (
    ExecutionLedgerHeadHTTPApplication,
    build_execution_ledger_head_http_server,
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
    records_path = Path(required("TRIAXIS_ELH_LEDGER_KEYS_JSON")).resolve()
    records = json.loads(records_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("ledger keys JSON must be an array")
    registry = TrustKeyRegistry(records)

    db_path = Path(required("TRIAXIS_ELH_DB")).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = secret(
        "TRIAXIS_ELH_PRIVATE_KEY_B64",
        "TRIAXIS_ELH_PRIVATE_KEY_CREDENTIAL_NAME",
    )
    admin_token = secret(
        "TRIAXIS_ELH_ADMIN_TOKEN",
        "TRIAXIS_ELH_ADMIN_TOKEN_CREDENTIAL_NAME",
    )
    host = os.environ.get("TRIAXIS_ELH_HOST", "127.0.0.1")
    port = int(os.environ.get("TRIAXIS_ELH_PORT", "18874"))
    response_ttl = int(os.environ.get("TRIAXIS_ELH_RESPONSE_TTL", "10"))
    if not (0 <= port <= 65535):
        raise ValueError("TRIAXIS_ELH_PORT must be between 0 and 65535")

    with SQLiteExecutionLedgerHeadAuthority(
        db_path,
        authority_id=required("TRIAXIS_ELH_AUTHORITY_ID"),
        service_id=required("TRIAXIS_ELH_SERVICE_ID"),
        ledger_registry=registry,
        expected_ledger_signer_id=required("TRIAXIS_ELH_EXPECTED_LEDGER_SIGNER_ID"),
        expected_ledger_trust_domain=required("TRIAXIS_ELH_EXPECTED_LEDGER_TRUST_DOMAIN"),
        key_id=required("TRIAXIS_ELH_KEY_ID"),
        signer_id=required("TRIAXIS_ELH_SIGNER_ID"),
        trust_domain=required("TRIAXIS_ELH_TRUST_DOMAIN"),
        private_key_b64=private_key,
        response_ttl=response_ttl,
    ) as authority:
        app = ExecutionLedgerHeadHTTPApplication(
            authority,
            clock=lambda: int(time.time()),
            admin_token_sha256=hashlib.sha256(admin_token.encode("utf-8")).hexdigest(),
            response_ttl=response_ttl,
        )
        server = build_execution_ledger_head_http_server(host, port, app)

        def stop(*_: object) -> None:
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        print(
            json.dumps(
                {
                    "status": "listening",
                    "process_id": os.getpid(),
                    "authority_id": authority.authority_id,
                    "service_id": authority.service_id,
                    "signer_id": authority.signer_id,
                    "key_id": authority.key_id,
                    "trust_domain": authority.trust_domain,
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
