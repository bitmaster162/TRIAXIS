from __future__ import annotations

import argparse
import os
import time

from triaxis.external_execution_ledger import SQLiteExternalExecutionLedger
from triaxis.external_execution_ledger_http import ExecutionLedgerHTTPApplication, build_execution_ledger_http_server


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the TRIAXIS external execution-ledger reference service")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--db", required=True)
    p.add_argument("--ledger-id", required=True)
    p.add_argument("--authority-id", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--signer-id", required=True)
    p.add_argument("--trust-domain", required=True)
    p.add_argument("--receipt-ttl", type=int, default=30)
    p.add_argument("--private-key-env", default="TRIAXIS_EXECUTION_LEDGER_PRIVATE_KEY_B64")
    p.add_argument("--client-token-sha256-env", default="TRIAXIS_EXECUTION_LEDGER_CLIENT_TOKEN_SHA256")
    return p


def main() -> int:
    args = parser().parse_args()
    private_key = os.environ.get(args.private_key_env, "")
    client_token_sha256 = os.environ.get(args.client_token_sha256_env, "")
    if not private_key:
        raise SystemExit(f"missing environment variable {args.private_key_env}")
    if not client_token_sha256:
        raise SystemExit(f"missing environment variable {args.client_token_sha256_env}")
    ledger = SQLiteExternalExecutionLedger(
        args.db,
        ledger_id=args.ledger_id,
        authority_id=args.authority_id,
        key_id=args.key_id,
        signer_id=args.signer_id,
        trust_domain=args.trust_domain,
        private_key_b64=private_key,
        receipt_ttl=args.receipt_ttl,
    )
    app = ExecutionLedgerHTTPApplication(
        ledger,
        clock=lambda: int(time.time()),
        client_token_sha256=client_token_sha256,
    )
    server = build_execution_ledger_http_server(args.host, args.port, app)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        ledger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
