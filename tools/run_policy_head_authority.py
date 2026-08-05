#!/usr/bin/env python3
"""Run the TRIAXIS Policy Head Authority reference HTTP service.

Required environment variables:
  TRIAXIS_PHA_POLICY_DB
  TRIAXIS_PHA_RESPONSE_DB
  TRIAXIS_PHA_POLICY_ROOT_KEYS_JSON   (JSON array of public trust-key records)
  TRIAXIS_PHA_POLICY_ID
  TRIAXIS_PHA_POLICY_ROOT_SIGNER_ID
  TRIAXIS_PHA_POLICY_ROOT_TRUST_DOMAIN
  TRIAXIS_PHA_AUTHORITY_ID
  TRIAXIS_PHA_KEY_ID
  TRIAXIS_PHA_SIGNER_ID
  TRIAXIS_PHA_TRUST_DOMAIN
  TRIAXIS_PHA_PRIVATE_KEY_B64

Optional:
  TRIAXIS_PHA_HOST=127.0.0.1
  TRIAXIS_PHA_PORT=8787
  TRIAXIS_PHA_RESPONSE_TTL=10
  TRIAXIS_PHA_ADMIN_TOKEN (enables policy installation endpoint)
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time

from triaxis.anchor_quorum_policy import SQLiteAnchorQuorumPolicyStore
from triaxis.crypto_trust import TrustKeyRegistry
from triaxis.policy_head_authority import SQLitePolicyHeadAuthorityService
from triaxis.policy_head_http import PolicyHeadHTTPApplication, build_http_server


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing environment variable: {name}")
    return value


def main() -> None:
    records = json.loads(Path(required("TRIAXIS_PHA_POLICY_ROOT_KEYS_JSON")).read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise SystemExit("policy root keys JSON must be an array")
    root_registry = TrustKeyRegistry(records)
    policy_store = SQLiteAnchorQuorumPolicyStore(
        required("TRIAXIS_PHA_POLICY_DB"),
        policy_root_registry=root_registry,
        policy_id=required("TRIAXIS_PHA_POLICY_ID"),
        policy_root_signer_id=required("TRIAXIS_PHA_POLICY_ROOT_SIGNER_ID"),
        policy_root_trust_domain=required("TRIAXIS_PHA_POLICY_ROOT_TRUST_DOMAIN"),
    )
    service = SQLitePolicyHeadAuthorityService(
        required("TRIAXIS_PHA_RESPONSE_DB"),
        policy_store=policy_store,
        authority_id=required("TRIAXIS_PHA_AUTHORITY_ID"),
        key_id=required("TRIAXIS_PHA_KEY_ID"),
        signer_id=required("TRIAXIS_PHA_SIGNER_ID"),
        trust_domain=required("TRIAXIS_PHA_TRUST_DOMAIN"),
        private_key_b64=required("TRIAXIS_PHA_PRIVATE_KEY_B64"),
    )
    admin = os.environ.get("TRIAXIS_PHA_ADMIN_TOKEN")
    app = PolicyHeadHTTPApplication(
        service,
        clock=lambda: int(time.time()),
        response_ttl=int(os.environ.get("TRIAXIS_PHA_RESPONSE_TTL", "10")),
        admin_token_sha256=hashlib.sha256(admin.encode("utf-8")).hexdigest() if admin else None,
    )
    server = build_http_server(
        os.environ.get("TRIAXIS_PHA_HOST", "127.0.0.1"),
        int(os.environ.get("TRIAXIS_PHA_PORT", "8787")),
        app,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
        service.close()
        policy_store.close()


if __name__ == "__main__":
    main()
