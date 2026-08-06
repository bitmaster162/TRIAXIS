#!/usr/bin/env python3
"""Run one TRIAXIS Gossip Head Authority HTTP process.

The configuration file contains public identity and paths only. The authority
private key and administrative bearer token are read from environment variables
named by the configuration. Do not use this reference server as an Internet
edge without mTLS, rate limiting, KMS/HSM-backed signing, and an independently
administered deployment boundary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import threading
import time

from triaxis.crypto_trust import TrustKeyRegistry
from triaxis.policy_transparency_gossip_head import SQLiteGossipHeadAuthority
from triaxis.policy_transparency_gossip_head_http import (
    GossipHeadHTTPApplication,
    build_gossip_head_http_server,
)


def _required(config: dict, field: str) -> str:
    value = config.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict):
        raise ValueError("configuration must be a JSON object")

    registry_path = Path(_required(config, "checkpoint_registry_path"))
    if not registry_path.is_absolute():
        registry_path = (config_path.parent / registry_path).resolve()
    records = json.loads(registry_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("checkpoint registry must be a JSON array")
    registry = TrustKeyRegistry(records)

    def load_secret(env_field: str, credential_field: str) -> str:
        env_name = config.get(env_field)
        credential_name = config.get(credential_field)
        if isinstance(env_name, str) and env_name:
            value = os.environ.get(env_name)
            if not value:
                raise RuntimeError(f"missing secret environment variable: {env_name}")
            return value.strip()
        if isinstance(credential_name, str) and credential_name:
            credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
            if not credential_dir:
                raise RuntimeError("CREDENTIALS_DIRECTORY is required for credential-backed secrets")
            path = Path(credential_dir) / credential_name
            value = path.read_text(encoding="utf-8").strip()
            if not value:
                raise RuntimeError(f"empty credential: {credential_name}")
            return value
        raise ValueError(f"configure exactly one of {env_field} or {credential_field}")

    private_key = load_secret("private_key_env", "private_key_credential_name")
    admin_token = load_secret("admin_token_env", "admin_token_credential_name")

    host = str(config.get("host", "127.0.0.1"))
    port = config.get("port", 0)
    response_ttl = config.get("response_ttl", 15)
    if type(port) is not int or not (0 <= port <= 65535):
        raise ValueError("port must be an integer from 0 to 65535")

    db_path = Path(_required(config, "db_path"))
    if not db_path.is_absolute():
        db_path = (config_path.parent / db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with SQLiteGossipHeadAuthority(
        db_path,
        authority_id=_required(config, "authority_id"),
        service_id=_required(config, "service_id"),
        checkpoint_registry=registry,
        expected_checkpoint_signer_id=_required(config, "expected_checkpoint_signer_id"),
        expected_checkpoint_trust_domain=_required(config, "expected_checkpoint_trust_domain"),
        key_id=_required(config, "key_id"),
        signer_id=_required(config, "signer_id"),
        trust_domain=_required(config, "trust_domain"),
        private_key_b64=private_key,
    ) as authority:
        app = GossipHeadHTTPApplication(
            authority,
            clock=lambda: int(time.time()),
            response_ttl=response_ttl,
            admin_token_sha256=hashlib.sha256(admin_token.encode("utf-8")).hexdigest(),
        )
        server = build_gossip_head_http_server(host, port, app)

        def stop(*_: object) -> None:
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        startup = {
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
        }
        print(json.dumps(startup, sort_keys=True), flush=True)
        try:
            server.serve_forever(poll_interval=0.1)
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "failed", "error": type(exc).__name__, "detail": str(exc)}), file=sys.stderr)
        raise
