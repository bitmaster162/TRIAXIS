"""PI-002 trust-boundary regression tests."""

from __future__ import annotations

import os
import socket
import sqlite3
import threading

from triaxis.identity import (
    SpiffeAgentMapping,
    SpiffeWorkloadIdentityProvider,
    TrustedWorkloadIdentityProviderRegistry,
)
from triaxis.identity.spiffe_provider import NativeSpiffeWorkloadApiClient


def test_regular_file_cannot_impersonate_workload_api(tmp_path):
    endpoint = tmp_path / "agent.sock"
    endpoint.write_text('{"svids":[{"x509_svid":"fake","bundle":"fake"}]}', encoding="utf-8")

    client = NativeSpiffeWorkloadApiClient(str(endpoint), timeout_seconds=0.2)
    payload, status = client.fetch_x509_svid()

    assert payload is None
    assert status == "INVALID_WORKLOAD_API_ENDPOINT"


def test_adjacent_spire_sqlite_cannot_mint_synthetic_svid(tmp_path):
    """Old fallback read datastore.sq3 and minted its own CA/leaf after a socket failure."""
    socket_path = tmp_path / "agent.sock"
    datastore_dir = tmp_path / "data" / "server"
    datastore_dir.mkdir(parents=True)
    datastore_path = datastore_dir / "datastore.sq3"

    with sqlite3.connect(datastore_path) as conn:
        conn.execute("CREATE TABLE registered_entries (id TEXT PRIMARY KEY, spiffe_id TEXT)")
        conn.execute(
            "CREATE TABLE selectors (registered_entry_id TEXT, type TEXT, value TEXT)"
        )
        conn.execute(
            "INSERT INTO registered_entries (id, spiffe_id) VALUES (?, ?)",
            ("entry-1", "spiffe://triaxis.local/agent/forged"),
        )
        uid = str(os.getuid()) if hasattr(os, "getuid") else "1000"
        conn.execute(
            "INSERT INTO selectors (registered_entry_id, type, value) VALUES (?, ?, ?)",
            ("entry-1", "unix", f"uid:{uid}"),
        )

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(2)
    server.settimeout(1.0)

    def accept_and_drop() -> None:
        try:
            for _ in range(2):
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    return
                with conn:
                    try:
                        conn.recv(65536)
                    except OSError:
                        pass
        finally:
            server.close()

    thread = threading.Thread(target=accept_and_drop, daemon=True)
    thread.start()

    client = NativeSpiffeWorkloadApiClient(str(socket_path), timeout_seconds=0.2)
    payload, status = client.fetch_x509_svid()
    thread.join(timeout=2)

    assert payload is None
    assert status != "OK"


def test_registry_rejects_runtime_socket_drift():
    mapping = SpiffeAgentMapping(
        {"spiffe://triaxis.local/agent/operator-001": "agent_inst_001"}
    )
    provider = SpiffeWorkloadIdentityProvider(
        expected_trust_domain="triaxis.local",
        mapping=mapping,
        socket_path="/tmp/triaxis-a.sock",
    )
    registry = TrustedWorkloadIdentityProviderRegistry()
    registry.register_provider("spiffe_spire_local", provider)

    assert registry.is_provider_trusted("spiffe_spire_local", provider)

    provider.socket_path = "/tmp/triaxis-b.sock"
    assert not registry.is_provider_trusted("spiffe_spire_local", provider)


def test_registry_rejects_explicit_config_mismatch():
    mapping = SpiffeAgentMapping(
        {"spiffe://triaxis.local/agent/operator-001": "agent_inst_001"}
    )
    provider = SpiffeWorkloadIdentityProvider(
        expected_trust_domain="triaxis.local",
        mapping=mapping,
        socket_path="/tmp/triaxis-a.sock",
    )
    registry = TrustedWorkloadIdentityProviderRegistry()

    try:
        registry.register_provider(
            "spiffe_spire_local",
            provider,
            socket_path="/tmp/other.sock",
        )
    except ValueError as exc:
        assert "socket path" in str(exc)
    else:
        raise AssertionError("registry accepted mismatched provider socket path")
