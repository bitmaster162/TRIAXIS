"""PI-002 trust-boundary regression tests."""

from __future__ import annotations

import os
import socket
import sqlite3
import threading
from types import SimpleNamespace

from triaxis.identity import (
    SpiffeAgentMapping,
    SpiffeWorkloadIdentityProvider,
    TrustedWorkloadIdentityProviderRegistry,
)
from triaxis.identity.spiffe_provider import NativeSpiffeWorkloadApiClient


def test_regular_file_cannot_impersonate_workload_api(tmp_path):
    endpoint = tmp_path / "agent.sock"
    endpoint.write_text(
        '{"svids":[{"x509_svid":"fake","bundle":"fake"}]}',
        encoding="utf-8",
    )

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
                    connection, _ = server.accept()
                except TimeoutError:
                    return
                with connection:
                    try:
                        connection.recv(65536)
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


def test_transport_is_delegated_to_spiffe_sdk_shaped_client(tmp_path):
    socket_path = tmp_path / "agent.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)

    trust_domain = object()
    cert_sentinel = object()
    authority_sentinel = object()

    class FakeSpiffeId:
        def __init__(self) -> None:
            self.trust_domain = trust_domain

        def __str__(self) -> str:
            return "spiffe://triaxis.local/agent/operator-001"

    fake_svid = SimpleNamespace(
        spiffe_id=FakeSpiffeId(),
        cert_chain=[cert_sentinel],
    )

    class FakeBundleSet:
        def get_bundle_for_trust_domain(self, value):
            assert value is trust_domain
            return SimpleNamespace(x509_authorities={authority_sentinel})

    fake_context = SimpleNamespace(
        default_svid=fake_svid,
        x509_bundle_set=FakeBundleSet(),
    )

    calls = {}

    class FakeClient:
        def __init__(self, *, socket_path, default_timeout):
            calls["socket_path"] = socket_path
            calls["default_timeout"] = default_timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return None

        def fetch_x509_context(self, *, timeout):
            calls["fetch_timeout"] = timeout
            return fake_context

    try:
        client = NativeSpiffeWorkloadApiClient(
            str(socket_path),
            timeout_seconds=0.25,
            client_factory=FakeClient,
        )
        payload, status = client.fetch_x509_svid()
    finally:
        server.close()

    assert status == "OK"
    assert calls == {
        "socket_path": f"unix:{socket_path}",
        "default_timeout": 0.25,
        "fetch_timeout": 0.25,
    }
    assert payload["spiffe_id"] == "spiffe://triaxis.local/agent/operator-001"
    assert payload["svid_chain"] == [cert_sentinel]
    assert payload["bundle_authorities"] == [authority_sentinel]


def test_sdk_permission_denied_maps_to_attestation_mismatch(tmp_path):
    socket_path = tmp_path / "agent.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)

    class DeniedClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return None

        def fetch_x509_context(self, *, timeout):
            raise RuntimeError("gRPC StatusCode.PERMISSION_DENIED")

    try:
        client = NativeSpiffeWorkloadApiClient(
            str(socket_path),
            timeout_seconds=0.2,
            client_factory=DeniedClient,
        )
        payload, status = client.fetch_x509_svid()
    finally:
        server.close()

    assert payload is None
    assert status == "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH"


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
