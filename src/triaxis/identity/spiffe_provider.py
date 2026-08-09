"""TRIAXIS PI-002 SPIFFE/SPIRE workload identity provider.

Production identity acquisition is delegated to the py-spiffe Workload API
client. TRIAXIS owns only local endpoint confinement, identity correlation,
certificate/profile checks, mapping, and authorization-boundary semantics.
It never reads SPIRE datastores and never synthesizes SVIDs or trust roots.
"""

from __future__ import annotations

import base64
from datetime import datetime as dt, timezone
import hashlib
import os
import stat
from typing import Any, Callable
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto

from .contract import VerifiedWorkloadIdentity
from .mapping import SpiffeAgentMapping


class NativeSpiffeWorkloadApiClient:
    """Compatibility wrapper around the py-spiffe WorkloadApiClient.

    The historical class name is retained to avoid breaking callers. No custom
    HTTP/2, gRPC, protobuf, SPIRE datastore, or synthetic-PKI implementation
    exists in this class.
    """

    def __init__(
        self,
        socket_path: str,
        timeout_seconds: float = 5.0,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self._client_factory = client_factory

    def fetch_x509_svid(self) -> tuple[dict[str, Any] | None, str]:
        """Fetch an X509 context exclusively through the configured Workload API UDS."""
        try:
            endpoint_uri, filesystem_path = self._normalize_unix_endpoint(self.socket_path)
        except ValueError:
            return None, "INVALID_WORKLOAD_API_ENDPOINT"

        try:
            endpoint_stat = os.stat(filesystem_path)
        except FileNotFoundError:
            return None, "SPIRE_AGENT_UNAVAILABLE"
        except OSError:
            return None, "SPIRE_WORKLOAD_API_ERROR"

        if not stat.S_ISSOCK(endpoint_stat.st_mode):
            return None, "INVALID_WORKLOAD_API_ENDPOINT"

        client_factory = self._client_factory
        if client_factory is None:
            try:
                from spiffe import WorkloadApiClient
            except ImportError:
                return None, "SPIFFE_SDK_UNAVAILABLE"
            client_factory = WorkloadApiClient

        try:
            with client_factory(
                socket_path=endpoint_uri,
                default_timeout=self.timeout_seconds,
            ) as client:
                context = client.fetch_x509_context(timeout=self.timeout_seconds)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}".upper()
            if "PERMISSION_DENIED" in message or "PERMISSIONDENIED" in message:
                return None, "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH"
            return None, "SPIRE_WORKLOAD_API_ERROR"

        try:
            svid = context.default_svid
            cert_chain = list(svid.cert_chain)
            spiffe_id = str(svid.spiffe_id)
            trust_domain = svid.spiffe_id.trust_domain
            bundle = context.x509_bundle_set.get_bundle_for_trust_domain(trust_domain)
            if bundle is None:
                return None, "TRUST_BUNDLE_UNAVAILABLE"
            authorities = list(bundle.x509_authorities)
        except Exception:
            return None, "SPIFFE_CONTEXT_INVALID"

        if not cert_chain:
            return None, "NO_SVID_ISSUED"
        if not authorities:
            return None, "TRUST_BUNDLE_UNAVAILABLE"

        return {
            "spiffe_id": spiffe_id,
            "svid_chain": cert_chain,
            "bundle_authorities": authorities,
        }, "OK"

    @staticmethod
    def _normalize_unix_endpoint(socket_path: str) -> tuple[str, str]:
        """Return (py-spiffe endpoint URI, local filesystem path)."""
        if not isinstance(socket_path, str) or not socket_path:
            raise ValueError("empty socket path")

        if socket_path.startswith("/"):
            return f"unix:{socket_path}", socket_path

        parsed = urlparse(socket_path)
        if parsed.scheme != "unix" or parsed.netloc or not parsed.path:
            raise ValueError("endpoint must be an absolute unix-domain socket")
        if not parsed.path.startswith("/"):
            raise ValueError("endpoint path must be absolute")
        if parsed.params or parsed.query or parsed.fragment:
            raise ValueError("endpoint contains unsupported components")

        return f"unix:{parsed.path}", parsed.path


class SpiffeWorkloadIdentityProvider:
    """SPIFFE Workload API adapter with TRIAXIS identity/profile enforcement."""

    def __init__(
        self,
        expected_trust_domain: str = "triaxis.local",
        mapping: SpiffeAgentMapping | None = None,
        socket_path: str | None = None,
        spire_agent_binary: str = "/home/bit/.local/bin/spire-agent",
        timeout_seconds: float = 5.0,
    ) -> None:
        self.expected_trust_domain = expected_trust_domain
        self.mapping = mapping or SpiffeAgentMapping({})
        self.socket_path = socket_path or os.environ.get(
            "SPIFFE_ENDPOINT_SOCKET",
            "/tmp/spire-agent/public/api.sock",
        )
        # Retained for constructor/API compatibility only. Runtime subprocess use is forbidden.
        self.spire_agent_binary = spire_agent_binary
        self.timeout_seconds = timeout_seconds
        self.client = NativeSpiffeWorkloadApiClient(self.socket_path, timeout_seconds)

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        now = dt.now(timezone.utc)
        now_iso = now.isoformat()
        empty_fingerprint = "0" * 64
        mapping_hash = self.mapping.identity_mapping_sha256

        svid_data, status = self.client.fetch_x509_svid()
        if status != "OK" or svid_data is None:
            denied_statuses = {
                "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH",
                "NO_SVID_ISSUED",
                "TRUST_BUNDLE_UNAVAILABLE",
                "INVALID_WORKLOAD_API_ENDPOINT",
                "SPIFFE_CONTEXT_INVALID",
            }
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=empty_fingerprint,
                status="DENIED" if status in denied_statuses else "ERROR",
                reason=status,
            )

        workload_api_spiffe_id: str | None = None
        try:
            if "svid_chain" in svid_data or "bundle_authorities" in svid_data:
                svid_chain = list(svid_data.get("svid_chain") or [])
                trust_bundle = list(svid_data.get("bundle_authorities") or [])
                workload_api_spiffe_id = str(svid_data.get("spiffe_id") or "")
            else:
                # Compatibility path for existing test doubles only. The production
                # Workload API adapter above never emits raw file/JSON payloads.
                svid_raw = svid_data.get("x509_svid", "")
                bundle_raw = svid_data.get("bundle", "")
                if not svid_raw:
                    return self._identity_result(
                        request_id=request_id,
                        mapping_hash=mapping_hash,
                        now_iso=now_iso,
                        fingerprint=empty_fingerprint,
                        status="DENIED",
                        reason="NO_SVID_ISSUED",
                    )
                if not bundle_raw:
                    return self._identity_result(
                        request_id=request_id,
                        mapping_hash=mapping_hash,
                        now_iso=now_iso,
                        fingerprint=empty_fingerprint,
                        status="DENIED",
                        reason="TRUST_BUNDLE_UNAVAILABLE",
                    )
                svid_chain = self._parse_x509_chain(svid_raw)
                trust_bundle = self._parse_x509_chain(bundle_raw)

            if not svid_chain:
                raise ValueError("empty SVID chain")
            if not trust_bundle:
                raise ValueError("empty trust bundle")
            if not all(isinstance(cert, x509.Certificate) for cert in svid_chain):
                raise TypeError("invalid SVID certificate object")
            if not all(isinstance(cert, x509.Certificate) for cert in trust_bundle):
                raise TypeError("invalid trust bundle certificate object")
            svid_cert = svid_chain[0]
        except Exception as exc:
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=empty_fingerprint,
                status="DENIED",
                reason=f"SVID_PARSE_ERROR: {type(exc).__name__}",
            )

        cert_fp = hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest()

        leaf_error = self._validate_leaf_profile(svid_cert)
        if leaf_error is not None:
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason=leaf_error,
            )

        spiffe_id = self._extract_spiffe_id(svid_cert)
        if spiffe_id is None:
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason="MISSING_SPIFFE_ID_IN_SVID",
            )
        if spiffe_id == "AMBIGUOUS":
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason="SVID_SPIFFE_ID_AMBIGUOUS",
            )

        if workload_api_spiffe_id and workload_api_spiffe_id != spiffe_id:
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason="WORKLOAD_API_SPIFFE_ID_MISMATCH",
                spiffe_id=spiffe_id,
            )

        remainder = spiffe_id[len("spiffe://") :]
        parts = remainder.split("/", 1)
        if len(parts) != 2 or not parts[1].strip("/"):
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason="SVID_LEAF_CONSTRAINTS_VIOLATED",
                spiffe_id=spiffe_id,
                trust_domain=parts[0] if parts else "",
            )

        trust_domain = parts[0]
        if trust_domain != self.expected_trust_domain:
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason="TRUST_DOMAIN_MISMATCH",
                spiffe_id=spiffe_id,
                trust_domain=trust_domain,
            )

        not_before, not_after = self._validity_window(svid_cert)
        if now < not_before or now > not_after:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=cert_fp,
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="CERTIFICATE_EXPIRED",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        if not self._verify_path(svid_chain, trust_bundle):
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=cert_fp,
                status="DENIED",
                reason="SVID_CHAIN_INVALID",
            )

        mapped_agent = self.mapping.resolve_agent_instance_id(spiffe_id)
        if not mapped_agent:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=cert_fp,
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="IDENTITY_MAPPING_NOT_FOUND",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        return VerifiedWorkloadIdentity(
            agent_instance_id=mapped_agent,
            spiffe_id=spiffe_id,
            trust_domain=trust_domain,
            identity_provider="SPIFFE-SPIRE-WorkloadAPI",
            certificate_fingerprint_sha256=cert_fp,
            not_before_iso=not_before.isoformat(),
            not_after_iso=not_after.isoformat(),
            verification_status="VERIFIED",
            verification_reason="SPIFFE_SVID_VERIFIED",
            identity_mapping_sha256=mapping_hash,
            request_id=request_id,
        )

    @staticmethod
    def _validity_window(cert: x509.Certificate) -> tuple[dt, dt]:
        if hasattr(cert, "not_valid_before_utc"):
            return cert.not_valid_before_utc, cert.not_valid_after_utc
        return (
            cert.not_valid_before.replace(tzinfo=timezone.utc),
            cert.not_valid_after.replace(tzinfo=timezone.utc),
        )

    @staticmethod
    def _validate_leaf_profile(cert: x509.Certificate) -> str | None:
        try:
            basic = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.BASIC_CONSTRAINTS
            ).value
        except x509.ExtensionNotFound:
            return "SVID_LEAF_CONSTRAINTS_VIOLATED"
        if basic.ca:
            return "SVID_LEAF_CONSTRAINTS_VIOLATED"

        try:
            key_usage_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
        except x509.ExtensionNotFound:
            return "SVID_KEY_USAGE_MISSING"

        if not key_usage_ext.critical:
            return "SVID_KEY_USAGE_NOT_CRITICAL"

        key_usage = key_usage_ext.value
        if not key_usage.digital_signature or key_usage.key_cert_sign or key_usage.crl_sign:
            return "SVID_LEAF_CONSTRAINTS_VIOLATED"

        try:
            eku = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            if (
                x509.ExtendedKeyUsageOID.CLIENT_AUTH not in eku
                or x509.ExtendedKeyUsageOID.SERVER_AUTH not in eku
            ):
                return "SVID_LEAF_CONSTRAINTS_VIOLATED"
        except x509.ExtensionNotFound:
            pass

        return None

    @staticmethod
    def _extract_spiffe_id(cert: x509.Certificate) -> str | None:
        try:
            sans = cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value.get_values_for_type(x509.UniformResourceIdentifier)
        except x509.ExtensionNotFound:
            return None
        if not sans:
            return None
        if len(sans) != 1:
            return "AMBIGUOUS"
        if not sans[0].startswith("spiffe://"):
            return None
        return sans[0]

    @staticmethod
    def _verify_path(
        svid_chain: list[x509.Certificate],
        trust_bundle: list[x509.Certificate],
    ) -> bool:
        try:
            store = crypto.X509Store()
            for cert in trust_bundle:
                store.add_cert(crypto.X509.from_cryptography(cert))
            leaf = crypto.X509.from_cryptography(svid_chain[0])
            intermediates = [
                crypto.X509.from_cryptography(cert) for cert in svid_chain[1:]
            ]
            crypto.X509StoreContext(store, leaf, intermediates).verify_certificate()
            return True
        except Exception:
            return False

    @classmethod
    def _parse_x509_chain(cls, data_str: str) -> list[x509.Certificate]:
        raw = (
            data_str.encode("utf-8")
            if data_str.startswith("-----BEGIN")
            else base64.b64decode(data_str)
        )
        if b"-----BEGIN CERTIFICATE-----" in raw:
            return list(x509.load_pem_x509_certificates(raw))
        return [
            x509.load_der_x509_certificate(cert_der, default_backend())
            for cert_der in cls._split_der_certificates(raw)
        ]

    @staticmethod
    def _split_der_certificates(raw: bytes) -> list[bytes]:
        certs: list[bytes] = []
        pos = 0
        while pos < len(raw):
            if raw[pos] != 0x30 or pos + 2 > len(raw):
                raise ValueError("invalid DER certificate sequence")
            length_octet = raw[pos + 1]
            if length_octet < 0x80:
                header_len = 2
                content_len = length_octet
            else:
                length_len = length_octet & 0x7F
                if (
                    length_len == 0
                    or length_len > 4
                    or pos + 2 + length_len > len(raw)
                ):
                    raise ValueError("invalid DER length")
                header_len = 2 + length_len
                content_len = int.from_bytes(
                    raw[pos + 2 : pos + 2 + length_len],
                    "big",
                )
            end = pos + header_len + content_len
            if end > len(raw):
                raise ValueError("truncated DER certificate")
            certs.append(raw[pos:end])
            pos = end
        return certs

    def _identity_result(
        self,
        *,
        request_id: str,
        mapping_hash: str,
        now_iso: str,
        fingerprint: str,
        status: str,
        reason: str,
        spiffe_id: str = "",
        trust_domain: str | None = None,
    ) -> VerifiedWorkloadIdentity:
        return VerifiedWorkloadIdentity(
            agent_instance_id="",
            spiffe_id=spiffe_id,
            trust_domain=trust_domain or self.expected_trust_domain,
            identity_provider="SPIFFE-SPIRE-WorkloadAPI",
            certificate_fingerprint_sha256=fingerprint,
            not_before_iso=now_iso,
            not_after_iso=now_iso,
            verification_status=status,
            verification_reason=reason,
            identity_mapping_sha256=mapping_hash,
            request_id=request_id,
        )
