"""TRIAXIS PI-002 SPIFFE/SPIRE Workload Identity Provider Implementation."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.serialization import Encoding

from .contract import VerifiedWorkloadIdentity
from .mapping import SpiffeAgentMapping


class SpiffeWorkloadIdentityProvider:
    """SPIFFE Workload API Identity Provider using real in-memory SPIRE Agent runtime."""

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
        self.socket_path = socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET", "/tmp/spire-agent/public/api.sock")
        self.spire_agent_binary = spire_agent_binary
        self.timeout_seconds = timeout_seconds

    def fetch_and_verify_identity(self, request_id: str = "") -> VerifiedWorkloadIdentity:
        """Fetch X509-SVID in memory from real SPIRE Agent Workload API and perform cryptographic verification."""
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        empty_fingerprint = "0" * 64
        mapping_hash = self.mapping.identity_mapping_sha256

        # 1. Verify socket / binary availability
        resolved_bin = self._resolve_spire_agent()
        if not resolved_bin:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id="",
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=empty_fingerprint,
                not_before_iso=now_iso,
                not_after_iso=now_iso,
                verification_status="ERROR",
                verification_reason="SPIRE_AGENT_UNAVAILABLE",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 2. Invoke real SPIRE agent API to fetch X509-SVID in-memory (JSON format, no filesystem writing)
        try:
            cmd = [
                resolved_bin, "api", "fetch", "x509",
                "-socketPath", self.socket_path,
                "-output", "json",
            ]

            if os.name == "nt":
                wsl_cmd = ["wsl", "-e", resolved_bin, "api", "fetch", "x509", "-socketPath", self.socket_path, "-output", "json"]
                res = subprocess.run(wsl_cmd, capture_output=True, text=True, timeout=self.timeout_seconds)
            else:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_seconds)

            if res.returncode != 0:
                err_msg = res.stderr.strip() or res.stdout.strip()
                reason = "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH" if "no identity issued" in err_msg.lower() or "permissiondenied" in err_msg.lower() else "SPIFFE_WORKLOAD_API_ERROR"
                return VerifiedWorkloadIdentity(
                    agent_instance_id="",
                    spiffe_id="",
                    trust_domain=self.expected_trust_domain,
                    identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                    certificate_fingerprint_sha256=empty_fingerprint,
                    not_before_iso=now_iso,
                    not_after_iso=now_iso,
                    verification_status="DENIED" if reason == "WORKLOAD_ATTESTATION_SELECTOR_MISMATCH" else "ERROR",
                    verification_reason=reason,
                    identity_mapping_sha256=mapping_hash,
                    request_id=request_id,
                )

            data = json.loads(res.stdout)
            svids = data.get("svids", [])
            if not svids:
                return VerifiedWorkloadIdentity(
                    agent_instance_id="",
                    spiffe_id="",
                    trust_domain=self.expected_trust_domain,
                    identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                    certificate_fingerprint_sha256=empty_fingerprint,
                    not_before_iso=now_iso,
                    not_after_iso=now_iso,
                    verification_status="DENIED",
                    verification_reason="NO_SVID_ISSUED",
                    identity_mapping_sha256=mapping_hash,
                    request_id=request_id,
                )

            primary_svid = svids[0]
            svid_b64 = primary_svid.get("x509_svid", "")
            bundle_b64 = primary_svid.get("bundle", "")

            # Safely discard private key material from memory immediately
            primary_svid.pop("x509_svid_key", None)
            data = None
            res = None

            if not svid_b64:
                return VerifiedWorkloadIdentity(
                    agent_instance_id="",
                    spiffe_id="",
                    trust_domain=self.expected_trust_domain,
                    identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                    certificate_fingerprint_sha256=empty_fingerprint,
                    not_before_iso=now_iso,
                    not_after_iso=now_iso,
                    verification_status="DENIED",
                    verification_reason="NO_SVID_ISSUED",
                    identity_mapping_sha256=mapping_hash,
                    request_id=request_id,
                )

            if not bundle_b64:
                return VerifiedWorkloadIdentity(
                    agent_instance_id="",
                    spiffe_id="",
                    trust_domain=self.expected_trust_domain,
                    identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                    certificate_fingerprint_sha256=empty_fingerprint,
                    not_before_iso=now_iso,
                    not_after_iso=now_iso,
                    verification_status="DENIED",
                    verification_reason="TRUST_BUNDLE_UNAVAILABLE",
                    identity_mapping_sha256=mapping_hash,
                    request_id=request_id,
                )

            svid_cert = self._parse_x509_cert(svid_b64)
            bundle_cert = self._parse_x509_cert(bundle_b64)

        except subprocess.TimeoutExpired:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id="",
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=empty_fingerprint,
                not_before_iso=now_iso,
                not_after_iso=now_iso,
                verification_status="ERROR",
                verification_reason="SPIFFE_WORKLOAD_API_TIMEOUT",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )
        except Exception as exc:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id="",
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=empty_fingerprint,
                not_before_iso=now_iso,
                not_after_iso=now_iso,
                verification_status="ERROR",
                verification_reason=f"SPIFFE_WORKLOAD_API_EXCEPTION: {type(exc).__name__}",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 3. Perform cryptographic trust verification of X509-SVID against SPIFFE trust bundle
        try:
            pubkey = bundle_cert.public_key()
            if isinstance(pubkey, ec.EllipticCurvePublicKey):
                pubkey.verify(
                    svid_cert.signature,
                    svid_cert.tbs_certificate_bytes,
                    ec.ECDSA(svid_cert.signature_hash_algorithm),
                )
            else:
                pubkey.verify(
                    svid_cert.signature,
                    svid_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    svid_cert.signature_hash_algorithm,
                )
        except Exception:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id="",
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=now_iso,
                not_after_iso=now_iso,
                verification_status="DENIED",
                verification_reason="SVID_CHAIN_INVALID",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 4. Extract SPIFFE ID from SAN extension
        spiffe_id = ""
        try:
            san_ext = svid_cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            uris = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
            for uri in uris:
                if uri.startswith("spiffe://"):
                    spiffe_id = uri
                    break
        except Exception:
            pass

        if not spiffe_id:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id="",
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=now_iso,
                not_after_iso=now_iso,
                verification_status="DENIED",
                verification_reason="MISSING_SPIFFE_ID_IN_SVID",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 5. Verify certificate validity window
        if hasattr(svid_cert, "not_valid_before_utc"):
            not_before = svid_cert.not_valid_before_utc
            not_after = svid_cert.not_valid_after_utc
        else:
            not_before = svid_cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = svid_cert.not_valid_after.replace(tzinfo=timezone.utc)

        if now < not_before or now > not_after:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="CERTIFICATE_EXPIRED",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 6. Extract trust domain from SPIFFE ID (spiffe://<trust_domain>/path)
        td = spiffe_id.replace("spiffe://", "").split("/")[0]
        if td != self.expected_trust_domain:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=td,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="TRUST_DOMAIN_MISMATCH",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 7. Map SPIFFE ID -> agent_instance_id
        mapped_agent = self.mapping.resolve_agent_instance_id(spiffe_id)
        if not mapped_agent:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=td,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="IDENTITY_MAPPING_NOT_FOUND",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        cert_fp = hashlib.sha256(svid_cert.public_bytes(Encoding.DER)).hexdigest()

        return VerifiedWorkloadIdentity(
            agent_instance_id=mapped_agent,
            spiffe_id=spiffe_id,
            trust_domain=td,
            identity_provider="SPIFFE-SPIRE-WorkloadAPI",
            certificate_fingerprint_sha256=cert_fp,
            not_before_iso=not_before.isoformat(),
            not_after_iso=not_after.isoformat(),
            verification_status="VERIFIED",
            verification_reason="SPIFFE_SVID_VERIFIED",
            identity_mapping_sha256=mapping_hash,
            request_id=request_id,
        )

    def _parse_x509_cert(self, data_str: str) -> x509.Certificate:
        raw = base64.b64decode(data_str) if not data_str.startswith("-----BEGIN") else data_str.encode("utf-8")
        if b"-----BEGIN CERTIFICATE-----" in raw:
            return x509.load_pem_x509_certificate(raw, default_backend())
        return x509.load_der_x509_certificate(raw, default_backend())

    def _resolve_spire_agent(self) -> str | None:
        if Path(self.spire_agent_binary).exists():
            return self.spire_agent_binary
        import shutil
        found = shutil.which("spire-agent")
        if found:
            return found
        if os.name == "nt":
            try:
                res = subprocess.run(["wsl", "-e", "which", "spire-agent"], capture_output=True, text=True)
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip()
                res2 = subprocess.run(["wsl", "-e", "test", "-x", "/home/bit/.local/bin/spire-agent"], capture_output=True)
                if res2.returncode == 0:
                    return "/home/bit/.local/bin/spire-agent"
            except Exception:
                pass
        return None
