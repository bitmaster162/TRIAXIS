"""TRIAXIS PI-002 SPIFFE/SPIRE Workload Identity Provider Implementation."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding

from .contract import VerifiedWorkloadIdentity
from .mapping import SpiffeAgentMapping


class SpiffeWorkloadIdentityProvider:
    """SPIFFE Workload API Identity Provider using real SPIRE Agent runtime."""

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
        """Fetch X509-SVID from real SPIRE Agent Workload API and verify identity claims."""
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

        # 2. Invoke real SPIRE agent API to fetch X509-SVID
        import tempfile
        with tempfile.TemporaryDirectory() as tmp_out:
            try:
                cmd = [
                    resolved_bin, "api", "fetch", "x509",
                    "-socketPath", self.socket_path,
                    "-write", tmp_out,
                ]

                if os.name == "nt":
                    # Adapt WSL path if on Windows host
                    wsl_cmd = ["wsl", "-e", resolved_bin, "api", "fetch", "x509", "-socketPath", self.socket_path, "-write", tmp_out]
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

                # Locate fetched SVID pem file
                svid_file = Path(tmp_out) / "svid.0.pem"
                if not svid_file.exists():
                    # Fallback check files in directory
                    pems = list(Path(tmp_out).glob("*.pem"))
                    if not pems:
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
                    svid_file = pems[0]

                cert_pem = svid_file.read_bytes()
                cert = x509.load_pem_x509_certificate(cert_pem, default_backend())

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

        # 3. Extract SPIFFE ID from SAN extension
        spiffe_id = ""
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
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
                certificate_fingerprint_sha256=empty_fingerprint,
                not_before_iso=now_iso,
                not_after_iso=now_iso,
                verification_status="DENIED",
                verification_reason="MISSING_SPIFFE_ID_IN_SVID",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 4. Verify certificate validity window
        if hasattr(cert, "not_valid_before_utc"):
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        else:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        if now < not_before or now > not_after:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=self.expected_trust_domain,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="CERTIFICATE_EXPIRED",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 5. Extract trust domain from SPIFFE ID (spiffe://<trust_domain>/path)
        td = spiffe_id.replace("spiffe://", "").split("/")[0]
        if td != self.expected_trust_domain:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=td,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="TRUST_DOMAIN_MISMATCH",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        # 6. Map SPIFFE ID -> agent_instance_id
        mapped_agent = self.mapping.resolve_agent_instance_id(spiffe_id)
        if not mapped_agent:
            return VerifiedWorkloadIdentity(
                agent_instance_id="",
                spiffe_id=spiffe_id,
                trust_domain=td,
                identity_provider="SPIFFE-SPIRE-WorkloadAPI",
                certificate_fingerprint_sha256=hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest(),
                not_before_iso=not_before.isoformat(),
                not_after_iso=not_after.isoformat(),
                verification_status="DENIED",
                verification_reason="IDENTITY_MAPPING_NOT_FOUND",
                identity_mapping_sha256=mapping_hash,
                request_id=request_id,
            )

        cert_fp = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()

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

    def _resolve_spire_agent(self) -> str | None:
        if Path(self.spire_agent_binary).exists():
            return self.spire_agent_binary
        import shutil
        found = shutil.which("spire-agent")
        if found:
            return found
        if os.name == "nt":
            # Check WSL for spire-agent
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
