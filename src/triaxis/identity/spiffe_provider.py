"""TRIAXIS PI-002 SPIFFE/SPIRE Workload Identity Provider.

The production path accepts identity material only from a Unix-domain SPIFFE
Workload API endpoint. It never reads SPIRE datastores and never synthesizes
SVIDs or trust roots locally.
"""

from __future__ import annotations

import base64
from datetime import datetime as dt, timezone
import hashlib
import os
import socket
import stat
import struct
import time
from typing import Any, Iterator

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from OpenSSL import crypto

from .contract import VerifiedWorkloadIdentity
from .mapping import SpiffeAgentMapping


class NativeSpiffeWorkloadApiClient:
    """Minimal native SPIFFE Workload API client over a Unix-domain socket."""

    _FETCH_X509_SVID_PATH = "/spiffe.workload.v1.SpiffeWorkloadAPI/FetchX509SVID"

    def __init__(self, socket_path: str, timeout_seconds: float = 5.0):
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds

    def fetch_x509_svid(self) -> tuple[dict[str, Any] | None, str]:
        """Fetch an X509-SVID only from the configured Workload API UDS."""
        resolved_path = self.socket_path
        try:
            endpoint_stat = os.stat(resolved_path)
        except FileNotFoundError:
            return None, "SPIRE_AGENT_UNAVAILABLE"
        except OSError:
            return None, "SPIRE_WORKLOAD_API_ERROR"

        if not stat.S_ISSOCK(endpoint_stat.st_mode):
            return None, "INVALID_WORKLOAD_API_ENDPOINT"

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout_seconds)
                sock.connect(resolved_path)
                sock.sendall(self._build_fetch_request())

                raw_response = b""
                started = time.monotonic()
                while time.monotonic() - started < self.timeout_seconds:
                    try:
                        chunk = sock.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    raw_response += chunk
                    parsed, status = self._parse_http2_grpc_response(raw_response)
                    if status == "OK":
                        return parsed, status

            parsed, status = self._parse_http2_grpc_response(raw_response)
            if status == "OK":
                return parsed, status
            return None, "NO_SVID_ISSUED"
        except (ConnectionError, OSError):
            return None, "SPIRE_WORKLOAD_API_ERROR"

    def _build_fetch_request(self) -> bytes:
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        settings = self._frame(frame_type=0x04, flags=0x00, stream_id=0, payload=b"")

        headers = b"\x83\x86"
        headers += self._hpack_literal(":path", self._FETCH_X509_SVID_PATH)
        headers += self._hpack_literal(":authority", "localhost")
        headers += self._hpack_literal("content-type", "application/grpc")
        headers += self._hpack_literal("workload.spiffe.io", "true")
        headers += self._hpack_literal("te", "trailers")
        headers_frame = self._frame(
            frame_type=0x01,
            flags=0x04,
            stream_id=1,
            payload=headers,
        )

        grpc_empty_request = b"\x00\x00\x00\x00\x00"
        data_frame = self._frame(
            frame_type=0x00,
            flags=0x01,
            stream_id=1,
            payload=grpc_empty_request,
        )
        return preface + settings + headers_frame + data_frame

    @staticmethod
    def _frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        length = len(payload)
        return (
            length.to_bytes(3, "big")
            + bytes([frame_type, flags])
            + struct.pack(">I", stream_id & 0x7FFFFFFF)
            + payload
        )

    @staticmethod
    def _hpack_literal(name: str, value: str) -> bytes:
        name_bytes = name.encode("utf-8")
        value_bytes = value.encode("utf-8")
        if len(name_bytes) >= 127 or len(value_bytes) >= 127:
            raise ValueError("HPACK literal too long for minimal encoder")
        return bytes([0x00, len(name_bytes)]) + name_bytes + bytes([len(value_bytes)]) + value_bytes

    def _parse_http2_grpc_response(self, raw_response: bytes) -> tuple[dict[str, Any] | None, str]:
        data = bytearray()
        for frame_type, flags, stream_id, payload in self._iter_http2_frames(raw_response):
            if stream_id != 1 or frame_type != 0x00:
                continue
            if flags & 0x08:
                if not payload:
                    continue
                pad_len = payload[0]
                if pad_len >= len(payload):
                    continue
                payload = payload[1 : len(payload) - pad_len]
            data.extend(payload)

        for message in self._iter_grpc_messages(bytes(data)):
            result = self._decode_x509_svid_response(message)
            if result is not None:
                return result, "OK"
        return None, "INCOMPLETE_RESPONSE"

    @staticmethod
    def _iter_http2_frames(raw: bytes) -> Iterator[tuple[int, int, int, bytes]]:
        pos = 0
        while pos + 9 <= len(raw):
            length = int.from_bytes(raw[pos : pos + 3], "big")
            frame_type = raw[pos + 3]
            flags = raw[pos + 4]
            stream_id = int.from_bytes(raw[pos + 5 : pos + 9], "big") & 0x7FFFFFFF
            end = pos + 9 + length
            if end > len(raw):
                break
            yield frame_type, flags, stream_id, raw[pos + 9 : end]
            pos = end

    @staticmethod
    def _iter_grpc_messages(data: bytes) -> Iterator[bytes]:
        pos = 0
        while pos + 5 <= len(data):
            compressed = data[pos]
            message_len = int.from_bytes(data[pos + 1 : pos + 5], "big")
            end = pos + 5 + message_len
            if end > len(data):
                break
            if compressed == 0:
                yield data[pos + 5 : end]
            pos = end

    @classmethod
    def _decode_x509_svid_response(cls, message: bytes) -> dict[str, Any] | None:
        """Decode the first X509SVID from the protobuf response."""
        for field_no, wire_type, value in cls._iter_protobuf_fields(message):
            if field_no != 1 or wire_type != 2 or not isinstance(value, bytes):
                continue
            x509_svid = b""
            bundle = b""
            for nested_no, nested_wire, nested_value in cls._iter_protobuf_fields(value):
                if nested_wire != 2 or not isinstance(nested_value, bytes):
                    continue
                if nested_no == 2:
                    x509_svid = nested_value
                elif nested_no == 4:
                    bundle = nested_value
            if x509_svid and bundle:
                return {
                    "x509_svid": base64.b64encode(x509_svid).decode("ascii"),
                    "bundle": base64.b64encode(bundle).decode("ascii"),
                }
        return None

    @classmethod
    def _iter_protobuf_fields(cls, data: bytes) -> Iterator[tuple[int, int, int | bytes]]:
        pos = 0
        while pos < len(data):
            key, pos = cls._read_varint(data, pos)
            field_no = key >> 3
            wire_type = key & 0x07
            if field_no == 0:
                return
            if wire_type == 0:
                value, pos = cls._read_varint(data, pos)
                yield field_no, wire_type, value
            elif wire_type == 1:
                end = pos + 8
                if end > len(data):
                    return
                yield field_no, wire_type, data[pos:end]
                pos = end
            elif wire_type == 2:
                length, pos = cls._read_varint(data, pos)
                end = pos + length
                if end > len(data):
                    return
                yield field_no, wire_type, data[pos:end]
                pos = end
            elif wire_type == 5:
                end = pos + 4
                if end > len(data):
                    return
                yield field_no, wire_type, data[pos:end]
                pos = end
            else:
                return

    @staticmethod
    def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
        value = 0
        shift = 0
        while pos < len(data) and shift < 70:
            byte = data[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value, pos
            shift += 7
        raise ValueError("invalid protobuf varint")


class SpiffeWorkloadIdentityProvider:
    """SPIFFE Workload API provider with RFC 5280 path validation."""

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
            }
            return self._identity_result(
                request_id=request_id,
                mapping_hash=mapping_hash,
                now_iso=now_iso,
                fingerprint=empty_fingerprint,
                status="DENIED" if status in denied_statuses else "ERROR",
                reason=status,
            )

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

        try:
            svid_chain = self._parse_x509_chain(svid_raw)
            trust_bundle = self._parse_x509_chain(bundle_raw)
            if not svid_chain:
                raise ValueError("empty SVID chain")
            if not trust_bundle:
                raise ValueError("empty trust bundle")
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
            basic = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS).value
            if basic.ca:
                return "SVID_LEAF_CONSTRAINTS_VIOLATED"
        except x509.ExtensionNotFound:
            pass

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
            eku = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE).value
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
    def _verify_path(svid_chain: list[x509.Certificate], trust_bundle: list[x509.Certificate]) -> bool:
        try:
            store = crypto.X509Store()
            for cert in trust_bundle:
                store.add_cert(crypto.X509.from_cryptography(cert))
            leaf = crypto.X509.from_cryptography(svid_chain[0])
            intermediates = [crypto.X509.from_cryptography(cert) for cert in svid_chain[1:]]
            crypto.X509StoreContext(store, leaf, intermediates).verify_certificate()
            return True
        except Exception:
            return False

    @classmethod
    def _parse_x509_chain(cls, data_str: str) -> list[x509.Certificate]:
        raw = data_str.encode("utf-8") if data_str.startswith("-----BEGIN") else base64.b64decode(data_str)
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
                if length_len == 0 or length_len > 4 or pos + 2 + length_len > len(raw):
                    raise ValueError("invalid DER length")
                header_len = 2 + length_len
                content_len = int.from_bytes(raw[pos + 2 : pos + 2 + length_len], "big")
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
