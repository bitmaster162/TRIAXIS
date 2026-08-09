"""TRIAXIS PI-002 R1.1 Mandatory Focused Controls & X509 Validation Matrix Test Suite."""

import base64
import datetime
from datetime import datetime as dt, timezone
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
import pytest

from triaxis.identity import SpiffeAgentMapping, SpiffeWorkloadIdentityProvider


def make_custom_svid_pki(
    spiffe_id: str = "spiffe://triaxis.local/agent/test-001",
    include_key_usage: bool = True,
    key_usage_critical: bool = True,
    digital_signature: bool = True,
    key_cert_sign: bool = False,
    crl_sign: bool = False,
    uri_sans: list[str] | None = None,
    eku_oids: list[x509.ObjectIdentifier] | None = None,
    ca_flag: bool = False,
    expired: bool = False,
):
    if uri_sans is None:
        uri_sans = [spiffe_id] if spiffe_id else []

    trust_domain = "triaxis.local"
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, f"SPIFFE CA ({trust_domain})")])
    now = dt.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "SPIFFE Leaf SVID")])

    if expired:
        n_before = now - datetime.timedelta(days=2)
        n_after = now - datetime.timedelta(days=1)
    else:
        n_before = now - datetime.timedelta(minutes=10)
        n_after = now + datetime.timedelta(hours=2)

    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(n_before)
        .not_valid_after(n_after)
        .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
    )

    if include_key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                key_cert_sign=key_cert_sign,
                crl_sign=crl_sign,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=key_usage_critical,
        )

    if eku_oids is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH, x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )

    if uri_sans:
        san_uris = [x509.UniformResourceIdentifier(u) for u in uri_sans]
        builder = builder.add_extension(x509.SubjectAlternativeName(san_uris), critical=True)

    leaf_cert = builder.sign(ca_key, hashes.SHA256())
    return ca_cert.public_bytes(Encoding.PEM).decode("utf-8"), leaf_cert.public_bytes(Encoding.PEM).decode("utf-8")


class MockClientCustomPayload:
    def __init__(self, svid_pem: str, bundle_pem: str):
        self.svid_pem = svid_pem
        self.bundle_pem = bundle_pem

    def fetch_x509_svid(self):
        return {
            "x509_svid": self.svid_pem,
            "bundle": self.bundle_pem,
        }, "OK"


def eval_custom_svid(provider: SpiffeWorkloadIdentityProvider, svid_pem: str, bundle_pem: str):
    provider.client = MockClientCustomPayload(svid_pem, bundle_pem)
    return provider.fetch_and_verify_identity("req_test")


def test_focused_control_1_missing_key_usage():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(include_key_usage=False)
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_KEY_USAGE_MISSING"


def test_focused_control_2_non_critical_key_usage():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(key_usage_critical=False)
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_KEY_USAGE_NOT_CRITICAL"


def test_focused_control_3_digital_signature_false():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(digital_signature=False)
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"


def test_focused_control_4_key_cert_sign_true():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(key_cert_sign=True)
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"


def test_focused_control_5_crl_sign_true():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(crl_sign=True)
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"


def test_focused_control_6_zero_uri_san():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(uri_sans=[])
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "MISSING_SPIFFE_ID_IN_SVID"


def test_focused_control_7_two_uri_sans():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(uri_sans=["spiffe://triaxis.local/agent/test-001", "spiffe://triaxis.local/agent/test-002"])
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_SPIFFE_ID_AMBIGUOUS"


def test_focused_control_8_non_spiffe_uri():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(uri_sans=["https://triaxis.local/agent/test-001"])
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "MISSING_SPIFFE_ID_IN_SVID"


def test_focused_control_9_root_only_spiffe_id():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(spiffe_id="spiffe://triaxis.local")
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"

    # Also test spiffe://triaxis.local/
    ca_pem2, leaf_pem2 = make_custom_svid_pki(spiffe_id="spiffe://triaxis.local/")
    res2 = eval_custom_svid(provider, leaf_pem2, ca_pem2)
    assert res2.verification_status == "DENIED"
    assert res2.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"


def test_focused_control_10_eku_only_client_auth():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(eku_oids=[x509.ExtendedKeyUsageOID.CLIENT_AUTH])
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"


def test_focused_control_11_eku_only_server_auth():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)
    ca_pem, leaf_pem = make_custom_svid_pki(eku_oids=[x509.ExtendedKeyUsageOID.SERVER_AUTH])
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    assert res.verification_status == "DENIED"
    assert res.verification_reason == "SVID_LEAF_CONSTRAINTS_VIOLATED"


def test_generate_machine_readable_x509_validation_matrix():
    mapping = SpiffeAgentMapping({"spiffe://triaxis.local/agent/test-001": "inst_001"})
    provider = SpiffeWorkloadIdentityProvider(expected_trust_domain="triaxis.local", mapping=mapping)

    matrix = []

    # Positive control
    ca_pem, leaf_pem = make_custom_svid_pki()
    res = eval_custom_svid(provider, leaf_pem, ca_pem)
    matrix.append({
        "control_id": "positive_svid_valid",
        "description": "Fully valid SPIFFE X509-SVID leaf certificate",
        "expected_status": "VERIFIED",
        "expected_reason": "SPIFFE_SVID_VERIFIED",
        "actual_status": res.verification_status,
        "actual_reason": res.verification_reason,
        "passed": res.verification_status == "VERIFIED" and res.verification_reason == "SPIFFE_SVID_VERIFIED",
    })

    # Focused negative controls
    controls = [
        ("missing_key_usage", "Missing KeyUsage extension", {"include_key_usage": False}, "DENIED", "SVID_KEY_USAGE_MISSING"),
        ("non_critical_key_usage", "Non-critical KeyUsage extension", {"key_usage_critical": False}, "DENIED", "SVID_KEY_USAGE_NOT_CRITICAL"),
        ("digital_signature_false", "KeyUsage digitalSignature=false", {"digital_signature": False}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("key_cert_sign_true", "KeyUsage keyCertSign=true", {"key_cert_sign": True}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("crl_sign_true", "KeyUsage crlSign=true", {"crl_sign": True}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("zero_uri_san", "Zero URI SANs", {"uri_sans": []}, "DENIED", "MISSING_SPIFFE_ID_IN_SVID"),
        ("two_uri_sans", "Two URI SANs", {"uri_sans": ["spiffe://triaxis.local/agent/test-001", "spiffe://triaxis.local/agent/test-002"]}, "DENIED", "SVID_SPIFFE_ID_AMBIGUOUS"),
        ("non_spiffe_uri", "Non-SPIFFE URI scheme (https://)", {"uri_sans": ["https://triaxis.local/agent/test-001"]}, "DENIED", "MISSING_SPIFFE_ID_IN_SVID"),
        ("root_only_spiffe_id", "Root-only SPIFFE ID (spiffe://triaxis.local)", {"spiffe_id": "spiffe://triaxis.local"}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("eku_only_client_auth", "EKU with only clientAuth", {"eku_oids": [x509.ExtendedKeyUsageOID.CLIENT_AUTH]}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("eku_only_server_auth", "EKU with only serverAuth", {"eku_oids": [x509.ExtendedKeyUsageOID.SERVER_AUTH]}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("ca_flag_true", "BasicConstraints ca=true", {"ca_flag": True}, "DENIED", "SVID_LEAF_CONSTRAINTS_VIOLATED"),
        ("expired_certificate", "Expired SVID certificate", {"expired": True}, "DENIED", "CERTIFICATE_EXPIRED"),
    ]

    for cid, desc, kwargs, exp_status, exp_reason in controls:
        c_ca, c_leaf = make_custom_svid_pki(**kwargs)
        r = eval_custom_svid(provider, c_leaf, c_ca)
        passed = (r.verification_status == exp_status) and (r.verification_reason == exp_reason)
        matrix.append({
            "control_id": cid,
            "description": desc,
            "expected_status": exp_status,
            "expected_reason": exp_reason,
            "actual_status": r.verification_status,
            "actual_reason": r.verification_reason,
            "passed": passed,
        })

    out_file = Path("evidence/pi-002/PI002_R1_1_X509_VALIDATION_MATRIX.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(matrix, indent=2))
    print(f"Written machine-readable matrix to {out_file}")
