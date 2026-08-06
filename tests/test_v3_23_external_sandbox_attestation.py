from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis.crypto_trust import (
    PURPOSE_SANDBOX_PROVISION_ATTESTATION,
    TrustKeyRegistry,
    generate_ed25519_keypair,
    make_trust_key_record,
)
from triaxis.harness_attestation import (
    build_attested_subagent_contract,
    seal_sandbox_provision_attestation,
    sign_sandbox_provision_attestation,
    verify_sandbox_provision_attestation,
)
from triaxis.harness_v1 import (
    make_sandbox_provision_receipt,
    resolve_harness_config,
    seal_sandbox_plan,
)
from triaxis.integrity import seal_mapping

D = "d" * 64
RUNTIME = "9" * 64


def authority():
    return {
        "capabilities": ["read", "execute"],
        "tools": ["read_file"],
        "targets": ["workspace:triaxis"],
        "data_classes": ["PUBLIC", "INTERNAL"],
        "mcp_servers": ["docs"],
        "max_context_bytes": 4096,
        "max_subagents": 2,
        "max_workflow_fanout": 2,
        "max_rounds": 4,
    }


def config():
    return resolve_harness_config([
        {
            "name": "managed",
            "values": {
                **authority(),
                "whole_repo_upload": False,
                "plugin_digests": [],
                "sandbox_profiles": ["sandbox:read-exec"],
            },
            "requirements": {
                "capabilities": ["read", "execute"],
                "tools": ["read_file"],
                "targets": ["workspace:triaxis"],
                "data_classes": ["PUBLIC", "INTERNAL"],
                "mcp_servers": ["docs"],
                "max_context_bytes": 4096,
                "max_subagents": 2,
                "max_workflow_fanout": 2,
                "max_rounds": 4,
                "whole_repo_upload": False,
            },
        }
    ])


def parent():
    return {
        "session_id": "session:parent",
        "depth": 0,
        "active_child_count": 0,
        "capabilities": ["read", "execute"],
        "mcp_servers": ["docs"],
    }


def sandbox_receipt(child_id: str = "child:exec"):
    plan = seal_sandbox_plan({
        "sandbox_id": f"sandbox:{child_id}",
        "profile_id": "sandbox:read-exec",
        "child_session_id": child_id,
        "repository_manifest_sha256": None,
        "allowed_capabilities": ["read", "execute"],
        "network_mode": "DENY",
        "network_allowlist": [],
        "read_paths": ["workspace/triaxis"],
        "write_paths": [],
        "env_allowlist": ["PATH"],
        "budgets": {"cpu_seconds": 30, "memory_mb": 512, "wall_seconds": 60, "max_processes": 8},
        "expires_at_tick": 20,
    })
    observed = {
        "sandbox_id": plan["sandbox_id"],
        "profile_id": plan["profile_id"],
        "child_session_id": plan["child_session_id"],
        "repository_manifest_sha256": None,
        "network_mode": "DENY",
        "network_allowlist": [],
        "read_paths": ["workspace/triaxis"],
        "write_paths": [],
        "env_allowlist": ["PATH"],
        "budgets": plan["budgets"],
        "backend_id": "backend:containerd",
        "state_dir_id": "state:exec",
        "pid_namespace_id": "pidns:123",
        "mount_namespace_id": "mntns:456",
        "network_namespace_id": "netns:789",
    }
    return make_sandbox_provision_receipt(
        plan,
        observed,
        provisioner_id="provisioner:external",
        observed_at_tick=5,
    )


def trust_fixture(*, revoked_at=None, trust_domain="infra:independent"):
    pair = generate_ed25519_keypair()
    record = make_trust_key_record(
        key_id="key:sandbox-attestor:1",
        signer_id="attestor:runtime:1",
        trust_domain=trust_domain,
        public_key_b64=pair["public_key_b64"],
        purposes=[PURPOSE_SANDBOX_PROVISION_ATTESTATION],
        valid_from=0,
        valid_until=100,
        revoked_at=revoked_at,
    )
    return pair, TrustKeyRegistry([record])


def signed_fixture(receipt, *, pair=None, features=None, signer_id="attestor:runtime:1", trust_domain="infra:independent"):
    pair = generate_ed25519_keypair() if pair is None else pair
    attestation = seal_sandbox_provision_attestation(
        receipt,
        attestor_id=signer_id,
        runtime_measurement_sha256=RUNTIME,
        observed_features=features or ["PID_NAMESPACE", "MOUNT_NAMESPACE", "NETWORK_DENY", "NON_ROOT"],
        observed_at_tick=6,
        expires_at_tick=15,
    )
    signed = sign_sandbox_provision_attestation(
        attestation,
        key_id="key:sandbox-attestor:1",
        signer_id=signer_id,
        trust_domain=trust_domain,
        private_key_b64=pair["private_key_b64"],
        issued_at=6,
        valid_until=15,
    )
    return attestation, signed


class ExternalSandboxAttestationTests(unittest.TestCase):
    def test_valid_external_attestation_allows_exact_subagent(self):
        receipt = sandbox_receipt()
        pair, registry = trust_fixture()
        _, signed = signed_fixture(receipt, pair=pair)
        request = {
            "child_session_id": "child:exec",
            "agent_type": "executor",
            "capability_mode": "execute",
            "requested_capabilities": ["read", "execute"],
            "isolation": "none",
            "sandbox_profile": "sandbox:read-exec",
            "sandbox_receipt_sha256": receipt["receipt_sha256"],
            "sandbox_attestation_envelope_sha256": signed["envelope_sha256"],
            "context_manifest_sha256": D,
            "mcp_inheritance": {"mode": "none", "names": []},
        }
        result = build_attested_subagent_contract(
            parent(),
            request,
            config(),
            repository_manifest={},
            sandbox_receipt=receipt,
            signed_sandbox_attestation=signed,
            trust_registry=registry,
            evaluation_tick=7,
            required_features=["PID_NAMESPACE", "MOUNT_NAMESPACE", "NETWORK_DENY"],
            allowed_trust_domains=["infra:independent"],
        )
        self.assertEqual(result["status"], "PASS", result["errors"])
        self.assertEqual(result["attestor_id"], "attestor:runtime:1")
        self.assertEqual(result["runtime_measurement_sha256"], RUNTIME)

    def test_unsigned_or_forged_envelope_is_blocked(self):
        receipt = sandbox_receipt()
        pair, registry = trust_fixture()
        _, signed = signed_fixture(receipt, pair=pair)
        forged = deepcopy(signed)
        forged["signature_b64"] = "A" * 88
        result = verify_sandbox_provision_attestation(
            forged,
            registry=registry,
            evaluation_tick=7,
            expected_sandbox_receipt=receipt,
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertTrue({"invalid_signature", "invalid_signature_encoding"} & {row["code"] for row in result["errors"]})

    def test_attestation_cannot_be_reused_for_another_receipt(self):
        receipt_a = sandbox_receipt("child:exec")
        receipt_b = sandbox_receipt("child:other")
        pair, registry = trust_fixture()
        _, signed = signed_fixture(receipt_a, pair=pair)
        result = verify_sandbox_provision_attestation(
            signed,
            registry=registry,
            evaluation_tick=7,
            expected_sandbox_receipt=receipt_b,
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("attestation_subject_mismatch", {row["code"] for row in result["errors"]})

    def test_revoked_key_and_wrong_trust_domain_are_blocked(self):
        receipt = sandbox_receipt()
        pair, revoked_registry = trust_fixture(revoked_at=7)
        _, signed = signed_fixture(receipt, pair=pair)
        revoked = verify_sandbox_provision_attestation(
            signed,
            registry=revoked_registry,
            evaluation_tick=7,
            expected_sandbox_receipt=receipt,
        )
        self.assertEqual(revoked["status"], "BLOCK")
        self.assertIn("signing_key_revoked", {row["code"] for row in revoked["errors"]})

        pair2, registry2 = trust_fixture(trust_domain="infra:shared-host")
        _, signed2 = signed_fixture(receipt, pair=pair2, trust_domain="infra:shared-host")
        denied = verify_sandbox_provision_attestation(
            signed2,
            registry=registry2,
            evaluation_tick=7,
            expected_sandbox_receipt=receipt,
            allowed_trust_domains=["infra:independent"],
        )
        self.assertEqual(denied["status"], "BLOCK")
        self.assertIn("attestor_trust_domain_denied", {row["code"] for row in denied["errors"]})

    def test_required_features_and_exact_envelope_binding(self):
        receipt = sandbox_receipt()
        pair, registry = trust_fixture()
        _, signed = signed_fixture(receipt, pair=pair, features=["PID_NAMESPACE"])
        request = {
            "child_session_id": "child:exec",
            "capability_mode": "execute",
            "requested_capabilities": ["read", "execute"],
            "isolation": "none",
            "sandbox_profile": "sandbox:read-exec",
            "sandbox_receipt_sha256": receipt["receipt_sha256"],
            "sandbox_attestation_envelope_sha256": "0" * 64,
            "context_manifest_sha256": D,
            "mcp_inheritance": {"mode": "none", "names": []},
        }
        result = build_attested_subagent_contract(
            parent(),
            request,
            config(),
            repository_manifest={},
            sandbox_receipt=receipt,
            signed_sandbox_attestation=signed,
            trust_registry=registry,
            evaluation_tick=7,
            required_features=["PID_NAMESPACE", "NETWORK_DENY"],
        )
        self.assertEqual(result["status"], "BLOCK")
        codes = {row["code"] for row in result["errors"]}
        self.assertIn("required_feature_missing", codes)
        self.assertIn("sandbox_attestation_binding_mismatch", codes)

    def test_canonical_resealing_cannot_replace_signature(self):
        receipt = sandbox_receipt()
        pair, registry = trust_fixture()
        attestation, signed = signed_fixture(receipt, pair=pair)
        tampered = deepcopy(attestation)
        tampered["backend_id"] = "backend:invented"
        tampered = seal_mapping(tampered, "attestation_sha256")
        forged = deepcopy(signed)
        forged["inner_contract"] = tampered
        forged["inner_digest"] = tampered["attestation_sha256"]
        forged["envelope_sha256"] = "0" * 64
        result = verify_sandbox_provision_attestation(
            forged,
            registry=registry,
            evaluation_tick=7,
            expected_sandbox_receipt=receipt,
        )
        self.assertEqual(result["status"], "BLOCK")
        self.assertTrue({"envelope_digest_mismatch", "invalid_signature"} & {row["code"] for row in result["errors"]})


if __name__ == "__main__":
    unittest.main()
