from __future__ import annotations

import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from tests.test_v3_23_external_sandbox_attestation import config, parent, sandbox_receipt, signed_fixture, trust_fixture
from triaxis.harness_attestation import build_attested_subagent_contract

D = "d" * 64


class ExternalSandboxAttestationSchemaTests(unittest.TestCase):
    def validate(self, name: str, value) -> None:
        schema = json.loads(Path("schemas", name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)

    def test_reference_contracts(self) -> None:
        receipt = sandbox_receipt()
        pair, registry = trust_fixture()
        attestation, signed = signed_fixture(receipt, pair=pair)
        self.validate("triaxis_sandbox_provision_attestation_v1.schema.json", attestation)
        request = {
            "child_session_id": "child:exec", "agent_type": "executor",
            "capability_mode": "execute", "requested_capabilities": ["read", "execute"],
            "isolation": "none", "sandbox_profile": "sandbox:read-exec",
            "sandbox_receipt_sha256": receipt["receipt_sha256"],
            "sandbox_attestation_envelope_sha256": signed["envelope_sha256"],
            "context_manifest_sha256": D,
            "mcp_inheritance": {"mode": "none", "names": []},
        }
        result = build_attested_subagent_contract(
            parent(), request, config(), repository_manifest={}, sandbox_receipt=receipt,
            signed_sandbox_attestation=signed, trust_registry=registry, evaluation_tick=7,
            required_features=["PID_NAMESPACE", "MOUNT_NAMESPACE", "NETWORK_DENY"],
            allowed_trust_domains=["infra:independent"],
        )
        self.validate("triaxis_attested_subagent_v1.schema.json", result)


if __name__ == "__main__":
    unittest.main()
