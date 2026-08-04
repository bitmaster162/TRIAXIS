from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis import (
    TRUST_CHECKPOINT_CONTRACT_ID,
    TRUST_CHECKPOINT_V2_CONTRACT_ID,
    validate_checkpoint_receipt,
)
from triaxis.provenance_trust_state import ProvenanceTrustCheckpoint
from validation.provenance_trust.authority_checkpoint_receipt_trigger_v31 import run_trigger


class V238CheckpointReceiptTests(unittest.TestCase):
    @staticmethod
    def _checkpoint(parent=None, *, sequence: int = 1) -> ProvenanceTrustCheckpoint:
        return ProvenanceTrustCheckpoint(
            sequence=sequence,
            envelope_sha256="1" * 64,
            snapshot_sha256="2" * 64,
            previous_envelope_sha256=parent,
            issued_at=5,
            evaluation_tick=5,
            authority_id="authority:test",
            key_id="key:test",
            authority_root_sha256="3" * 64,
        )

    def test_contract_bumps_to_v3_without_erasing_v2(self) -> None:
        self.assertEqual(
            TRUST_CHECKPOINT_V2_CONTRACT_ID,
            "TRIAXIS_PROVENANCE_TRUST_CHECKPOINT_v2",
        )
        self.assertEqual(
            TRUST_CHECKPOINT_CONTRACT_ID,
            "TRIAXIS_PROVENANCE_TRUST_CHECKPOINT_v3",
        )

    def test_frozen_v31_trigger_is_closed(self) -> None:
        result = run_trigger()
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["pass_count"], 9, result)
        self.assertEqual(result["positive_control_pass_count"], 4, result)

    def test_receipt_is_self_verifying_and_tamper_evident(self) -> None:
        receipt = self._checkpoint().as_dict()
        accepted = validate_checkpoint_receipt(receipt)
        self.assertEqual(accepted["status"], "PASS", accepted)
        tampered = deepcopy(receipt)
        tampered["sequence"] = 2
        rejected = validate_checkpoint_receipt(tampered)
        self.assertEqual(rejected["status"], "BLOCK", rejected)
        self.assertEqual(
            {item["code"] for item in rejected["errors"]},
            {"checkpoint_receipt_digest_mismatch"},
        )

    def test_parent_dimension_cannot_serialize_to_same_receipt(self) -> None:
        left = self._checkpoint(parent="a" * 64, sequence=2).as_dict()
        right = self._checkpoint(parent="b" * 64, sequence=2).as_dict()
        self.assertNotEqual(left, right)
        self.assertNotEqual(left["checkpoint_sha256"], right["checkpoint_sha256"])


if __name__ == "__main__":
    unittest.main()
