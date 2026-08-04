from __future__ import annotations

import copy
import unittest

from triaxis import AuthorityAnalysisSession
from triaxis.provenance_trust_state import ProvenanceTrustStateGuard
from validation.analysis_support_v5 import build_valid_analysis_bundle_v5
from validation.provenance_trust.binding_context_closure_v20 import REVIEW_REF, _bind
from validation.provenance_trust.support_v2 import build_trust_fixture_v2
from validation.provenance_trust.support_v3 import build_snapshot_authority_root, seal_snapshot_envelope


class V234RecoveryContractTests(unittest.TestCase):
    def test_valid_authority_bundle_commits_once(self) -> None:
        bundle = _bind(build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=5), REVIEW_REF)
        snapshot = build_trust_fixture_v2(bundle, evaluation_tick=5).snapshot
        envelope = seal_snapshot_envelope(snapshot, sequence=1, previous_envelope_sha256=None, issued_at=5, valid_until=20)
        guard = ProvenanceTrustStateGuard(authority_roots=[build_snapshot_authority_root(valid_until=20)])
        result = AuthorityAnalysisSession(trust_guard=guard).validate(bundle, trust_envelope=envelope, trusted_evaluation_tick=5)
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(guard.checkpoint.sequence, 1)

    def test_signature_tamper_is_state_neutral(self) -> None:
        bundle = _bind(build_valid_analysis_bundle_v5(control_profile="A3", evaluation_tick=5), REVIEW_REF)
        snapshot = build_trust_fixture_v2(bundle, evaluation_tick=5).snapshot
        envelope = seal_snapshot_envelope(snapshot, sequence=1, previous_envelope_sha256=None, issued_at=5, valid_until=20)
        envelope = copy.deepcopy(envelope)
        envelope["signature_b64"] = "AA=="
        guard = ProvenanceTrustStateGuard(authority_roots=[build_snapshot_authority_root(valid_until=20)])
        result = AuthorityAnalysisSession(trust_guard=guard).validate(bundle, trust_envelope=envelope, trusted_evaluation_tick=5)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIsNone(guard.checkpoint)


if __name__ == "__main__":
    unittest.main()
