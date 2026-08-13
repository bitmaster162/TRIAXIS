import itertools
import unittest

from triaxis_runtime_r13 import *

class TestSideEffectCommit(unittest.TestCase):
    def base_event(self):
        return EventFacts(
            action_attempted=True,action_executed=True,action_completed=True,
            consequential_action=True,user_authority=True,
            scientific_candidate_executed=False,
            instrument_required=False,evidence_complete=True,
            tool_needed=True,tool_invocation_valid=True,tool_runtime_success=True
        )

    def test_accept_without_verify_is_partial(self):
        a=adjudicate(self.base_event(),SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.NOT_PERFORMED
        ))
        self.assertEqual(a.event_outcome,EventOutcome.PARTIAL)
        self.assertEqual(a.failure_cause,FailureCause.RESULT_STATE_UNVERIFIED)
        self.assertEqual(a.commit_state,CommitState.NOT_COMMITTED)

    def test_accept_mismatch_fails(self):
        a=adjudicate(self.base_event(),SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MISMATCH,
            expected_fingerprint="a",observed_fingerprint="b"
        ))
        self.assertEqual(a.event_outcome,EventOutcome.EXECUTED_FAILURE)
        self.assertEqual(a.failure_cause,FailureCause.RESULT_STATE_MISMATCH)
        self.assertEqual(a.commit_state,CommitState.NOT_COMMITTED)

    def test_declared_match_with_hash_mismatch_fails(self):
        a=adjudicate(self.base_event(),SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MATCH,
            expected_fingerprint="a",observed_fingerprint="b"
        ))
        self.assertEqual(a.failure_cause,FailureCause.RESULT_STATE_MISMATCH)
        self.assertEqual(a.commit_state,CommitState.NOT_COMMITTED)

    def test_verified_match_commits(self):
        a=adjudicate(self.base_event(),SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MATCH,
            expected_fingerprint="a",observed_fingerprint="a"
        ))
        self.assertEqual(a.event_outcome,EventOutcome.EXECUTED_SUCCESS)
        self.assertEqual(a.failure_cause,FailureCause.NONE)
        self.assertEqual(a.commit_state,CommitState.COMMITTED)
        self.assertEqual(a.scientific_verdict,ScientificVerdict.NOT_APPLICABLE)

    def test_submission_rejected(self):
        a=adjudicate(self.base_event(),SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.REJECTED,
            verification_outcome=VerificationOutcome.NOT_PERFORMED
        ))
        self.assertEqual(a.failure_cause,FailureCause.SUBMISSION_REJECTED)
        self.assertEqual(a.commit_state,CommitState.NOT_COMMITTED)

class TestScientificOrthogonality(unittest.TestCase):
    def test_model_pass_plus_verified_write(self):
        e=EventFacts(
            consequential_action=True,scientific_candidate_executed=True,
            instrument_required=True,instrument_applicable=True,instrument_functioning=True,
            score_available=True,score_pass=True
        )
        s=SideEffectFacts(
            consequential=True,submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MATCH,
            expected_fingerprint="x",observed_fingerprint="x"
        )
        a=adjudicate(e,s)
        self.assertEqual(a.scientific_verdict,ScientificVerdict.PASS)
        self.assertTrue(a.model_denominator_eligible)
        self.assertEqual(a.commit_state,CommitState.COMMITTED)

    def test_model_fail_can_have_committed_side_effect(self):
        e=EventFacts(
            consequential_action=True,scientific_candidate_executed=True,
            instrument_required=True,instrument_applicable=True,instrument_functioning=True,
            score_available=True,score_pass=False
        )
        s=SideEffectFacts(
            consequential=True,submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MATCH
        )
        a=adjudicate(e,s)
        self.assertEqual(a.scientific_verdict,ScientificVerdict.FAIL)
        self.assertEqual(a.failure_cause,FailureCause.MODEL_TASK_FAILURE)
        self.assertEqual(a.commit_state,CommitState.COMMITTED)
        self.assertEqual(a.event_outcome,EventOutcome.EXECUTED_FAILURE)

class TestLiveFalsifier(unittest.TestCase):
    def test_first_bad_git_write(self):
        e=EventFacts(consequential_action=True,tool_needed=True)
        s=SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MISMATCH,
            expected_fingerprint="a0bb505276050c3398ce37000a0599bfc7174573",
            observed_fingerprint="04362447423c27481f9417d505fe0d176afe1aee"
        )
        a=adjudicate(e,s)
        self.assertEqual(a.failure_cause,FailureCause.RESULT_STATE_MISMATCH)
        self.assertEqual(a.commit_state,CommitState.NOT_COMMITTED)

    def test_repair_git_write(self):
        e=EventFacts(consequential_action=True,tool_needed=True)
        s=SideEffectFacts(
            consequential=True,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MATCH,
            expected_fingerprint="a0bb505276050c3398ce37000a0599bfc7174573",
            observed_fingerprint="a0bb505276050c3398ce37000a0599bfc7174573"
        )
        a=adjudicate(e,s)
        self.assertEqual(a.commit_state,CommitState.COMMITTED)
        self.assertEqual(a.event_outcome,EventOutcome.EXECUTED_SUCCESS)

class TestReceiptInvariants(unittest.TestCase):
    def test_unverified_cannot_validate_as_committed(self):
        r=Receipt(
            target="x",controller="R13",scientific_model=None,execution_backend="GitHub",
            operational_state=OperationalState.EXECUTE_EXTERNAL,
            event_outcome=EventOutcome.EXECUTED_SUCCESS,
            failure_cause=FailureCause.NONE,scientific_verdict=ScientificVerdict.NOT_APPLICABLE,
            model_denominator_eligible=False,contract_status=ContractStatus.NOT_NEEDED,
            commit_state=CommitState.NOT_COMMITTED,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.NOT_PERFORMED
        )
        self.assertIn("TERMINAL_SUCCESS_WITH_UNCOMMITTED_CONSEQUENTIAL_EFFECT",validate_receipt(r))

    def test_verified_receipt_valid(self):
        r=Receipt(
            target="x",controller="R13",scientific_model=None,execution_backend="GitHub",
            operational_state=OperationalState.EXECUTE_EXTERNAL,
            event_outcome=EventOutcome.EXECUTED_SUCCESS,
            failure_cause=FailureCause.NONE,scientific_verdict=ScientificVerdict.NOT_APPLICABLE,
            model_denominator_eligible=False,contract_status=ContractStatus.NOT_NEEDED,
            commit_state=CommitState.COMMITTED,
            submission_outcome=SubmissionOutcome.ACCEPTED,
            verification_outcome=VerificationOutcome.MATCH,
            expected_fingerprint="x",observed_fingerprint="x"
        )
        self.assertEqual(validate_receipt(r),())

class TestExhaustiveSideEffect(unittest.TestCase):
    def test_all_side_effect_combinations(self):
        e=EventFacts(consequential_action=True,tool_needed=True)
        for sub in SubmissionOutcome:
            if sub is SubmissionOutcome.NOT_APPLICABLE:
                continue
            for ver in VerificationOutcome:
                if ver is VerificationOutcome.NOT_APPLICABLE and sub is SubmissionOutcome.ACCEPTED:
                    pass
                for equal in [False,True]:
                    s=SideEffectFacts(
                        consequential=True,submission_outcome=sub,verification_outcome=ver,
                        expected_fingerprint="x",observed_fingerprint="x" if equal else "y"
                    )
                    a=adjudicate(e,s)
                    if a.commit_state is CommitState.COMMITTED:
                        self.assertEqual(sub,SubmissionOutcome.ACCEPTED)
                        self.assertEqual(ver,VerificationOutcome.MATCH)
                        self.assertTrue(equal)
                        self.assertEqual(a.failure_cause,FailureCause.NONE)
                    if sub is SubmissionOutcome.ACCEPTED and ver in {
                        VerificationOutcome.NOT_PERFORMED,
                        VerificationOutcome.UNAVAILABLE,
                        VerificationOutcome.NOT_APPLICABLE,
                    }:
                        self.assertNotEqual(a.commit_state,CommitState.COMMITTED)

if __name__=="__main__":
    unittest.main(verbosity=2)
