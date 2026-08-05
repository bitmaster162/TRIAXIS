#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.12 external Policy Head Authority."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from tests.test_v3_12_policy_head_authority import PolicyHeadFixture
from triaxis.crypto_trust import generate_ed25519_keypair
from triaxis.policy_head_authority import PolicyHeadAuthorityError


def _observe(call):
    try:
        call()
        return "PASS"
    except PolicyHeadAuthorityError as exc:
        return exc.code


def _row(case_id: str, expected: str, observed: str, *, positive_control: bool = False) -> dict:
    return {
        "case_id": case_id,
        "expected": expected,
        "observed": observed,
        "status": "PASS" if observed == expected else "FAIL",
        "positive_control": positive_control,
    }


def run_trigger() -> dict:
    fx = PolicyHeadFixture()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Exact current head succeeds.
        with fx.store(root / "positive-authority.db") as authority_store, fx.store(root / "positive-local.db") as local_store:
            fx.install(authority_store, fx.policy1, fx.policy2)
            fx.install(local_store, fx.policy1, fx.policy2)
            with fx.service(root / "positive-responses.db", authority_store) as service:
                session, ledger, challenge = fx.challenge(root / "positive")
                with ledger:
                    signed = fx.response(service, session, challenge)
                    observed = _observe(lambda: fx.load(local_store, signed, ledger, challenge))
        rows.append(_row("EXACT_CURRENT_POLICY_HEAD", "PASS", observed, positive_control=True))

        # Whole local DB rollback is detected by the external head.
        with fx.store(root / "rollback-authority.db") as authority_store, fx.store(root / "rollback-local.db") as local_store:
            fx.install(authority_store, fx.policy1, fx.policy2)
            fx.install(local_store, fx.policy1)
            with fx.service(root / "rollback-responses.db", authority_store) as service:
                session, ledger, challenge = fx.challenge(root / "rollback")
                with ledger:
                    signed = fx.response(service, session, challenge)
                    observed = _observe(lambda: fx.load(local_store, signed, ledger, challenge))
        rows.append(_row("WHOLE_LOCAL_POLICY_DB_ROLLBACK", "local_policy_rollback", observed))

        # Same version, different digest is a fork.
        fork = fx.managed.policy(2, fx.policy1["policy_sha256"], fx.signers, 2, anchor_set_id="anchor-set:fork")
        with fx.store(root / "fork-authority.db") as authority_store, fx.store(root / "fork-local.db") as local_store:
            fx.install(authority_store, fx.policy1, fx.policy2)
            fx.install(local_store, fx.policy1, fork)
            with fx.service(root / "fork-responses.db", authority_store) as service:
                session, ledger, challenge = fx.challenge(root / "fork")
                with ledger:
                    signed = fx.response(service, session, challenge)
                    observed = _observe(lambda: fx.load(local_store, signed, ledger, challenge))
        rows.append(_row("SAME_VERSION_POLICY_FORK", "local_policy_fork", observed))

        # Forged service signature is rejected.
        attacker = generate_ed25519_keypair()
        with fx.store(root / "forged-policy.db") as store:
            fx.install(store, fx.policy1, fx.policy2)
            with fx.service(root / "forged-responses.db", store, private_key_b64=attacker["private_key_b64"]) as service:
                session, ledger, challenge = fx.challenge(root / "forged")
                with ledger:
                    signed = fx.response(service, session, challenge)
                    observed = _observe(lambda: fx.load(store, signed, ledger, challenge))
        rows.append(_row("FORGED_POLICY_HEAD_SIGNATURE", "invalid_policy_head_signature", observed))

        # A response bound to one challenge cannot answer another.
        with fx.store(root / "replay-policy.db") as store:
            fx.install(store, fx.policy1, fx.policy2)
            with fx.service(root / "replay-responses.db", store) as service:
                from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession
                session = VerifierFreshnessSession.create("verifier:policy-client", 8)
                with SQLiteEpochChallengeLedger(root / "replay-challenges.db", session) as ledger:
                    old = ledger.issue(8, 20)
                    signed = fx.response(service, session, old)
                    fresh = ledger.issue(8, 20)
                    observed = _observe(lambda: fx.load(store, signed, ledger, fresh))
        rows.append(_row("CHALLENGE_BOUND_RESPONSE_REPLAY", "policy_head_challenge_mismatch", observed))

        # Operator floor cannot be silently lowered by the local store.
        with fx.store(root / "floor-policy.db") as store:
            fx.install(store, fx.policy1, fx.policy2)
            with fx.service(root / "floor-responses.db", store) as service:
                session, ledger, challenge = fx.challenge(root / "floor")
                with ledger:
                    signed = fx.response(service, session, challenge)
                    observed = _observe(lambda: fx.load(store, signed, ledger, challenge, minimum_policy_version=3))
        rows.append(_row("OPERATOR_MINIMUM_POLICY_FLOOR", "minimum_policy_version_not_met", observed))

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_EXTERNAL_POLICY_HEAD_AUTHORITY_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.12-RC1-EXTERNAL-POLICY-HEAD-AUTHORITY",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
