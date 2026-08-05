#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.13 Policy Head Authority quorum."""
from __future__ import annotations

from contextlib import ExitStack
import json
import tempfile
from pathlib import Path

from tests.test_v3_13_policy_head_quorum import PolicyHeadQuorumFixture
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_head_quorum import make_policy_head_quorum_config
from triaxis.trust_registry_quorum import SQLiteEpochChallengeLedger, VerifierFreshnessSession


def _observe(call):
    try:
        call()
        return "PASS"
    except PolicyHeadAuthorityError as exc:
        return exc.code


def _row(case_id, expected, observed, *, positive_control=False):
    return {
        "case_id": case_id,
        "expected": expected,
        "observed": observed,
        "status": "PASS" if expected == observed else "FAIL",
        "positive_control": positive_control,
    }


def run_trigger() -> dict:
    fx = PolicyHeadQuorumFixture()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "positive", (2, 2, 2))
            local = stack.enter_context(fx.base.store(root / "positive-local.db"))
            fx.base.install(local, fx.base.policy1, fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "positive-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services[:2], session, challenge), ledger, challenge))
        rows.append(_row("TWO_OF_THREE_CURRENT_HEAD", "PASS", observed, positive_control=True))

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "one-old", (1, 2, 2))
            local = stack.enter_context(fx.base.store(root / "one-old-local.db"))
            fx.base.install(local, fx.base.policy1, fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "one-old-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services, session, challenge), ledger, challenge))
        rows.append(_row("ONE_ROLLED_BACK_AUTHORITY", "PASS", observed))

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "split", (1, 2, 1))
            local = stack.enter_context(fx.base.store(root / "split-local.db"))
            fx.base.install(local, fx.base.policy1, fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "split-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services[:2], session, challenge), ledger, challenge))
        rows.append(_row("SPLIT_VIEW_NO_THRESHOLD", "policy_head_quorum_not_met", observed))

        strict = make_policy_head_quorum_config(
            config_id="strict", authority_set_id="set", policy_id="quorum-policy:main", threshold=3,
            authorities=fx.config_rows(), minimum_policy_version=2, minimum_policy_sha256=None,
            valid_from=1, valid_until=200,
        )
        lower = make_policy_head_quorum_config(
            config_id="strict", authority_set_id="set", policy_id="quorum-policy:main", threshold=2,
            authorities=fx.config_rows(), minimum_policy_version=1, minimum_policy_sha256=None,
            valid_from=1, valid_until=200,
        )
        with ExitStack() as stack:
            services = fx.open_services(stack, root / "config", (2, 2, 2))
            local = stack.enter_context(fx.base.store(root / "config-local.db"))
            fx.base.install(local, fx.base.policy1, fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "config-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(
                local, fx.responses(services[:2], session, challenge), ledger, challenge,
                config=lower, expected_digest=strict["config_sha256"],
            ))
        rows.append(_row("PINNED_CONFIG_DOWNGRADE", "policy_head_quorum_config_substitution", observed))

        with ExitStack() as stack:
            local = stack.enter_context(fx.base.store(root / "equivocation-local.db"))
            fx.base.install(local, fx.base.policy1, fx.base.policy2)
            session = VerifierFreshnessSession.create("verifier:q", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "equivocation-challenges.db", session))
            challenge = ledger.issue(8, 20)
            responses = [
                fx.signed_view(0, fx.base.policy1, session, challenge),
                fx.signed_view(0, fx.base.policy2, session, challenge),
                fx.signed_view(1, fx.base.policy2, session, challenge),
            ]
            observed = _observe(lambda: fx.load(local, responses, ledger, challenge))
        rows.append(_row("SINGLE_SIGNER_EQUIVOCATION", "policy_head_signer_equivocation", observed))

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_POLICY_HEAD_AUTHORITY_QUORUM_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.13-RC1-POLICY-HEAD-AUTHORITY-QUORUM",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
