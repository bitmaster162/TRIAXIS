#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.14 Policy Transparency Floor."""
from __future__ import annotations

from contextlib import ExitStack
import json
import tempfile
from pathlib import Path

from tests.test_v3_14_policy_transparency_floor import PolicyTransparencyFloorFixture
from triaxis.policy_head_authority import PolicyHeadAuthorityError
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
    fx = PolicyTransparencyFloorFixture()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "positive", (2, 2, 2))
            local = stack.enter_context(fx.store(root / "positive-local.db"))
            fx.install(local, 2)
            session = VerifierFreshnessSession.create("verifier:floor", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "positive-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services[:2], session, challenge), ledger, challenge))
        rows.append(_row("TWO_OF_THREE_CURRENT_FLOOR", "PASS", observed, positive_control=True))

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "rollback", (2, 2, 2))
            local = stack.enter_context(fx.store(root / "rollback-local.db"))
            fx.install(local, 1)
            session = VerifierFreshnessSession.create("verifier:floor", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "rollback-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services[:2], session, challenge), ledger, challenge))
        rows.append(_row("ROLLED_BACK_HEAD_AND_LOCAL", "policy_below_transparency_floor", observed))

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "one-stale", (1, 2, 2))
            local = stack.enter_context(fx.store(root / "one-stale-local.db"))
            fx.install(local, 2)
            session = VerifierFreshnessSession.create("verifier:floor", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "one-stale-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services, session, challenge), ledger, challenge))
        rows.append(_row("ONE_STALE_WITNESS", "PASS", observed))

        with ExitStack() as stack:
            services = fx.open_services(stack, root / "split", (1, 2, 1))
            local = stack.enter_context(fx.store(root / "split-local.db"))
            fx.install(local, 2)
            session = VerifierFreshnessSession.create("verifier:floor", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "split-challenges.db", session))
            challenge = ledger.issue(8, 20)
            observed = _observe(lambda: fx.load(local, fx.responses(services[:2], session, challenge), ledger, challenge))
        rows.append(_row("SPLIT_FLOOR_NO_THRESHOLD", "transparency_floor_quorum_not_met", observed))

        with ExitStack() as stack:
            local = stack.enter_context(fx.store(root / "equivocation-local.db"))
            fx.install(local, 2)
            session = VerifierFreshnessSession.create("verifier:floor", 8)
            ledger = stack.enter_context(SQLiteEpochChallengeLedger(root / "equivocation-challenges.db", session))
            challenge = ledger.issue(8, 20)
            responses = [
                fx.signed_view(0, fx.policy1, session, challenge),
                fx.signed_view(0, fx.policy2, session, challenge),
                fx.signed_view(1, fx.policy2, session, challenge),
            ]
            observed = _observe(lambda: fx.load(local, responses, ledger, challenge))
        rows.append(_row("WITNESS_EQUIVOCATION", "transparency_witness_equivocation", observed))

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_POLICY_TRANSPARENCY_FLOOR_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.14-RC1-POLICY-TRANSPARENCY-FLOOR",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
