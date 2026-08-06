#!/usr/bin/env python3
"""Closure trigger for TRIAXIS v3.15 persistent transparency gossip."""
from __future__ import annotations

from contextlib import ExitStack
import json
import tempfile
from pathlib import Path

from tests.test_v3_14_policy_transparency_floor import HEAD_CONFIG_SHA256, PolicyTransparencyFloorFixture
from triaxis.policy_head_authority import PolicyHeadAuthorityError
from triaxis.policy_transparency_floor import (
    SQLitePolicyTransparencyGossipStore,
    enforce_policy_transparency_floor_quorum_with_gossip,
)
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


def _load(fx, local, responses, ledger, challenge, gossip):
    return enforce_policy_transparency_floor_quorum_with_gossip(
        local,
        responses,
        gossip_store=gossip,
        witness_registry=fx.registry,
        floor_quorum_config=fx.config,
        expected_floor_config_sha256=fx.config["config_sha256"],
        expected_policy_head_quorum_config_sha256=HEAD_CONFIG_SHA256,
        challenge_ledger=ledger,
        expected_challenge=challenge,
        evaluation_tick=9,
    )


def run_trigger() -> dict:
    fx = PolicyTransparencyFloorFixture()
    rows = []
    with tempfile.TemporaryDirectory() as tmp, ExitStack() as stack:
        root = Path(tmp)
        gossip = stack.enter_context(SQLitePolicyTransparencyGossipStore(root / "gossip.db"))

        local2 = stack.enter_context(fx.store(root / "positive-local.db")); fx.install(local2, 2)
        s0 = VerifierFreshnessSession.create("verifier:positive", 8)
        l0 = stack.enter_context(SQLiteEpochChallengeLedger(root / "positive-c.db", s0)); c0 = l0.issue(8, 20)
        observed = _observe(lambda: _load(fx, local2, [fx.signed_view(0, fx.policy2, s0, c0), fx.signed_view(1, fx.policy2, s0, c0)], l0, c0, gossip))
        rows.append(_row("INITIAL_FLOOR_PIN", "PASS", observed, positive_control=True))

        local3 = stack.enter_context(fx.store(root / "higher-local.db")); fx.install(local3, 3)
        s1 = VerifierFreshnessSession.create("verifier:higher", 8)
        l1 = stack.enter_context(SQLiteEpochChallengeLedger(root / "higher-c.db", s1)); c1 = l1.issue(8, 20)
        observed = _observe(lambda: _load(fx, local3, [fx.signed_view(0, fx.policy3, s1, c1), fx.signed_view(1, fx.policy3, s1, c1)], l1, c1, gossip))
        rows.append(_row("MONOTONIC_ADVANCE", "PASS", observed))

        local2b = stack.enter_context(fx.store(root / "rollback-local.db")); fx.install(local2b, 2)
        s2 = VerifierFreshnessSession.create("verifier:rollback", 8)
        l2 = stack.enter_context(SQLiteEpochChallengeLedger(root / "rollback-c.db", s2)); c2 = l2.issue(8, 20)
        observed = _observe(lambda: _load(fx, local2b, [fx.signed_view(0, fx.policy2, s2, c2), fx.signed_view(2, fx.policy2, s2, c2)], l2, c2, gossip))
        rows.append(_row("CROSS_SESSION_ROLLBACK", "transparency_witness_rollback_detected", observed))

        fork = fx.managed.policy(3, fx.policy2["policy_sha256"], fx.signers, 2, anchor_set_id="anchor-set:gossip-fork")
        s3 = VerifierFreshnessSession.create("verifier:fork", 8)
        l3 = stack.enter_context(SQLiteEpochChallengeLedger(root / "fork-c.db", s3)); c3 = l3.issue(8, 20)
        observed = _observe(lambda: _load(fx, local3, [fx.signed_view(0, fork, s3, c3), fx.signed_view(2, fork, s3, c3)], l3, c3, gossip))
        rows.append(_row("CROSS_SESSION_FORK", "transparency_witness_fork_detected", observed))

    passed = sum(row["status"] == "PASS" for row in rows)
    return {
        "contract_id": "TRIAXIS_POLICY_TRANSPARENCY_GOSSIP_TRIGGER_RESULT_v1",
        "target": "TRIAXIS-v3.15-RC1-POLICY-TRANSPARENCY-GOSSIP",
        "status": "PASS" if passed == len(rows) else "FAIL",
        "case_count": len(rows),
        "pass_count": passed,
        "rows": rows,
    }


if __name__ == "__main__":
    print(json.dumps(run_trigger(), sort_keys=True, indent=2))
