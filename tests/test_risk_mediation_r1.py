from copy import deepcopy

import pytest

from triaxis.integrity import seal_mapping, verify_sealed_mapping
from triaxis.risk_authority import (
    CriticalDomain,
    EffectScope,
    Reversibility,
    RiskFacts,
)
from triaxis.risk_mediation import (
    RiskFactObservation,
    RiskMediatedAuthorizationBoundary,
    RiskMediationError,
    TrustedRiskFactsAdapterRegistry,
    risk_subject_sha256,
)


def action(risk="R2"):
    return {
        "subject_id": "subject-1",
        "object_id": "object-1",
        "capability": "execute_capability",
        "tool_id": "tool.write",
        "execution_target": "target://one",
        "payload_sha256": "a" * 64,
        "state_witness": {"witness_sha256": "b" * 64},
        "risk_class": risk,
    }


class Adapter:
    adapter_id = "effects-r1"
    adapter_version = 1

    def __init__(self, facts, *, forced_subject=None, fail=False, malformed=False):
        self.facts = facts
        self.forced_subject = forced_subject
        self.fail = fail
        self.malformed = malformed

    def observe_risk_facts(self, value):
        if self.fail:
            raise RuntimeError("adapter unavailable")
        if self.malformed:
            return {"facts": self.facts}
        return RiskFactObservation(
            self.adapter_id,
            self.adapter_version,
            self.forced_subject or risk_subject_sha256(value),
            self.facts,
        )


class Authorizer:
    def __init__(self, *, risk_override=None, omit_digest=False, target_override=None):
        self.calls = []
        self.risk_override = risk_override
        self.omit_digest = omit_digest
        self.target_override = target_override

    def __call__(self, value, *args, **kwargs):
        self.calls.append((deepcopy(value), args, kwargs))
        token = {
            "subject_id": value["subject_id"],
            "object_id": value["object_id"],
            "capability": value["capability"],
            "tool_id": value["tool_id"],
            "execution_target": self.target_override or value["execution_target"],
            "payload_sha256": value["payload_sha256"],
            "state_witness_sha256": value["state_witness"]["witness_sha256"],
            "risk_class": self.risk_override or value["risk_class"],
            "outcome": "ALLOW",
            "token_sha256": "",
        }
        if self.omit_digest:
            token.pop("token_sha256")
            return token
        return seal_mapping(token, "token_sha256")


def boundary(adapter, authorizer, *, registry_adapter=None):
    trusted = adapter if registry_adapter is None else registry_adapter
    registry = TrustedRiskFactsAdapterRegistry({"effects-r1": (1, trusted)})
    return RiskMediatedAuthorizationBoundary(
        authorizer=authorizer,
        risk_adapter=adapter,
        trusted_registry=registry,
        adapter_id="effects-r1",
        adapter_version=1,
    )


def test_trusted_equal_risk_delegates_once_and_seals_receipt():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer()
    result = boundary(adapter, authorizer).authorize(action("R2"), "policy", tick=7)
    assert len(authorizer.calls) == 1
    assert authorizer.calls[0][1] == ("policy",)
    assert authorizer.calls[0][2] == {"tick": 7}
    assert result.risk_assessment.derived_risk == "R2"
    assert result.risk_assessment.effective_risk == "R2"
    assert result.authorization["risk_class"] == "R2"
    assert verify_sealed_mapping(result.risk_mediation_receipt, "receipt_sha256")
    assert result.risk_mediation_receipt["authorization_token_sha256"] == result.authorization["token_sha256"]


def test_caller_overclassification_is_preserved_not_lowered():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer()
    result = boundary(adapter, authorizer).authorize(action("R4"))
    assert result.risk_assessment.derived_risk == "R2"
    assert result.risk_assessment.effective_risk == "R4"
    assert result.authorization["risk_class"] == "R4"


def test_caller_downgrade_blocks_before_authorizer():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.IRREVERSIBLE))
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "RISK_DOWNGRADE_BLOCKED"
    assert authorizer.calls == []


def test_critical_domain_r4_cannot_be_claimed_r3():
    adapter = Adapter(
        RiskFacts(
            EffectScope.EXTERNAL,
            Reversibility.REVERSIBLE,
            frozenset({CriticalDomain.TRADING}),
        )
    )
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R3"))
    assert exc.value.code == "RISK_DOWNGRADE_BLOCKED"
    assert authorizer.calls == []


def test_untrusted_same_id_version_adapter_is_rejected_by_instance_identity():
    trusted = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    attacker = Adapter(RiskFacts(EffectScope.NONE, Reversibility.NOT_APPLICABLE))
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(attacker, authorizer, registry_adapter=trusted).authorize(action("R2"))
    assert exc.value.code == "UNTRUSTED_RISK_FACT_ADAPTER"
    assert authorizer.calls == []


def test_stale_or_cross_action_observation_is_rejected():
    adapter = Adapter(
        RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE),
        forced_subject="0" * 64,
    )
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "RISK_FACT_SUBJECT_MISMATCH"
    assert authorizer.calls == []


class MutatingAdapter(Adapter):
    def observe_risk_facts(self, value):
        value["execution_target"] = "target://mutated"
        return RiskFactObservation(
            self.adapter_id,
            self.adapter_version,
            risk_subject_sha256(value),
            self.facts,
        )


def test_adapter_cannot_mutate_action_seen_by_authorizer():
    adapter = MutatingAdapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "RISK_FACT_SUBJECT_MISMATCH"
    assert authorizer.calls == []


def test_adapter_failure_fails_closed_before_authorizer():
    adapter = Adapter(
        RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE),
        fail=True,
    )
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "RISK_FACT_ADAPTER_FAILURE"
    assert authorizer.calls == []


def test_malformed_adapter_result_fails_closed():
    adapter = Adapter(
        RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE),
        malformed=True,
    )
    authorizer = Authorizer()
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "INVALID_RISK_FACT_OBSERVATION"
    assert authorizer.calls == []


def test_authorizer_cannot_return_token_bound_to_different_effect_subject():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer(target_override="target://attacker")
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "AUTHORIZATION_EFFECT_BINDING_MISMATCH"
    assert len(authorizer.calls) == 1


def test_authorizer_cannot_return_token_bound_to_different_risk():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer(risk_override="R1")
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "AUTHORIZATION_RISK_BINDING_MISMATCH"
    assert len(authorizer.calls) == 1


def test_authorization_token_digest_is_required_for_chain_binding():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer(omit_digest=True)
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(action("R2"))
    assert exc.value.code == "AUTHORIZATION_TOKEN_DIGEST_MISSING"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tool_id", "tool.other"),
        ("execution_target", "target://two"),
        ("payload_sha256", "c" * 64),
    ],
)
def test_effect_substitution_changes_risk_subject(field, replacement):
    base = action("R2")
    changed = deepcopy(base)
    changed[field] = replacement
    assert risk_subject_sha256(base) != risk_subject_sha256(changed)


def test_state_witness_substitution_changes_risk_subject():
    base = action("R2")
    changed = deepcopy(base)
    changed["state_witness"]["witness_sha256"] = "d" * 64
    assert risk_subject_sha256(base) != risk_subject_sha256(changed)


def test_risk_class_is_excluded_from_subject_to_prevent_caller_claim_from_driving_facts():
    low = action("R1")
    high = action("R4")
    assert risk_subject_sha256(low) == risk_subject_sha256(high)


def test_input_action_is_not_mutated():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer()
    original = action("R2")
    before = deepcopy(original)
    boundary(adapter, authorizer).authorize(original)
    assert original == before


def test_missing_risk_class_blocks_before_authorizer():
    adapter = Adapter(RiskFacts(EffectScope.EXTERNAL, Reversibility.REVERSIBLE))
    authorizer = Authorizer()
    value = action("R2")
    del value["risk_class"]
    with pytest.raises(RiskMediationError) as exc:
        boundary(adapter, authorizer).authorize(value)
    assert exc.value.code == "RISK_CLASS_REQUIRED"
    assert authorizer.calls == []
