from __future__ import annotations

from copy import deepcopy
import unittest

from triaxis.evidence_broker import (
    CLAIM_RECORD_CONTRACT_ID,
    EVIDENCE_PACKAGE_CONTRACT_ID,
    SOURCE_RECORD_CONTRACT_ID,
    seal_contract,
    validate_evidence_package,
)


def source(
    source_id: str,
    *,
    group: str,
    digest_char: str,
    polarity: str = "SUPPORTS",
    source_type: str = "PRIMARY_SOURCE",
    attestation: str = "AUTHENTICATED",
    subject: str = "subject:1",
    observed_at: int = 5,
    valid_until: int | None = 10,
    upstream: list[str] | None = None,
):
    return seal_contract(
        {
            "contract_id": SOURCE_RECORD_CONTRACT_ID,
            "source_id": source_id,
            "subject_id": subject,
            "source_group": group,
            "publisher_id": f"publisher:{group}",
            "source_type": source_type,
            "polarity": polarity,
            "attestation_level": attestation,
            "content_sha256": digest_char * 64,
            "observed_at": observed_at,
            "valid_until": valid_until,
            "upstream_ids": [] if upstream is None else upstream,
            "source_sha256": "",
        },
        "source_sha256",
    )


def claim(
    claim_id: str = "C1",
    *,
    evidence_ids: list[str] | None = None,
    required_groups: int = 2,
    authoritative: bool = False,
    required_attestation: str = "AUTHENTICATED",
    load_bearing: bool = True,
    subject: str = "subject:1",
):
    return seal_contract(
        {
            "contract_id": CLAIM_RECORD_CONTRACT_ID,
            "claim_id": claim_id,
            "subject_id": subject,
            "claim_kind": "FACTUAL",
            "load_bearing": load_bearing,
            "required_independent_groups": required_groups,
            "required_attestation": required_attestation,
            "requires_authoritative_adapter": authoritative,
            "evidence_ids": ["E1", "E2"] if evidence_ids is None else evidence_ids,
            "claim_sha256": "",
        },
        "claim_sha256",
    )


def package(sources=None, claims=None, tick: int = 6):
    return seal_contract(
        {
            "contract_id": EVIDENCE_PACKAGE_CONTRACT_ID,
            "evaluation_tick": tick,
            "sources": sources
            if sources is not None
            else [source("E1", group="g1", digest_char="a"), source("E2", group="g2", digest_char="b")],
            "claims": claims if claims is not None else [claim()],
            "package_sha256": "",
        },
        "package_sha256",
    )


class EvidenceBrokerTests(unittest.TestCase):
    def test_two_independent_sources_verify(self):
        result = validate_evidence_package(package())
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "VERIFIED")

    def test_identical_content_is_correlated_even_with_different_labels(self):
        p = package(
            sources=[source("E1", group="g1", digest_char="a"), source("E2", group="g2", digest_char="a")]
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["status"], "ESCALATE", result)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "CORRELATED")

    def test_shared_upstream_is_correlated(self):
        p = package(
            sources=[
                source("E1", group="g1", digest_char="a", upstream=["origin:x"]),
                source("E2", group="g2", digest_char="b", upstream=["origin:x"]),
            ]
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "CORRELATED")

    def test_stale_support_escalates(self):
        p = package(
            sources=[
                source("E1", group="g1", digest_char="a", valid_until=6),
                source("E2", group="g2", digest_char="b", valid_until=6),
            ]
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "STALE")

    def test_future_dated_evidence_escalates(self):
        p = package(
            sources=[
                source("E1", group="g1", digest_char="a", observed_at=7),
                source("E2", group="g2", digest_char="b", observed_at=7),
            ]
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "FUTURE_DATED")

    def test_subject_substitution_blocks(self):
        p = package(
            sources=[
                source("E1", group="g1", digest_char="a", subject="subject:other"),
                source("E2", group="g2", digest_char="b"),
            ]
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("evidence_subject_mismatch", {item["code"] for item in result["errors"]})

    def test_authoritative_fact_requires_adapter(self):
        p = package(claims=[claim(authoritative=True, required_groups=1, evidence_ids=["E1"])])
        result = validate_evidence_package(p)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "UNVERIFIED_AUTHORITY")

    def test_authenticated_authoritative_adapter_verifies(self):
        p = package(
            sources=[
                source(
                    "E1",
                    group="authority",
                    digest_char="a",
                    source_type="AUTHORITATIVE_ADAPTER",
                    attestation="HARDWARE_ROOTED",
                )
            ],
            claims=[claim(authoritative=True, required_groups=1, evidence_ids=["E1"], required_attestation="AUTHENTICATED")],
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["status"], "PASS", result)

    def test_support_and_contradiction_is_contested(self):
        p = package(
            sources=[
                source("E1", group="g1", digest_char="a"),
                source("E2", group="g2", digest_char="b", polarity="CONTRADICTS"),
            ]
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "CONTESTED")

    def test_only_contradiction_refutes(self):
        p = package(
            sources=[source("E1", group="g1", digest_char="a", polarity="CONTRADICTS")],
            claims=[claim(evidence_ids=["E1"], required_groups=1)],
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "REFUTED")

    def test_non_load_bearing_unknown_does_not_block_package(self):
        p = package(
            sources=[],
            claims=[claim(evidence_ids=[], required_groups=1, load_bearing=False)],
        )
        result = validate_evidence_package(p)
        self.assertEqual(result["status"], "PASS", result)
        self.assertEqual(result["report"]["claim_results"][0]["status"], "UNVERIFIED")

    def test_unknown_evidence_reference_blocks(self):
        p = package(claims=[claim(evidence_ids=["missing"], required_groups=1)])
        result = validate_evidence_package(p)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("unknown_evidence", {item["code"] for item in result["errors"]})

    def test_nested_digest_tamper_blocks(self):
        p = package()
        p = deepcopy(p)
        p["sources"][0]["publisher_id"] = "tampered"
        p = seal_contract(p, "package_sha256")
        result = validate_evidence_package(p)
        self.assertEqual(result["status"], "BLOCK")
        self.assertIn("digest_mismatch", {item["code"] for item in result["errors"]})


if __name__ == "__main__":
    unittest.main()
