# E003 — COMMON CORPUS DEFINITION

Contains 15 test cases evaluating Rekor / in-toto transparency log integration:
* `TC01_VALID_INTOTO_REKOR_ENTRY`: Valid in-toto SLSA statement with verified Rekor SET proof -> `ALLOW`
* `TC02_TRUSTED_KEY_AUTHORIZATION`: Statement signed by trusted key -> `ALLOW`
* `TC03_TAMPERED_SUBJECT_PAYLOAD`: Modified subject digest -> `DENY (PAYLOAD_MISMATCH)`
* `TC04_INVALID_SIGNATURE`: Corrupted digital signature -> `DENY (SIGNATURE_INVALID)`
* `TC05_UNRECOGNIZED_PUBLIC_KEY`: Signed by untrusted key -> `DENY (UNTRUSTED_KEY)`
* `TC06_MALFORMED_PREDICATE`: Invalid JSON syntax -> `DENY (PREDICATE_MALFORMED)`
* `TC07_EXPIRED_ATTESTATION`: Timestamp exceeds clock skew limit -> `DENY (ATTESTATION_EXPIRED)`
* `TC08_MISSING_LOG_INCLUSION_PROOF`: Missing SET proof -> `DENY (MISSING_INCLUSION_PROOF)`
* `TC09_MERKLE_ROOT_MISMATCH`: Corrupted root hash -> `DENY (MERKLE_PROOF_INVALID)`
* `TC10_REVOKED_KEY`: Key marked as revoked -> `DENY (KEY_REVOKED)`
* `TC11_SLSA_LEVEL3_COMPLIANCE`: SLSA Level 3 verified -> `ALLOW`
* `TC12_SLSA_LEVEL_MISMATCH`: SLSA Level 1 (requires >= 3) -> `DENY (SLSA_LEVEL_INSUFFICIENT)`
* `TC13_REAL_TRANSPORT_FAILURE`: Connection refused on 127.0.0.1:8089 -> `DENY (TRANSPORT_PDP_UNAVAILABLE)`
* `TC14_REKOR_INDEX_LOOKUP_VALID`: Log index lookup succeeds -> `ALLOW`
* `TC15_REKOR_INDEX_LOOKUP_NOT_FOUND`: Log index lookup fails -> `DENY (ENTRY_NOT_FOUND)`
