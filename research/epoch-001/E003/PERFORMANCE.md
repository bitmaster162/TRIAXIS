# E003 — PERFORMANCE METRICS

* **ECDSA Signature Verification Latency**: ~0.45 ms per statement.
* **in-toto Statement Formatting & Hashing**: ~0.12 ms per payload.
* **Local Rekor Proof Validation**: ~0.25 ms per SET verification.
* **Remote Rekor Inclusion Lookup (Network Latency)**: ~45–120 ms (Async build/release pipeline only; NOT on authorization hot path).

**Recommendation**: Verification of Rekor transparency proofs must occur during asynchronous deployment/ingress gates or policy loading, avoiding hot-path request evaluation delays.
