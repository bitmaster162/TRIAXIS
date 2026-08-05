# TRIAXIS Gap Register v3.8

## Closed

- restoration of an older local registry database while a current external witness is supplied;
- equal-sequence local fork against the external digest;
- accepting a local head newer than a stale external witness;
- forged or wrong-domain anchor signer;
- expired external witness.

## P0 remaining

1. Replay of an older but unexpired witness together with matching rolled-back local state.
2. Challenge-bound or online authoritative anchor freshness.
3. Anchor-service equivocation and transparency.
4. Threshold/multi-provider anchors.
5. KMS/HSM key custody.
6. Complete mediation at the physical executor.
7. Signed external execution receipts.
