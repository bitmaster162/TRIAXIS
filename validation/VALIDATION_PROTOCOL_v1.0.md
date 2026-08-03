# TRIAXIS Commit-Sealed Holdout Protocol v1.0

## Purpose

Reduce direct post-hoc fitting when the same development environment creates the candidate specification and validation assets.

## Procedure

1. Freeze the candidate specification and executable projection in Git.
2. Freeze the case bank, generator and independent oracle in Git.
3. Derive the exact holdout seed from the frozen commit binding and a batch ID.
4. Generate exact cases only after the commit exists.
5. Preserve case payload and result SHA-256 values.
6. Patch only after recording the complete failure set.
7. Re-run the patched version on all prior cases as regression.
8. Generate a new commit-bound batch for the patched version before making a new validation claim.

## Evidence classification

This protocol is **commit-sealed**, not independently blind. The same model and environment may still share conceptual blind spots across candidate, generator and oracle. A zero-failure result supports deterministic conformance only within the encoded scenario domain.

## Anti-overfitting rule

A batch used to design a patch becomes regression evidence. It cannot remain the blind validation set for the patched version. The patched version receives a fresh batch derived from its own frozen commit.
