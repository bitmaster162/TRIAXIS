# TRIAXIS v2.7-RC1 — Release Notes

## Evidence trigger

Frozen v2.6-RC2 failed 8 of 32 P1 metamorphic cases.

## Changes

1. Added decision severity lattice: `BLOCK > HOLD/HUMAN > ALLOW_WITH_LIMITS > ALLOW`.
2. Reliance Gate no longer returns before hard blockers are evaluated.
3. Material contradiction blocks/holds a decision at any X level.
4. Toolchain, capability-evidence, checkpoint and ledger integrity are dependency-triggered at X0 as well as X>0.
5. Task nodes now declare evidence, toolchain, state and release dependencies.
