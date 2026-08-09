# NeuroState-Bench compatibility adapter v0.1

Do not rewrite NeuroState tasks. Wrap model calls only.

## Arms
- NS-P0: repository/default agent prompt.
- NS-P1: EBRC state record before final commitment.
- NS-P2: Trialectic EBRC with one action-changing countermodel.
- NS-P3: WMX compact state ledger, when wrapper access permits history/state compression.

## Mapping
NeuroState's outcome score remains native.
NeuroState commitment-integrity/probe scores remain native.

Our diagnostic fields may be logged alongside:
- epistemic_state
- closure_class
- minimal_witness
- reopen_trigger
- selected discriminator/tool

The hypothesis is not necessarily higher task success. It is lower divergence between final action, side-query probes and persistent commitment state under distractors.
