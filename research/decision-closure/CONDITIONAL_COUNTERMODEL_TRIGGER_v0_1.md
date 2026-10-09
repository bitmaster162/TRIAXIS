# Conditional Countermodel Trigger v0.1

## Status

`PREREGISTERED_AND_PROSPECTIVELY_TESTED_ON_INTERVENEBENCH_BATCH3`

This rule replaces default adversarial/persona execution.

## Trigger

Invoke exactly one countermodel only if **all** conditions hold:

1. The leading decision/model depends on at least one material identification or applicability assumption that is not directly established by supplied evidence.
2. A concrete alternative mechanism/design is plausible under the supplied evidence.
3. The alternative would change the selected action/model, not merely wording or confidence.
4. No direct discriminator already settles the choice, such as an explicit cutoff, assignment rule, untreated comparison, valid instrument, or authoritative semantic binding.

If any condition is false: **do not run DEVIL**.

## Output

When triggered, return only:

- one action-changing alternative;
- the single load-bearing assumption or discriminator separating it from the leading model;
- resulting action/model if the alternative survives.

Then commit or request one discriminator and stop.

## Forbidden

- generic skepticism;
- alternatives that imply the same action;
- countermodels already contradicted by direct evidence;
- repeated adversarial rounds;
- majority vote / persona consensus.

## Empirical origin

Exploratory InterveneBench cases showed both rescues and harm from unrestricted one-countermodel reasoning. In particular, the countermodel rescued self-selection/endogeneity cases but incorrectly displaced a valid New Budget Law DiD design.

This trigger was therefore frozen before a fresh 10-case InterveneBench batch.

Prospective batch result:

- V2 Active Control: 8/10
- Triggered V3: 10/10
- two action changes, both verified rescues
- zero harms

Because the batch is small and the same GPT-5.6 Sol session produced both arms, this remains candidate evidence rather than an independent superiority claim.

## Kill rule

Keep DEVIL disabled by default unless future independent runs show net positive verified rescues over harms under a frozen trigger and matched budget.

Governance:

`TRIAXIS_IS_CONTESTANT=true`
`TRIAXIS_IS_ORACLE=false`
`PRODUCTION_CHANGE=false`
`AUTO_MERGE=false`
`MERGE_PERMISSION=DENY`
