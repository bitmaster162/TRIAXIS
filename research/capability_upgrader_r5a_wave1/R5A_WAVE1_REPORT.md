# TRIAXIS R5-A — WEAKNESS MINER — WAVE 1

## Result

Wave 1 now contains four different failure classes instead of another batch of only
olympiad-style tasks.

### F1/F8 — semantic model + exact compute
Historical clean case: AGC051 F / 2400.

Direct GPT-5.6 Sol produced a wrong reachability model. Exact symbolic verification exposed
the failure and a bounded representation change reached PASS. This remains the strongest
evidence for `D_VERIFY_EXACT`.

### F2/F5 — current real repository state drift
Repository: `bitmaster162/okx-nft-bot`.

Current source declares a shared global OKX limiter that "uses slowest rate". An
`OKXMarketplaceClient` stores the returned limiter object in its transport.

The current implementation tightens the global rate by replacing the singleton object.
An existing client therefore keeps the old object.

Executable discriminator:
- first client obtains 10 req/s limiter;
- later client requests stricter 2 req/s;
- global pointer becomes a new 2 req/s object;
- first client still references the old 10 req/s object.

This is a concrete object-identity/state-binding defect candidate:

`GLOBAL_POLICY_REPLACEMENT != EXISTING_CONSUMER_REBINDING`

Important R5 behavior: the base model found this directly and a tiny probe resolved the
claim. The router therefore **does not escalate** to a Claude/Gemini-style donor. Avoiding
unnecessary donor compute is part of capability upgrading.

No production code was changed.

### F6 — freshness
A memory-only GPT-5.6 Sol answer about current Claude Fable 5 API facts was frozen before
documentation lookup.

Material errors:
1. it guessed that Fable 5 had an opt-in 1M context;
2. it guessed a 1M beta header;
3. it generalized premium >200k long-context pricing to Fable.

Current Anthropic primary/help material checked after freeze says:
- API model id is `claude-fable-5`;
- Fable release pricing is $10/MTok input and $50/MTok output;
- Anthropic's current context-window help page says 1M is available with Sonnet 4, while
  other models are 200K+.

Fields not resolved from the checked primary material (max output and exact thinking/effort
syntax) are now marked **UNVERIFIED**, rather than filled from memory.

Effect:
`D_DOC_SKILL = MATERIAL_FRESHNESS_RESCUE`.

No Claude call occurred; this is grounding, not multi-model synergy.

### F9 — stopping
Historical Hadamard lane:
the proposed search method failed the known solved 428 warm-up, so the human-unsolved 668
target was not launched.

This is retained as a positive capability:
`D_NEGATIVE_CONTROL`.

## Wave-1 routing table

| Failure class | Base state | Smallest sufficient route |
|---|---|---|
| F1/F8 semantic/exact | wrong model | exact executable verifier + bounded representation repair |
| F2/F5 current repo state | base already finds defect | tiny executable probe, then STOP |
| F6 freshness | memory materially stale | current primary docs / skill grounding |
| F9 stopping | search instrument fails control | negative-control veto |

## What remains missing

The most important missing evidence is the actual published weak slice:

**repo-scale software engineering**.

We still need a clean case where:
- B0 direct fails;
- B1 minimal verifier also fails or stalls;
- Fable-style long-horizon/repo-behavior donor adds a verified rescue;
- B4 full router is compared against that donor under matched correction budget.

That is the next R5-A lane.

## Architecture decision

Keep:

`gap detector -> minimal router -> verifier -> bounded correction -> gate -> capability memory`

Do not promote additional TRIAXIS state unless it wins incrementally.

`DEVIL_DEFAULT=OFF`.

No main/production/trading changes.
