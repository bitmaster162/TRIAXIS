# TRIAXIS v2.10-RC2 — Operator Card

## New controls

```text
SEMANTIC RULESET v2
  scan USER_CONTROL only
  keep QUOTED_DATA / EXTERNAL_CONTENT as data
  disambiguate message / email / order / open

TASK GRAPH
  validate -> topological sort -> own gates
  -> dependency propagation -> completion mode -> severity
```

## Serialization invariant

The same acyclic task graph must produce the same decision and topological node receipt for every JSON node permutation. A list-order-dependent decision is a defect.

## Role boundary

| Span role | Can create action-coverage obligation? | Can mint authority? |
|---|---:|---:|
| USER_CONTROL | yes | only valid positive directive |
| QUOTED_DATA | no | no |
| EXTERNAL_CONTENT | no | no |
| SYSTEM_CONTEXT | no | no |

## Lexical backstop examples

```text
Analyze this message.          -> ANALYZE
Analyze the email headers.     -> ANALYZE
Analyze order of operations.   -> ANALYZE
Open report.pdf.               -> READ
Open a BTC position.           -> TRADE
Email Alice the report.        -> SEND
Place a limit order.           -> TRADE
```

## Limits

This scanner remains bounded. It does not establish general natural-language understanding. Ambiguity must be surfaced as clarification, bounded handling or external verification—not guessed.
