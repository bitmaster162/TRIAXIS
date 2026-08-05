# TRIAXIS Research Assurance MVP — PRD

## Problem

Deep Research reports can be long and persuasive while containing unsupported numbers, correlated sources, citation mismatch, stale facts and hidden contradictions. Reading several reports manually does not produce a defensible decision.

## MVP

Upload 2–5 research reports and receive:

1. claim register;
2. source register;
3. agreement/contradiction matrix;
4. unsupported-number register;
5. evidence correlation map;
6. load-bearing claims and defeaters;
7. falsification experiments;
8. `ADOPT / REJECT / EXPERIMENT / UNKNOWN` decision table;
9. one-page Decision Assurance Receipt.

## Non-goals

- proving semantic truth solely from model output;
- automatic high-risk execution;
- novelty certification;
- majority voting.

## Architecture

- document ingestion;
- claim extraction;
- Evidence Broker;
- independent retrieval lanes;
- adjudication compiler;
- human review UI;
- signed/digest-sealed export.

## Success metrics

- critical unsupported-claim recall/precision;
- source-correlation detection;
- human review time;
- decision changes caused by detected defects;
- false alarm rate;
- willingness to pay.
