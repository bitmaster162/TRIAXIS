# TRIAXIS v2.10-RC1 — Release Notes

## Trigger evidence

After v2.9-RC1 logic commit `a8d07b121b51a17af2a7060a3c95cdf9f8ffc435`, a new frozen Composition/State Protocol v1.0 was committed as `4bc66dd4614017544023d67316cefec7efab726b`.

Commit-bound CS1 result for v2.9-RC1:

```text
PASS 12 / FAIL 9 / TOTAL 21
Cases SHA-256:
19301108d9af348df6e6f43e6da11dcbf23d58e9b2befc2edfb3e5f78ad3f261
Results SHA-256:
3af716c958b9c4f89ee2488bb7b549e1394891cd0f837d0d82ffd9500a4126a1
```

Root causes:

1. Dependency resolution followed node serialization order.
2. Explicit scanner scanned the whole source, including quoted/external data.
3. Bare nouns `message`, `email`, `order` caused false SEND/TRADE surfaces.
4. `open position` was misread as READ instead of TRADE.

## Logic changes

- Semantic Ruleset v2 scans `USER_CONTROL` spans only.
- Contextual lexical patterns replace high-noise bare nouns.
- Task graph is evaluated in stable topological order.
- Dependency blockers propagate after own-node evaluation.
- Historical v2.9 behavior remains reproducible under Ruleset v1 and list-order projection.

## Development verification

```text
Composition/State full bank: 21/21 PASS
Routing full bank:           53/53 PASS
Semantic ingress full bank:  37/37 PASS
3-node graph permutations:    6/6 invariant
```

Fresh commit-bound v2.10 validation is required before RC2.
