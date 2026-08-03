# TRIAXIS Composition/State Report — 2.9-RC1

- Cases SHA-256: `19301108d9af348df6e6f43e6da11dcbf23d58e9b2befc2edfb3e5f78ad3f261`
- Results SHA-256: `3af716c958b9c4f89ee2488bb7b549e1394891cd0f837d0d82ffd9500a4126a1`
- PASS: **12**
- FAIL: **9**

## Family summary

| Family | PASS | FAIL |
|---|---:|---:|
| completion | 3 | 0 |
| graph_order | 1 | 2 |
| imperative_positive | 4 | 0 |
| integrity | 2 | 0 |
| lexical_ambiguity | 0 | 4 |
| role_separation | 0 | 3 |
| severity | 2 | 0 |

## Failures

### C-003 — open_position_is_trade

- Family: `lexical_ambiguity`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-004 — quoted_delete_is_data

- Family: `role_separation`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-006 — direct_send_with_quoted_delete

- Family: `role_separation`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-010 — message_as_noun

- Family: `lexical_ambiguity`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-011 — order_as_sequence

- Family: `lexical_ambiguity`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-012 — graph_reverse_order_allow

- Family: `graph_order`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_DEPENDENCY`

### C-013 — email_as_noun

- Family: `lexical_ambiguity`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-017 — external_send_is_data

- Family: `role_separation`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_SEMANTIC_INGRESS`

### C-020 — graph_reverse_transitive_allow

- Family: `graph_order`
- Expected: `ALLOW / CONDITIONS_SATISFIED`
- Observed: `BLOCK / BLOCKED_BY_DEPENDENCY`

