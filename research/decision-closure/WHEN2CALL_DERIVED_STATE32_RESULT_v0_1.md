# When2Call-derived State-32 — AVR Mechanism Result v0.1

This is a generator-faithful **derived mechanism test**, not an official NVIDIA When2Call benchmark score.

Category semantics follow NVIDIA When2Call's released evaluation-generation logic:
- `direct`: current information is sufficient without a tool;
- `tool_call`: matching tool is available and required inputs are present;
- `request_for_info`: matching tool exists but a required input is missing;
- `cannot_answer`: the needed capability is unavailable.

Predictions were frozen before the private derived oracle was opened.

## Result

| Arm | Accuracy |
|---|---:|
| B0 naive tool-centric | 16/32 = 50% |
| A1 AVR four-state gate | 32/32 = 100% |

Absolute lift: **+50 pp**.

The naive policy had only two states: if a semantically matching tool exists, call it; otherwise cannot-answer. It therefore failed all `direct` and all `request_for_info` cases.

AVR gate:

```text
INTERNALLY SUFFICIENT?
├─ YES → DIRECT
└─ NO
   ↓
MATCHING CAPABILITY AVAILABLE?
├─ NO → CANNOT_ANSWER
└─ YES
   ↓
ALL REQUIRED INPUTS PRESENT?
├─ NO → REQUEST_FOR_INFO
└─ YES → TOOL_CALL
```

## Claim boundary

- Cases were generated in-session using the official category-construction semantics, not sampled from the official 19.5 MB evaluation JSONL.
- Same model authored templates and classified them, though oracle labels were hidden until prediction freeze.
- Do not report 32/32 as an NVIDIA When2Call benchmark score.

Supported mechanism claim: the four-state control decomposition prevents two systematic errors that a binary tool/no-tool policy cannot represent.
