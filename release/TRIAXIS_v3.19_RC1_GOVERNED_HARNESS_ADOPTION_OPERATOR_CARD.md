# TRIAXIS v3.19-RC1 Operator Card

## Verify

```bash
TERM=xterm PYTHONPATH=src:. python -m unittest discover -s tests -q
TERM=xterm PYTHONPATH=src:. python validation/harness_adoption/run_v319_grok_build_adoption_trigger.py \
  --output /tmp/TRIAXIS_v3.19_GROK_BUILD_ADOPTION_TRIGGER.json
```

## Interpret

- Unit-test PASS proves regression only.
- Trigger PASS proves the frozen harness-adoption cases only.
- Neither result authorizes deployment or side effects.

## Non-negotiable rules

- never enable whole-repository upload;
- never activate an unpinned plugin;
- never allow a hook or subagent to widen authority;
- write subagents require worktrees;
- execute subagents require approved sandboxes;
- side-effecting tools require the exact TRIAXIS authorization token;
- ACP-style adapter cannot directly execute tools;
- treat actual content materialization as a separate trust boundary.
