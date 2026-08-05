# TRIAXIS v3.5-RC1 exact post-commit validation

Exact product identity:

- commit: `ee1dae92cdb93c02bc5f46405bd79a85fbacea7f`
- tree: `75779a120e4ec91463bfefaa4aa22876a8b52807`
- src tree: `09188da51ebee18b3a987ba9b799de4f33756369`
- tag: `TRIAXIS-v3.5-RC1-EFFECTIVE-EXPIRY`

Results:

- historical/unit suite: 191 / 191 PASS;
- assurance artifact binding: 6 / 6 PASS;
- exact action scope: 5 / 5 PASS;
- effective expiry constructor/validator trigger: 5 / 5 PASS;
- fresh post-product consumer expiry trigger: 5 / 5 PASS;
- end-to-end example: PASS;
- offline local-registry JSON Schema validation: PASS;
- exact detached worktree after cleanup: CLEAN.

The consumer trigger was created after the product commit. No product source was
changed after that trigger passed. RC2 is therefore intended as validation-only.
