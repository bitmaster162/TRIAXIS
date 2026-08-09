# UMWP20 Weak-3B Runner Receipt

Purpose: run the external UMWP bridge on an actually small model rather than simulating a weak model with a frontier model.

Default model:
`meta-llama/llama-3.2-3b-instruct:free`

Default experiment:
- P0 Ordinary
- P1 EBRC
- 20 UMWP items per arm
- batch size 5
- 8 OpenRouter API calls total
- local native-UMWP scoring after inference
- private oracle never sent in model prompts

Optional P2 Trialectic arm is disabled by default and should be run only after P0/P1 or when a direct adversarial ablation is desired.

Local runner package SHA-256:
`53e0cf57a68625ade7677310d6aecd73ab43ae5ff84a99f7412b4b93d27e66bd`

Cost discipline:
- the runner fixes the specific `:free` model slug instead of the random free router;
- it does not launch Hugging Face Jobs or other metered compute;
- API credentials are read from `OPENROUTER_API_KEY` and are not stored in the package.
