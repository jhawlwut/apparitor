# Contributing

Thanks for your interest! This is an Apache-2.0, public-standards-only project. Please keep
contributions free of proprietary or confidential material.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"            # AuthZEN client/models + tooling
pip install -e ".[dev,llamafirewall]"   # add the scanner path (pulls the LlamaFirewall ML stack)
```

The `[llamafirewall]` extra is heavy (it brings PromptGuard's ML dependencies). The
AuthZEN-free modules (`models`, `client`, `adapters`, `mapping`, `cache`, `config`,
`errors`) develop and test fine **without** it.

## Checks

```bash
ruff check .            # lint
ruff format .           # format
mypy src/               # types (strict)
pytest                  # unit suite (integration excluded by default)
pytest -m integration   # integration (needs Docker; auto-skips when absent)
python -m build && twine check dist/*   # packaging
```

CI runs lint, types, the unit suite on Python 3.10–3.13, and a packaging check. The
coverage gate (≥90% line+branch on the LlamaFirewall-free modules) turns on with the
behavioural suite.

## Branching & PRs

- Develop on a feature branch; keep PRs focused.
- Match the surrounding style; add tests for behavioural changes.
- By contributing you agree your work is licensed under Apache-2.0 (DCO-style sign-off
  welcome: `git commit -s`).

## Design

Read [`docs/requirements.md`](docs/requirements.md) before proposing behavioural changes —
several decisions (no fail-open, subject never from message content, ALLOW-only caching)
are deliberate security invariants, not oversights.
