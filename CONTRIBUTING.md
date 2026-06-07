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

## Branch naming

Format: **`<type>/<short-kebab-summary>`**, optionally with an issue number:
`<type>/<issue>-<summary>`. Lowercase, hyphen-separated, 3–5 words.

```
feat/authzen-client
fix/cache-ttl-clamp
docs/setup-guide
feat/42-batch-evaluation
```

`<type>` matches the commit types below (`feat`, `fix`, `docs`, `refactor`, `test`,
`chore`, `ci`, `perf`). Automated agent sessions may push to tool-managed branches like
`claude/<slug>-<id>` — the trailing id is intentional collision-avoidance, not a naming
choice; human-driven branches should use the convention above.

## Commit messages — [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

```
<type>(<optional scope>): <imperative summary>   # ≤72 chars, lowercase, no trailing period

<body: explain *why*, not what — wrapped at 72 cols>

<footers: e.g. "Closes #123", "BREAKING CHANGE: ...">
```

- **Types:** `feat` (new feature), `fix` (bug fix), `docs`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- **Scope** (optional) names the area, e.g. `feat(client):`, `fix(cache):`.
- **Breaking changes:** append `!` (`feat(config)!: ...`) and/or add a
  `BREAKING CHANGE:` footer.
- Imperative mood ("add", not "added"/"adds"). The subject says *what*; the body says
  *why*.

## Pull requests

- One logical change per PR; keep them small and reviewable. Open as **draft** early.
- PR **title** uses the Conventional Commits format (it usually becomes the squash-merge
  subject).
- PR **body** covers: context/why, what changed, how it was tested, and linked issues
  (`Closes #N`).
- CI must be green. Run the full check suite (see above) before pushing.
- Add or update tests for behavioural changes; update docs in the same PR.

## AI-assisted contributions

AI coding assistants are **welcome** here — many of this project's own changes are
agent-assisted. The bar is the same as for any contribution, and a few expectations keep it
useful rather than noisy:

- **You are the author of record.** By submitting, you certify you understand, have
  reviewed, and have tested the change — you can explain and stand behind every line,
  whoever (or whatever) drafted it. Signing off (`git commit -s`, see below) makes that
  explicit.
- **Same quality bar.** The full check suite must pass, behavioural changes need tests, and
  the [anti-slop guidance in `AGENTS.md`](AGENTS.md) applies: smallest change that solves
  the problem, no drive-by churn, comments that explain *why*. Unreviewed or bulk
  machine-generated PRs (mass "fix-up" sweeps, output you haven't read) will be closed.
- **Disclosure is encouraged, not required.** If an assistant did meaningful work, note it
  with a provenance trailer so reviewers know where to look — `Assisted-by:` when a human
  authored with help, `Generated-by:` when a tool produced essentially all of a change
  (e.g. `Assisted-by: <tool/model>`). The trailer names a *tool*, never an author: an
  assistant is never listed as `Signed-off-by:` or `Co-authored-by:` — the DCO sign-off and
  authorship are yours alone, and the change is attributed to you. (Don't name the assistant
  anywhere else in the commit or PR text.)
- **Agent-instruction files are security-sensitive.** Changes to `AGENTS.md`, `CLAUDE.md`,
  `.claude/**`, and the CI/release workflows are reviewed with extra scrutiny — coding agents
  treat instruction files as trusted context and a compromised workflow could leak secrets,
  so both are an injection / supply-chain surface. See [`SECURITY.md`](SECURITY.md).

Working through an agent? [`AGENTS.md`](AGENTS.md) is the canonical guide (tool-specific
files point to it), and reusable workflows live in [`.claude/skills/`](.claude/skills/).

## Licensing & sign-off

By contributing you agree your work is licensed under Apache-2.0. DCO-style sign-off is
welcome: `git commit -s`.

## Design

Read [`docs/requirements.md`](docs/requirements.md) before proposing behavioural changes —
several decisions (no fail-open, subject never from message content, ALLOW-only caching)
are deliberate security invariants, not oversights.
