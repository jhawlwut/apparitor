<!--
PR title must follow Conventional Commits, e.g. "feat(client): add bounded retry".
See CONTRIBUTING.md and AGENTS.md.
-->

## What & why

<!-- The problem this solves and the approach taken. Lead with context. -->

## Changes

-

## How tested

<!-- Commands run and/or scenarios exercised. Paste relevant output. -->

## Linked issues

Closes #

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
- [ ] `ruff check . && ruff format --check . && mypy src/ && pytest` all pass locally
- [ ] Tests added/updated for behavioural changes
- [ ] Docs updated (`docs/`, README) where relevant
- [ ] No secrets committed; security & layering invariants preserved (see `AGENTS.md`, `SECURITY.md`)

<!-- Optional: if an AI assistant did meaningful work, an "Assisted-by:"/"Generated-by:"
     commit trailer helps reviewers — see CONTRIBUTING.md. Not required. -->
