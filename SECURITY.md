# Security Policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than opening a
public issue. We aim to acknowledge reports within a few business days.

## Secure-by-default posture

This is an authorization control, so the defaults are conservative:

- **Fail-closed.** On any PDP error the verdict is `BLOCK` (or `HUMAN_IN_THE_LOOP`); there
  is no global fail-open option.
- **TLS verification on** by default; the PDP URL must be HTTPS and may not be a
  private/link-local address unless explicitly opted in (`allow_insecure_pdp`, local dev).
- **Subject identity is never derived from model output** — only from trusted, request-
  scoped context. This blocks prompt-injection-driven privilege escalation.
- **Every** tool call in a message is authorized (no authorize-the-first-skip-the-rest).
- **Caching is off by default**; when enabled it caches `ALLOW` only, with a short, hard-
  capped TTL, keyed on the full request tuple (including an argument hash).
- **Secrets are never logged**; decision logs use argument fingerprints, not raw arguments.

See [`docs/requirements.md`](docs/requirements.md) for the full threat model and rationale.

## Scope

This project depends on third-party PDPs (OPA, Cerbos, …) and LlamaFirewall. Vulnerabilities
in those projects should be reported to their respective maintainers.
