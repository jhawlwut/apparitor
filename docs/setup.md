# Setup: connecting to a policy engine

apparitor speaks the AuthZEN 1.0 Access Evaluation API, so it reaches any compliant policy
decision point (PDP). Point it at an endpoint and go:

```python
from apparitor import AuthZENScanner

scanner = AuthZENScanner(pdp_url="https://pdp.internal")
```

By default it `POST`s to `/access/v1/evaluation` (single) and `/access/v1/evaluations`
(batch). Override the paths via `ScannerConfig` if your PDP mounts them elsewhere or sits
behind a gateway.

## Installation

```bash
pip install "apparitor[llamafirewall]"   # scanner + LlamaFirewall
pip install apparitor                    # AuthZEN client/models only
```

## Authentication & TLS (bring-your-own httpx client)

For bearer tokens, mTLS, custom CA roots, or proxies, pass a pre-configured
`httpx.AsyncClient`. Secrets stay in your client and never touch message content or logs.

```python
import httpx
from apparitor import AuthZENScanner, ScannerConfig

http = httpx.AsyncClient(
    headers={"Authorization": f"Bearer {token}"},
    verify="/etc/ssl/corp-ca.pem",
)
scanner = AuthZENScanner(
    config=ScannerConfig(pdp_url="https://pdp.internal"),
    http_client=http,
)
```

> **Security:** `pdp_url` must be HTTPS and must not resolve to a private/link-local
> address unless `allow_insecure_pdp=True` (local development only). TLS verification is on
> by default. See [requirements.md §3.7](requirements.md).

## Identity: resolving the subject

The **subject** is the principal the PDP authorizes — usually the end user the agent acts
for, not the agent process. apparitor resolves it per request, in this order, and fails
closed (`AuthZENConfigError`) if none is found:

1. a `subject` in `current_request_context`,
2. the `current_subject` context variable (set it with `subject_scope`),
3. `config.agent_id` — a static fallback, mapped to `Subject(type=config.subject_type, id=agent_id)`.

Bind the authenticated user for the agent run with `subject_scope` rather than setting
`current_subject` directly — it resets the value on exit, so a subject can never leak to a
later request that reuses the same task or event loop:

```python
from apparitor import Subject, subject_scope

# In your request handler, where the user is already authenticated:
with subject_scope(Subject(type="user", id=authenticated_user_id)):
    result = await firewall.scan_async(assistant_message)
```

Attach request-scoped enrichment via `current_request_context`: `user_id`, `conversation_id`,
and `correlation_id` are forwarded to the PDP as AuthZEN `context` for policy conditions. (A
`subject` placed here is instead used to resolve the request's subject — see the order above —
not forwarded as context.) The `correlation_id` value also appears verbatim in the C1 audit
log line — see [audit-log.md](audit-log.md) for the full log schema and stability
contract.

```python
from apparitor.mapping import current_request_context

token = current_request_context.set({"user_id": "alice@acme.com", "conversation_id": "c-42"})
try:
    result = await firewall.scan_async(assistant_message)
finally:
    current_request_context.reset(token)
```

> **Security:** the subject and request context must be **host-trusted, out-of-band** data,
> established by your authentication layer — never derived from model output or a tool result.
> Deriving the principal from model output would let a prompt-injected agent choose its own
> identity (a confused deputy). See [requirements.md](requirements.md).

## Mock PDP

A tiny in-process AuthZEN PDP for tests and demos (configurable allow/deny rules, no
external services) lives in [`examples/mock_pdp/`](../examples/mock_pdp/). Start here.

## OpenFGA (Zanzibar / relationship-based)

[OpenFGA](https://openfga.dev) exposes the AuthZEN Access Evaluation API **natively**
(single and batch) as an [experimental feature](https://openfga.dev/docs/interacting/authzen)
— enable it with the AuthZEN experimental flag and pin the server version, since the API
surface may still change. Agent tool authorization maps cleanly onto OpenFGA's
`type:id` + relation model: `resource{type:"tool", id:<name>}` and an
`action`/relation like `tool_call.execute`. The worked example lives in
[`examples/openfga/`](../examples/openfga/).

## Cedar (policy-as-code)

[Cedar](https://www.cedarpolicy.com/) is reachable over AuthZEN via a gateway shim that
translates AuthZEN requests into Cedar `is_authorized` calls. The
[`examples/cedar/`](../examples/cedar/) example runs Cedar locally behind such a gateway
with sample policies.

## Amazon Verified Permissions (managed Cedar)

AVP is the managed AWS Cedar service. AWS publishes an
[open-source AuthZEN interface for AVP](https://github.com/aws-samples/sample-authzen-interface-verified-permissions)
(a Lambda translating AuthZEN ↔ AVP `IsAuthorized`). Because it needs an AWS account, it
is a later **cloud** example ([`examples/avp/`](../examples/avp/)), not part of the
local/CI set.

## Other PDPs

OPA (via [`kanywst/opa-authzen`](https://github.com/kanywst/opa-authzen)), Cerbos, and
Topaz also expose AuthZEN endpoints; any AuthZEN 1.0 PDP works. Resource and subject
**type vocabularies differ** between PDPs (OpenFGA's `type:id` relations vs Cedar
entities/actions vs OPA's free-form input) — adapt the `ToolCallMapper` to your PDP's
schema.
