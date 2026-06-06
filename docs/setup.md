# Setup: connecting to a PDP

The scanner speaks the AuthZEN 1.0 Access Evaluation API, so it works with any compliant
PDP. Point it at an endpoint and go:

```python
from authzen_llamafirewall import AuthZENScanner

scanner = AuthZENScanner(pdp_url="https://pdp.internal")
```

By default it `POST`s to `/access/v1/evaluation` (single) and `/access/v1/evaluations`
(batch). Override the paths via `ScannerConfig` if your PDP mounts them elsewhere or sits
behind a gateway.

## Installation

```bash
pip install "authzen-llamafirewall-scanner[llamafirewall]"   # scanner + LlamaFirewall
pip install authzen-llamafirewall-scanner                    # AuthZEN client/models only
```

## Authentication & TLS (bring-your-own httpx client)

For bearer tokens, mTLS, custom CA roots, or proxies, pass a pre-configured
`httpx.AsyncClient`. Secrets stay in your client and never touch message content or logs.

```python
import httpx
from authzen_llamafirewall import AuthZENScanner, ScannerConfig

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
