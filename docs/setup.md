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

## OPA (via `kanywst/opa-authzen`)

[`kanywst/opa-authzen`](https://github.com/kanywst/opa-authzen) is a spec-complete
AuthZEN 1.0 front end for Open Policy Agent — use it as-is; do not rebuild it. The worked
example (compose file + pinned image + sample Rego policy + smoke script) lives in
[`examples/opa/`](../examples/opa/).

## Cerbos

Cerbos exposes AuthZEN natively. The worked example is in
[`examples/cerbos/`](../examples/cerbos/).

## Mock PDP

A tiny in-process AuthZEN PDP for tests and demos (configurable allow/deny rules, no
external services) lives in [`examples/mock_pdp/`](../examples/mock_pdp/).

## Other PDPs

OpenFGA and Topaz both expose AuthZEN endpoints; any AuthZEN 1.0 PDP works. Resource and
subject **type vocabularies differ** between PDPs (OpenFGA's `type:id` object model vs
Cerbos kinds vs OPA's free-form input) — adapt the `ToolCallMapper` to your PDP's schema.
