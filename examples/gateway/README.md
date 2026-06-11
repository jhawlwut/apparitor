# MCP authorization gateway

An enterprise receives a vendor's MCP server but cannot modify it — no middleware, no
routing changes, no source access.  The gateway pattern solves this: your team deploys a
thin FastMCP proxy you own in front of the vendor server and puts
`FastMCPAuthorizationMiddleware` on the proxy.  Every tool call and listing passes through
the proxy before it can reach the upstream; the upstream itself is untouched.

```
MCP client
    │
    ▼
vendor-gateway (FastMCPProxy — your server)
    ├── FastMCPAuthorizationMiddleware  ← enforcement lives here
    │       POST /access/v1/evaluation → PDP
    │           denied → ToolError (upstream never called)
    │           allowed ↓
    └── vendor server (upstream — unmodified)
            tool executes
```

Device management points clients at the gateway address; egress rules block direct
connections to the vendor endpoint.  Those are IT controls that make the gateway the
only path — apparitor enforces at the chokepoint once the path is constrained.

## Running the demo

```
pip install -e ".[fastmcp]"
python examples/gateway/demo.py
```

No Docker, no network egress.  The vendor server and the mock PDP both run in-process.

## What each assertion proves

| Assertion | What it shows |
| --- | --- |
| `tools/list` returns `read_report` only | `filter_listings=True` hides tools the subject may not call — the client never sees `delete_records` |
| `read_report` succeeds and vendor counter == 1 | Allowed calls flow through to the upstream; the proxy is transparent when policy permits |
| `delete_records` raises `ToolError` and vendor counter == 0 | The upstream is never reached on a denied call — the gateway is the chokepoint |

## Policy-key note

The proxy is named `"vendor-gateway"`.  The middleware's default `MCPResourceMapper`
server-scopes resource ids as `"<server>/<tool>"`, so the deny key for `delete_records`
is exactly `"tool_call.execute:vendor-gateway/delete_records"`.  A mapper override that
drops the server prefix (e.g. `DefaultToolCallMapper`) would silently break the deny —
leave the default mapper in place.

## Production hardening

| This demo | Production replaces with |
| --- | --- |
| `allow_insecure_pdp=True` + loopback mock PDP | TLS URL to a real PDP (OPA, OpenFGA, Cedar, …) |
| `allow_static_subject=True` + `agent_id` | `auth=` with a real OAuth token verifier; `sub` from the validated token becomes the subject; drop `allow_static_subject` |
| In-process vendor server | Remote vendor endpoint via `FastMCPProxy` transport |

## Honesty notes

- The in-process vendor server stands in for the remote vendor server.  In production the
  proxy connects to a real upstream over a network transport.
- The mock PDP is a scripted deny-list: everything is permitted unless a rule matches.
  That is the inverse of production authorization semantics (deny-by-default /
  permit-by-exception) and must not be copied into real deployments.
