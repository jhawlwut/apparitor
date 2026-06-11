# One policy, three enforcement points

The portability claim, made runnable: the **same Cedar policy** (vendored in
[`../cedar/`](../cedar/)) authorizes the same two tool calls at every shipping
enforcement-point adapter, over the **in-process Cedar backend** — no Docker, no gateway,
no network.

| Enforcement point | Surface | Verdict mapping |
| --- | --- | --- |
| LlamaFirewall scanner (`AuthZENScanner`) | firewall scan, assistant role | `ScanDecision.ALLOW` / `BLOCK` |
| NeMo Guardrails rail (`NeMoAuthorizationRails`) | custom action + `output_mapping` | `allowed` bool (fail-closed) |
| FastMCP middleware (`FastMCPAuthorizationMiddleware`) | server-side `tools/call` hook | execute / `ToolError` refusal |

The policy is a deny-override guardrail: `forbid` on `destructive == true` beats every
`permit`, so `delete_database` blocks for *any* subject while `read_file` is allowed for
the demo agent. (This in-policy `forbid` works when one PDP holds all your policy; the
`DualPrincipalMapper` generalises the same idea — see the README's identity ladder — by
making the agent boundary a separate decision that works across engines.) Each lane must print the same table:

```text
read_file        -> ALLOW
delete_database  -> BLOCK
```

## Run

From the repo root:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[llamafirewall,nemo,fastmcp,cedar]"
python examples/three-peps/demo.py
```

Lanes whose optional dependency is missing are skipped with an install hint; the script
exits non-zero if any lane disagrees (or, with `APPARITOR_DEMO_REQUIRE_ALL=1`, if any lane
was skipped). The `three-pep-demo` CI job runs all three on every PR and push to `main` —
no Docker and no `smoke.sh`, unlike the PDP examples, because everything is in-process.

Notes that keep the demo honest:

- The FastMCP lane passes `mapper=DefaultToolCallMapper(config)` so all three lanes emit
  the identical policy key (`Tool::"read_file"`). In a real MCP deployment you'd keep the
  default `MCPResourceMapper` (server-scoped `"<server>/<tool>"` ids) and write the policy
  against those keys.
- The FastMCP lane opts in to `allow_static_subject=True` because the demo runs in-process
  with no OAuth server. On a network transport, leave it off and let the validated token
  supply the subject.
- The NeMo lane invokes the registered action directly rather than through an `LLMRails`
  flow — the verdict contract (`return_value` + `output_mapping`) is identical either way,
  and the demo needs no LLM.
