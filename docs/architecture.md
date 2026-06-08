# Architecture

How apparitor turns an agent's tool call into an authorization decision — today via its
LlamaFirewall scanner and the AuthZEN evaluation pipeline. Design rationale lives in
[requirements.md](requirements.md); this document focuses on the runtime shape.

## Where it sits

```
            ┌──────────────────────────── LlamaFirewall ────────────────────────────┐
 agent ───▶ │ PromptGuard → AlignmentCheck → CodeShield → AuthZENAuthorizationScanner │ ─▶ tool executes
            └───────────────────────────────────────────────────────────│───────────┘
                                                                          │  POST /access/v1/evaluation(s)
                                                                          ▼
                                                            AuthZEN PDP (OpenFGA / Cedar / OPA / Topaz)
```

Content-safety scanners answer *"is this malicious?"* The AuthZEN scanner answers
*"is this allowed?"* — the orthogonal, previously-missing axis. It binds to the
`ASSISTANT` role so it runs **before** the tool call is dispatched.

## The scan pipeline

```
scan(message)                                       module
   │
   ├─ 1. extract  tool_calls ──▶ NormalizedToolCall  adapters.py   (provider-aware)
   │       └─ none → SKIPPED   ;  unparseable → BLOCK
   │
   ├─ 2. map      (call, request_context) ──▶ EvaluationRequest    mapping.py
   │       subject ← current_subject ContextVar (NOT message content)
   │       resource ← {type:"tool", id:name, properties.arguments}
   │
   ├─ 3. cache?   ALLOW-only lookup by full-tuple SHA-256          cache.py   (off by default)
   │
   ├─ 4. evaluate 1 call → /evaluation ; N → /evaluations          client.py  (httpx async, retries, budget)
   │
   ├─ 5. decide   true→ALLOW(0.0) ; false→BLOCK(1.0)               scanner.py
   │       review_predicate may only ESCALATE (BLOCK>HUMAN>ALLOW)
   │       error → on_error {deny|human_review}, status=ERROR
   │
   └─ 6. log + (cache ALLOW) ──▶ ScanResult
```

## Sequence (single tool call)

```
Agent → LlamaFirewall : assistant message with tool_calls
LlamaFirewall → Scanner: await scan(message)
Scanner → adapters     : detect + normalize tool call
Scanner → mapping      : EvaluationRequest (subject from ContextVar)
Scanner → AuthZEN PDP  : POST /access/v1/evaluation  {subject, action, resource, context}
AuthZEN PDP → Scanner  : { "decision": false, "context": {...} }
Scanner → LlamaFirewall: ScanResult(BLOCK, reason, score=1.0)
LlamaFirewall → Agent  : blocked — tool not dispatched
```

## Module boundaries

| Module | Imports LlamaFirewall? | Responsibility |
| --- | --- | --- |
| `scanner.py` | **yes** (only here) | `Scanner` subclass; pipeline orchestration; decision→`ScanResult` |
| `client.py` | no | AuthZEN transport + wire shape; retries; budget; httpx lifecycle |
| `models.py` | no | pydantic AuthZEN request/response models |
| `adapters.py` | no | provider-aware tool-call normalisation |
| `mapping.py` | no | `ToolCallMapper` seam; subject `ContextVar`; MCP resource ids |
| `cache.py` | no | opt-in ALLOW-only TTL cache + key derivation |
| `config.py` | no | `ScannerConfig` (pydantic) + `OnError` enum |
| `errors.py` | no | exception hierarchy (httpx mapped here) |

The single LlamaFirewall import lives at the top of `scanner.py` behind an `ImportError`
guard that re-raises `MissingDependencyError`. `apparitor.__init__` exposes
`AuthZENScanner` lazily (PEP 562 `__getattr__`) so `import apparitor` succeeds
without LlamaFirewall.

## Registration

```python
from llamafirewall import LlamaFirewall, Role
from apparitor import AuthZENScanner

scanner = AuthZENScanner(pdp_url="https://pdp.internal")
firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
```

The configured-instance path is primary because our scanner needs constructor arguments;
`@register_llamafirewall_scanner(...)` instantiates arg-less and cannot carry config.

## Decision & error tables

See [requirements.md §3.5–3.6](requirements.md). Summary: `true→ALLOW`, `false→BLOCK`;
every error class resolves through `on_error ∈ {deny, human_review}` (no fail-open) and
stamps `status=ERROR`.

## Concurrency model (to pin before implementation)

- `scan()` is async and single-loop; the scanner holds one pooled `httpx.AsyncClient`,
  closed via `aclose()` / `async with`.
- The decision cache is for single-loop async use. It does **not** currently coalesce
  concurrent in-flight misses for the same key (no thundering-herd protection) — two
  simultaneous identical scans can both hit the PDP. This is an accepted v0 limitation; a
  per-key in-flight future map is a future enhancement.
- A synchronous client variant (if added) would use `httpx.Client` and a `threading.Lock`ed
  cache — never an `asyncio.Lock` shared across threads, never `asyncio.run`.

## Performance

PDP calls sit in the agent hot path. Mitigations: keep-alive via the long-lived client,
batch (`/evaluations`) for multi-step plans, optional ALLOW caching, and a hard
`request_budget_s` so a slow PDP degrades to a fail-closed verdict rather than stalling
the agent. Emit latency + cache-hit metrics.
