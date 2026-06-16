# Architecture

How apparitor turns an agent's tool call into an authorization decision, today via its
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
*"is this allowed?"*, the orthogonal, previously-missing axis. It binds to the
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
LlamaFirewall → Agent  : blocked (tool not dispatched)
```

## Module boundaries

| Module | Optional dep | Responsibility |
| --- | --- | --- |
| `scanner.py` | `llamafirewall` | `Scanner` subclass; wires config; maps `VerdictResult`→`ScanResult` |
| `engine.py` | none | firewall-free pipeline orchestration (extract → map → evaluate → decide); `AuthorizationEngine` |
| `decision.py` | none | pure verdict vocabulary (`Verdict`, `VerdictResult`) and decision/aggregation/error logic |
| `backends.py` | none | `DecisionBackend` protocol; `build_backend` factory; `OPABackend` (Data API) |
| `client.py` | none | hardened HTTP transport (`HTTPDecisionTransport`); AuthZEN wire shape; retries; budget |
| `models.py` | none | pydantic AuthZEN 1.0 request/response models |
| `adapters.py` | none | provider-aware tool-call normalisation (OpenAI / Anthropic / LangChain) |
| `mapping.py` | none | `ToolCallMapper` seam; subject `ContextVar`; `DualPrincipalMapper`; MCP resource ids |
| `cache.py` | none | opt-in ALLOW-only TTL cache + SHA-256 key derivation |
| `metrics.py` | none | `MetricsSink` protocol; `InMemoryMetrics` (latency histogram, decision/cache counters) |
| `config.py` | none | `ScannerConfig` (pydantic) + `OnError` / `Backend` enums |
| `errors.py` | none | exception hierarchy; httpx exceptions mapped here |
| `cedar.py` | `cedarpy` | in-process Cedar backend; policies/entities loaded at construction; fail-closed |
| `nemo.py` | `nemoguardrails` | NeMo Guardrails rail adapter (`NeMoAuthorizationRails`); same engine as scanner |
| `fastmcp.py` | `fastmcp` | FastMCP server middleware (`FastMCPAuthorizationMiddleware`); subject from OAuth token |
| `a2a.py` | `a2a-sdk` | A2A agent-executor adapter (`A2AAuthorizationExecutor`); subject from authenticated peer |

Each optional-dep module is isolated so the core imports without it; missing deps raise
`MissingDependencyError`. All optional-dep adapters (`AuthZENScanner`, `NeMoAuthorizationRails`,
`FastMCPAuthorizationMiddleware`, `A2AAuthorizationExecutor`, `CedarBackend`) are exposed lazily
(PEP 562 `__getattr__`) so `import apparitor` succeeds without any optional extra installed.

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

See [requirements.md §3.5 to §3.6](requirements.md). Summary: `true→ALLOW`, `false→BLOCK`;
every error class resolves through `on_error ∈ {deny, human_review}` (no fail-open) and
stamps `status=ERROR`.

## Concurrency model (to pin before implementation)

- `scan()` is async and single-loop; the scanner holds one pooled `httpx.AsyncClient`,
  closed via `aclose()` / `async with`.
- The decision cache is for single-loop async use. It does **not** currently coalesce
  concurrent in-flight misses for the same key (no thundering-herd protection): two
  simultaneous identical scans can both hit the PDP. This is an accepted v0 limitation; a
  per-key in-flight future map is a future enhancement.
- A synchronous client variant (if added) would use `httpx.Client` and a `threading.Lock`ed
  cache, never an `asyncio.Lock` shared across threads, never `asyncio.run`.

## Performance

PDP calls sit in the agent hot path. Mitigations: keep-alive via the long-lived client,
batch (`/evaluations`) for multi-step plans, optional ALLOW caching, and a hard
`request_budget_s` so a slow PDP degrades to a fail-closed verdict rather than stalling
the agent. Emit latency and cache-hit metrics.
