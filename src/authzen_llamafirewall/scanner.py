"""The LlamaFirewall scanner plugin.

This is the **only** module that imports LlamaFirewall. The import is guarded so that
importing it without ``llamafirewall`` installed yields a clear, actionable
:class:`~authzen_llamafirewall.errors.MissingDependencyError` rather than an opaque
``ImportError``. (The rest of the package stays LlamaFirewall-free and importable
standalone.)

We import LlamaFirewall's real ``Scanner``/``ScanResult``/``ScanDecision``/``Message``
types directly — never re-declared stubs — so the objects this scanner returns are
identity-compatible with what the LlamaFirewall runtime consumes.

The scanning logic is deferred to the next session; this module pins the public
constructor (the ≤10-line wiring contract) and signatures.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .config import ScannerConfig
from .errors import MissingDependencyError

try:  # pragma: no cover - exercised via import-guard tests
    from llamafirewall import (
        Message,
        ScanDecision,
        Scanner,
        ScanResult,
        ScanStatus,
        Trace,
    )
except ImportError as exc:  # pragma: no cover
    raise MissingDependencyError(
        "authzen_llamafirewall.scanner requires LlamaFirewall. Install it with:\n"
        "    pip install 'authzen-llamafirewall-scanner[llamafirewall]'"
    ) from exc

if TYPE_CHECKING:
    import httpx

    from .mapping import ToolCallMapper

#: Predicate over a PDP response ``context`` that may *escalate* a verdict along the
#: lattice BLOCK > HUMAN_IN_THE_LOOP > ALLOW. It can never downgrade a deny.
ReviewPredicate = Callable[[dict[str, Any]], bool]


class AuthZENScanner(Scanner):  # type: ignore[misc]  # LlamaFirewall ships no type stubs (Scanner is Any)
    """Evaluates agent tool calls against an AuthZEN PDP.

    Happy path::

        scanner = AuthZENScanner(pdp_url="https://pdp.internal")
        firewall = LlamaFirewall(scanners={Role.ASSISTANT: [scanner]})
        result = await firewall.scan_async(message)

    Bind this to the **assistant** role: it is a pre-execution gate, so it must run
    before the tool call is dispatched, not on the tool-output role.
    """

    def __init__(
        self,
        pdp_url: str | None = None,
        *,
        config: ScannerConfig | None = None,
        mapper: ToolCallMapper | None = None,
        http_client: httpx.AsyncClient | None = None,
        review_predicate: ReviewPredicate | None = None,
        scanner_name: str = "AuthZENAuthorizationScanner",
        block_threshold: float = 1.0,
    ) -> None:
        super().__init__(scanner_name, block_threshold)
        if config is None:
            if pdp_url is None:
                raise ValueError("provide either pdp_url or config")
            config = ScannerConfig(pdp_url=pdp_url)
        self._config = config
        self._mapper = mapper
        self._http_client = http_client
        self._review_predicate = review_predicate

    async def scan(self, message: Message, past_trace: Trace | None = None) -> ScanResult:
        """Authorize the tool call(s) in ``message`` against the PDP.

        Returns a :class:`ScanResult` with decision ALLOW / BLOCK /
        HUMAN_IN_THE_LOOP_REQUIRED. See ``docs/requirements.md`` for the full
        extract → map → evaluate → decide pipeline.
        """
        raise NotImplementedError("deferred: see docs/requirements.md (scan pipeline)")

    async def aclose(self) -> None:
        """Release the underlying PDP client (call on scanner teardown)."""
        raise NotImplementedError("deferred")


__all__ = ["AuthZENScanner", "ReviewPredicate", "ScanDecision", "ScanStatus"]
