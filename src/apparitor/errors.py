"""Exception hierarchy for the AuthZEN scanner.

httpx exceptions are mapped onto this hierarchy at the client boundary so callers
never need to catch raw ``httpx`` errors. The error *class* determines how the
``on_error`` policy resolves a verdict (see ``docs/requirements.md`` §6).
"""

from __future__ import annotations


class AuthZENError(Exception):
    """Base class for every error raised by this package."""


class MissingDependencyError(AuthZENError):
    """Raised when an optional dependency required for an import path is absent.

    Notably raised by :mod:`apparitor.scanner` when ``llamafirewall``
    is not installed (install ``apparitor[llamafirewall]``).
    """


class AuthZENConfigError(AuthZENError):
    """Invalid or unsafe scanner configuration (e.g. a non-HTTPS / private PDP URL)."""


class AuthZENClientError(AuthZENError):
    """A client-side / request-construction fault, including PDP ``4xx`` responses.

    These indicate a bug or misconfiguration on our side (a malformed request, a
    rejected payload, an auth failure). They must surface loudly and are treated as
    a hard BLOCK — never silently allowed — and are **not** retried.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthZENServiceError(AuthZENError):
    """The PDP could not be reached or did not return a usable decision.

    Resolved through the ``on_error`` policy (deny / human_review).
    """


class PDPUnavailableError(AuthZENServiceError):
    """Transport-level failure: connection refused, DNS failure, or TLS error.

    Also a possible PDP-impersonation signal, so it is treated conservatively.
    """


class PDPTimeoutError(AuthZENServiceError):
    """The PDP did not respond within the configured timeout / latency budget."""


class MalformedPDPResponseError(AuthZENServiceError):
    """A ``2xx`` response that failed strict schema validation.

    A missing or non-boolean ``decision`` is an *error*, never a falsy "allow".
    """
