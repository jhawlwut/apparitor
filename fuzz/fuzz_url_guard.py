"""Atheris harness: the SSRF URL guard.

``validate_pdp_url`` parses a configured ``pdp_url`` and must reject non-HTTPS or
private/loopback/link-local hosts with ``AuthZENConfigError`` — and must never
crash on an adversarial URL string (``urlparse`` / ``ipaddress`` edge cases).
Run: ``python fuzz/fuzz_url_guard.py -max_total_time=60``.
"""

import sys

import atheris

with atheris.instrument_imports():
    from apparitor.client import validate_pdp_url
    from apparitor.errors import AuthZENConfigError


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    allow_insecure = fdp.ConsumeBool()
    url = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    try:
        validate_pdp_url(url, allow_insecure=allow_insecure)
    except AuthZENConfigError:
        return


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
