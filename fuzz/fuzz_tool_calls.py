"""Atheris harness: provider tool-call normalization.

``detect_adapter`` + ``adapter.normalize`` turn a model-emitted tool-call dict
(OpenAI / Anthropic / LangChain shapes) into a ``NormalizedToolCall``.
Mis-extraction is an authorization-bypass risk (see ``apparitor.adapters``), so a
malformed shape must raise ``ValueError`` and never crash with anything else.
Run: ``python fuzz/fuzz_tool_calls.py -max_total_time=60``.
"""

import sys
from typing import Any

import atheris

with atheris.instrument_imports():
    from apparitor.adapters import detect_adapter


def _consume_payload(fdp: atheris.FuzzedDataProvider) -> Any:
    """A fuzzed argument payload: dict, (maybe-JSON) string, None, or int."""
    choice = fdp.ConsumeIntInRange(0, 3)
    if choice == 0:
        return {fdp.ConsumeUnicodeNoSurrogates(8): fdp.ConsumeUnicodeNoSurrogates(8)}
    if choice == 1:
        return fdp.ConsumeUnicodeNoSurrogates(32)
    if choice == 2:
        return None
    return fdp.ConsumeInt(4)


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    raw: dict[str, Any] = {}
    if fdp.ConsumeBool():
        raw["type"] = ("function", "tool_use", "other")[fdp.ConsumeIntInRange(0, 2)]
    if fdp.ConsumeBool():
        raw["name"] = fdp.ConsumeUnicodeNoSurrogates(16)
    if fdp.ConsumeBool():
        raw["function"] = {
            "name": fdp.ConsumeUnicodeNoSurrogates(16),
            "arguments": _consume_payload(fdp),
        }
    if fdp.ConsumeBool():
        raw["input"] = _consume_payload(fdp)
    if fdp.ConsumeBool():
        raw["args"] = _consume_payload(fdp)
    if fdp.ConsumeBool():
        raw["arguments"] = _consume_payload(fdp)
    if fdp.ConsumeBool():
        raw["id"] = fdp.ConsumeUnicodeNoSurrogates(8)

    adapter = detect_adapter(raw)
    if adapter is None:
        return
    try:
        adapter.normalize(raw)
    except ValueError:
        return


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
