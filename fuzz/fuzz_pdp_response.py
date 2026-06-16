"""Atheris harness: the PDP response parsing path.

The body a PDP returns on a 2xx is outside our trust boundary. ``_strict_json``
(duplicate-key-rejecting JSON) feeds ``_parse`` (pydantic validation); both must
reject malformed input with ``MalformedPDPResponseError`` and never crash or hang.
Run: ``python fuzz/fuzz_pdp_response.py -max_total_time=60``.
"""

import sys

import atheris

with atheris.instrument_imports():
    from apparitor.client import _parse, _strict_json
    from apparitor.errors import MalformedPDPResponseError
    from apparitor.models import BatchEvaluationResponse, EvaluationResponse

_MODELS = (EvaluationResponse, BatchEvaluationResponse)


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    model = _MODELS[fdp.ConsumeIntInRange(0, len(_MODELS) - 1)]
    raw = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        parsed = _strict_json(raw)
        _parse(parsed, model)
    except MalformedPDPResponseError:
        return


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
