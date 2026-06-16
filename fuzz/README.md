# Fuzzing

Coverage-guided [Atheris](https://github.com/google/atheris) harnesses for the
parsers that handle data outside our trust boundary:

| Harness | Target | Boundary |
| --- | --- | --- |
| `fuzz_pdp_response.py` | `_strict_json` + response model validation | PDP response body |
| `fuzz_url_guard.py` | `validate_pdp_url` | configured `pdp_url` (SSRF guard) |
| `fuzz_tool_calls.py` | `detect_adapter` + `normalize` | model-emitted tool calls |

Each harness treats only its *expected* rejection (`MalformedPDPResponseError`,
`AuthZENConfigError`, `ValueError`) as a pass; any other exception, a crash, or a
hang is a finding.

## Run locally

```bash
pip install -e . atheris
python fuzz/fuzz_pdp_response.py -max_total_time=60
```

Pass any [libFuzzer flag](https://llvm.org/docs/LibFuzzer.html#options), e.g.
`-runs=100000` for a fixed budget or a corpus directory as the first argument.
The `fuzz` CI job runs each harness on pull requests and weekly.
