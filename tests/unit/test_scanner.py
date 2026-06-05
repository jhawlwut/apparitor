"""Scanner boundary tests — verdict → LlamaFirewall ScanResult mapping.

Requires LlamaFirewall (the scanner's only hard dependency). Skipped automatically when
it is not installed; the rest of the pipeline is covered by the LlamaFirewall-free engine
tests. A separate CI job installs ``[llamafirewall]`` to run these.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("llamafirewall")

from llamafirewall import ScanDecision, ScanStatus  # noqa: E402

from authzen_llamafirewall import AuthZENScanner  # noqa: E402
from authzen_llamafirewall.decision import Verdict, VerdictResult, VerdictStatus  # noqa: E402


@pytest.mark.parametrize(
    ("verdict", "status", "expected_decision", "expected_status", "expected_score"),
    [
        (Verdict.ALLOW, VerdictStatus.SUCCESS, ScanDecision.ALLOW, ScanStatus.SUCCESS, 0.0),
        (Verdict.BLOCK, VerdictStatus.ERROR, ScanDecision.BLOCK, ScanStatus.ERROR, 1.0),
        (Verdict.SKIP, VerdictStatus.SKIPPED, ScanDecision.ALLOW, ScanStatus.SKIPPED, 0.0),
        (
            Verdict.HUMAN_REVIEW,
            VerdictStatus.SUCCESS,
            ScanDecision.HUMAN_IN_THE_LOOP_REQUIRED,
            ScanStatus.SUCCESS,
            0.5,
        ),
    ],
)
def test_verdict_maps_to_scan_result(
    make_config, verdict, status, expected_decision, expected_status, expected_score
) -> None:
    scanner = AuthZENScanner(config=make_config())
    result = scanner._to_scan_result(VerdictResult(verdict, "reason", status))
    assert result.decision == expected_decision
    assert result.status == expected_status
    assert result.score == expected_score
    assert result.reason == "reason"
