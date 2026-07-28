"""Unit tests for risk scoring and severity classification."""

import pytest

from security_analytics.detection.scoring import severity_from_score
from security_analytics.models import Severity


@pytest.mark.parametrize(
    ("risk_score", "expected_severity"),
    [
        (100, Severity.CRITICAL),
        (90, Severity.CRITICAL),
        (89, Severity.HIGH),
        (70, Severity.HIGH),
        (69, Severity.MEDIUM),
        (40, Severity.MEDIUM),
        (39, Severity.LOW),
        (20, Severity.LOW),
        (19, Severity.INFORMATIONAL),
        (0, Severity.INFORMATIONAL),
    ],
)
def test_severity_from_score_boundaries(
    risk_score: int,
    expected_severity: Severity,
) -> None:
    """Risk-score boundaries should map to deterministic severities."""
    assert severity_from_score(risk_score) is expected_severity
