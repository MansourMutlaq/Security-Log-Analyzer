"""Risk scoring and severity classification."""

from security_analytics.models import Severity


def severity_from_score(risk_score: int) -> Severity:
    """Convert a zero-to-100 risk score into an alert severity."""

    if risk_score >= 90:
        return Severity.CRITICAL

    if risk_score >= 70:
        return Severity.HIGH

    if risk_score >= 40:
        return Severity.MEDIUM

    if risk_score >= 20:
        return Severity.LOW

    return Severity.INFORMATIONAL