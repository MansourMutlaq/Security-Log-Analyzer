"""Detection-engine tests."""

from collections import Counter

from security_analytics.config import ApplicationSettings
from security_analytics.detection import DetectionEngine
from security_analytics.models import SecurityEvent


def test_detection_engine_generates_expected_alerts(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)

    assert len(alerts) == 10
    assert {alert.rule_id for alert in alerts} == {
        "AWS-IDENTITY-001",
        "AWS-IAM-001",
        "AWS-LOGGING-001",
        "AWS-NETWORK-001",
        "CISCO-CONFIG-001",
        "CISCO-NET-001",
        "LINUX-AUTH-001",
        "LINUX-AUTH-002",
        "LINUX-AUTH-003",
        "LINUX-PRIV-001",
    }


def test_alerts_are_sorted_by_risk(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    scores = [alert.risk_score for alert in alerts]

    assert scores == sorted(scores, reverse=True)
    assert alerts[0].rule_id == "AWS-LOGGING-001"
    assert alerts[0].risk_score == 100


def test_severity_distribution(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    counts = Counter(alert.severity.value for alert in alerts)

    assert counts == {
        "critical": 5,
        "high": 2,
        "medium": 3,
    }


def test_aws_logging_alert_metadata(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    alert = next(item for item in alerts if item.rule_id == "AWS-LOGGING-001")

    assert alert.title == "AWS CloudTrail Logging Stopped"
    assert alert.mitre_techniques == ["T1562.008"]
    assert alert.user_name == "audit-admin"
    assert alert.resource == "organization-trail"


def test_sensitive_sudo_alert_metadata(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    alert = next(item for item in alerts if item.rule_id == "LINUX-PRIV-001")

    assert alert.user_name == "ops-admin"
    assert alert.risk_score == 84
    assert alert.mitre_techniques == ["T1548.003"]
    assert any("/etc/shadow" in item for item in alert.evidence)
