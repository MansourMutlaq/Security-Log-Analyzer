"""Time-window correlation tests."""

from datetime import UTC, datetime

from security_analytics.config import ApplicationSettings
from security_analytics.detection import DetectionEngine
from security_analytics.models import (
    EventOutcome,
    LogSource,
    SecurityEvent,
)


def test_success_after_failures_correlation(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    alert = next(item for item in alerts if item.rule_id == "LINUX-AUTH-003")

    assert alert.risk_score == 96
    assert alert.user_name == "ops-admin"
    assert "4 failures before success" in alert.evidence


def test_brute_force_threshold_not_met(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    failures = [event for event in sample_events if event.action == "ssh_login_failed"][:3]

    alerts = DetectionEngine(settings.detection).analyze(failures)

    assert "LINUX-AUTH-001" not in {alert.rule_id for alert in alerts}


def test_user_enumeration_is_correlated(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    alert = next(item for item in alerts if item.rule_id == "LINUX-AUTH-002")

    assert alert.risk_score == 58
    assert any("admin, oracle" in item for item in alert.evidence)


def test_cisco_interface_flap_is_correlated(
    sample_events: list[SecurityEvent],
    settings: ApplicationSettings,
) -> None:
    alerts = DetectionEngine(settings.detection).analyze(sample_events)
    alert = next(item for item in alerts if item.rule_id == "CISCO-NET-001")

    assert alert.resource == "GigabitEthernet0/1"
    assert "Device: DIST-01" in alert.evidence
    assert "State changes: 2" in alert.evidence


def test_normal_activity_does_not_generate_alerts(
    settings: ApplicationSettings,
) -> None:
    normal_events = [
        SecurityEvent(
            timestamp=datetime(
                2026,
                7,
                27,
                18,
                0,
                tzinfo=UTC,
            ),
            source=LogSource.LINUX_AUTH,
            category=["authentication"],
            event_type=["start"],
            outcome=EventOutcome.SUCCESS,
            action="ssh_login_success",
            message="Normal administrator login",
            host_name="srv-app-01",
            source_ip="192.0.2.10",
            user_name="ops-admin",
            raw_event="sanitized normal event",
        ),
        SecurityEvent(
            timestamp=datetime(
                2026,
                7,
                27,
                18,
                1,
                tzinfo=UTC,
            ),
            source=LogSource.AWS_CLOUDTRAIL,
            category=["configuration"],
            event_type=["info"],
            outcome=EventOutcome.SUCCESS,
            action="ListBuckets",
            message="Routine AWS read operation",
            source_ip="192.0.2.11",
            user_name="readonly-user",
            raw_event={"eventName": "ListBuckets"},
            attributes={
                "identity_type": "IAMUser",
                "request_parameters": {},
            },
        ),
    ]

    alerts = DetectionEngine(settings.detection).analyze(normal_events)

    assert alerts == []
