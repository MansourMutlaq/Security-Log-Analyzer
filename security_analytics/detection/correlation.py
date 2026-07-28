"""Time-window event correlation for infrastructure threats."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from security_analytics.config import DetectionSettings
from security_analytics.detection.scoring import severity_from_score
from security_analytics.models import (
    DetectionAlert,
    EventOutcome,
    LogSource,
    SecurityEvent,
)

IPAddress = IPv4Address | IPv6Address


def _events_within_window(
    events: list[SecurityEvent],
    *,
    window_seconds: int,
) -> bool:
    if len(events) < 2:
        return True

    ordered = sorted(events, key=lambda event: event.timestamp)
    elapsed = ordered[-1].timestamp - ordered[0].timestamp

    return elapsed <= timedelta(seconds=window_seconds)


def detect_linux_correlations(
    events: list[SecurityEvent],
    settings: DetectionSettings,
) -> list[DetectionAlert]:
    """Detect authentication attacks requiring multiple related events."""

    alerts: list[DetectionAlert] = []

    failures_by_ip: dict[IPAddress, list[SecurityEvent]] = defaultdict(list)

    for event in events:
        if (
            event.source == LogSource.LINUX_AUTH
            and event.action == "ssh_login_failed"
            and event.source_ip is not None
        ):
            failures_by_ip[event.source_ip].append(event)

    for source_ip, failures in failures_by_ip.items():
        ordered_failures = sorted(
            failures,
            key=lambda event: event.timestamp,
        )

        brute_settings = settings.linux_brute_force

        if (
            len(ordered_failures) >= brute_settings.threshold
            and _events_within_window(
                ordered_failures,
                window_seconds=brute_settings.window_seconds,
            )
        ):
            risk_score = 78

            alerts.append(
                DetectionAlert(
                    rule_id="LINUX-AUTH-001",
                    title="SSH Brute-Force Activity",
                    description=(
                        "Repeated SSH authentication failures were "
                        "correlated from one source address."
                    ),
                    detected_at=ordered_failures[-1].timestamp,
                    severity=severity_from_score(risk_score),
                    risk_score=risk_score,
                    source=LogSource.LINUX_AUTH,
                    source_ip=source_ip,
                    mitre_techniques=["T1110"],
                    event_ids=[
                        event.event_id for event in ordered_failures
                    ],
                    evidence=[
                        f"{len(ordered_failures)} failed SSH logins",
                        (
                            "Targeted users: "
                            + ", ".join(
                                sorted(
                                    {
                                        event.user_name
                                        for event in ordered_failures
                                        if event.user_name
                                    }
                                )
                            )
                        ),
                    ],
                    recommended_action=(
                        "Block or rate-limit the source IP, review the "
                        "targeted accounts, and validate SSH access controls."
                    ),
                    false_positive_notes=[
                        "Authorized security testing",
                        "Misconfigured automation or monitoring accounts",
                    ],
                )
            )

        enumeration_settings = settings.linux_user_enumeration

        invalid_user_events = [
            event
            for event in ordered_failures
            if event.attributes.get("invalid_user") is True
        ]
        invalid_users = {
            event.user_name
            for event in invalid_user_events
            if event.user_name
        }

        if (
            len(invalid_users)
            >= enumeration_settings.distinct_user_threshold
            and _events_within_window(
                invalid_user_events,
                window_seconds=enumeration_settings.window_seconds,
            )
        ):
            risk_score = 58

            alerts.append(
                DetectionAlert(
                    rule_id="LINUX-AUTH-002",
                    title="SSH User Enumeration",
                    description=(
                        "Multiple invalid account names were tested from "
                        "the same source address."
                    ),
                    detected_at=invalid_user_events[-1].timestamp,
                    severity=severity_from_score(risk_score),
                    risk_score=risk_score,
                    source=LogSource.LINUX_AUTH,
                    source_ip=source_ip,
                    mitre_techniques=["T1087"],
                    event_ids=[
                        event.event_id for event in invalid_user_events
                    ],
                    evidence=[
                        (
                            "Invalid users tested: "
                            + ", ".join(sorted(invalid_users))
                        )
                    ],
                    recommended_action=(
                        "Review authentication exposure, restrict SSH "
                        "sources, and investigate the scanning address."
                    ),
                    false_positive_notes=[
                        "Old automation referencing removed accounts"
                    ],
                )
            )

    success_settings = settings.successful_login_after_failures

    successful_events = [
        event
        for event in events
        if (
            event.source == LogSource.LINUX_AUTH
            and event.action == "ssh_login_success"
            and event.source_ip is not None
        )
    ]

    for success in successful_events:
        related_failures = [
            event
            for event in failures_by_ip.get(success.source_ip, [])
            if (
                event.timestamp <= success.timestamp
                and success.timestamp - event.timestamp
                <= timedelta(seconds=success_settings.window_seconds)
            )
        ]

        if len(related_failures) < success_settings.failure_threshold:
            continue

        risk_score = 96

        alerts.append(
            DetectionAlert(
                rule_id="LINUX-AUTH-003",
                title="Successful Login After Repeated Failures",
                description=(
                    "A successful SSH login followed several failures "
                    "from the same source address."
                ),
                detected_at=success.timestamp,
                severity=severity_from_score(risk_score),
                risk_score=risk_score,
                source=LogSource.LINUX_AUTH,
                source_ip=success.source_ip,
                user_name=success.user_name,
                mitre_techniques=["T1078"],
                event_ids=[
                    *[
                        event.event_id
                        for event in related_failures
                    ],
                    success.event_id,
                ],
                evidence=[
                    f"{len(related_failures)} failures before success",
                    f"Successful account: {success.user_name}",
                ],
                recommended_action=(
                    "Treat as a potential account compromise, revoke "
                    "active sessions, rotate credentials, and investigate."
                ),
                false_positive_notes=[
                    "Legitimate user repeatedly entering an incorrect password"
                ],
            )
        )

    return alerts


def detect_cisco_correlations(
    events: list[SecurityEvent],
    settings: DetectionSettings,
) -> list[DetectionAlert]:
    """Detect rapid Cisco interface down-and-up transitions."""

    grouped_events: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(
        list
    )

    for event in events:
        if (
            event.source == LogSource.CISCO_IOS
            and event.action == "cisco_interface_state_change"
            and event.host_name
            and event.resource
        ):
            grouped_events[(event.host_name, event.resource)].append(event)

    alerts: list[DetectionAlert] = []

    for (host_name, resource), interface_events in grouped_events.items():
        ordered_events = sorted(
            interface_events,
            key=lambda event: event.timestamp,
        )

        outcomes = {event.outcome for event in ordered_events}

        if not {
            EventOutcome.FAILURE,
            EventOutcome.SUCCESS,
        }.issubset(outcomes):
            continue

        if not _events_within_window(
            ordered_events,
            window_seconds=settings.cisco_interface_flap.window_seconds,
        ):
            continue

        risk_score = 48

        alerts.append(
            DetectionAlert(
                rule_id="CISCO-NET-001",
                title="Rapid Interface State Change",
                description=(
                    "A Cisco IOS interface transitioned down and back up "
                    "inside the configured correlation window."
                ),
                detected_at=ordered_events[-1].timestamp,
                severity=severity_from_score(risk_score),
                risk_score=risk_score,
                source=LogSource.CISCO_IOS,
                resource=resource,
                mitre_techniques=[],
                event_ids=[
                    event.event_id for event in ordered_events
                ],
                evidence=[
                    f"Device: {host_name}",
                    f"Interface: {resource}",
                    f"State changes: {len(ordered_events)}",
                ],
                recommended_action=(
                    "Review physical connectivity, interface counters, "
                    "spanning-tree events, and recent configuration changes."
                ),
                false_positive_notes=[
                    "Planned maintenance",
                    "Expected cable or device reconnection",
                ],
            )
        )

    return alerts