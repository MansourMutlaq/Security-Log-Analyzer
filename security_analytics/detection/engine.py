"""Rule-driven detection engine for normalized security events."""

from __future__ import annotations

from typing import Any

from security_analytics.config import DetectionSettings
from security_analytics.detection.correlation import (
    detect_cisco_correlations,
    detect_linux_correlations,
)
from security_analytics.detection.scoring import severity_from_score
from security_analytics.models import (
    DetectionAlert,
    LogSource,
    SecurityEvent,
)


class DetectionEngine:
    """Evaluate direct rules and time-window correlation rules."""

    def __init__(self, settings: DetectionSettings) -> None:
        self.settings = settings

    def analyze(
        self,
        events: list[SecurityEvent],
    ) -> list[DetectionAlert]:
        """Evaluate all supported detection rules."""

        alerts: list[DetectionAlert] = []

        for event in events:
            alert = self._evaluate_direct_event(event)

            if alert is not None:
                alerts.append(alert)

        alerts.extend(
            detect_linux_correlations(events, self.settings)
        )
        alerts.extend(
            detect_cisco_correlations(events, self.settings)
        )

        return sorted(
            alerts,
            key=lambda alert: (
                alert.risk_score,
                alert.detected_at,
            ),
            reverse=True,
        )

    def _evaluate_direct_event(
        self,
        event: SecurityEvent,
    ) -> DetectionAlert | None:
        if (
            event.source == LogSource.CISCO_IOS
            and event.action == "cisco_configuration_change"
        ):
            return self._alert(
                event=event,
                rule_id="CISCO-CONFIG-001",
                title="Cisco IOS Configuration Change",
                description=(
                    "A configuration modification was recorded on a "
                    "managed Cisco IOS device."
                ),
                risk_score=45,
                mitre_techniques=[],
                recommended_action=(
                    "Validate the change against an approved request and "
                    "compare the current configuration with the baseline."
                ),
                false_positive_notes=[
                    "Approved network maintenance"
                ],
            )

        if (
            event.source == LogSource.LINUX_AUTH
            and event.action == "sudo_command"
        ):
            command = str(event.attributes.get("command", "")).lower()

            matched_keywords = [
                keyword
                for keyword in self.settings.suspicious_sudo.keywords
                if keyword.lower() in command
            ]

            if matched_keywords:
                return self._alert(
                    event=event,
                    rule_id="LINUX-PRIV-001",
                    title="Sensitive Command Executed with Sudo",
                    description=(
                        "A privileged command matched a configured "
                        "sensitive-command indicator."
                    ),
                    risk_score=84,
                    mitre_techniques=["T1548.003"],
                    recommended_action=(
                        "Confirm the administrator's intent, review the "
                        "executed command, and inspect subsequent activity."
                    ),
                    false_positive_notes=[
                        "Authorized system administration"
                    ],
                    extra_evidence=[
                        f"Matched indicators: {', '.join(matched_keywords)}"
                    ],
                )

        if event.source == LogSource.AWS_CLOUDTRAIL:
            return self._evaluate_cloudtrail(event)

        return None

    def _evaluate_cloudtrail(
        self,
        event: SecurityEvent,
    ) -> DetectionAlert | None:
        identity_type = event.attributes.get("identity_type")

        if (
            event.action == "ConsoleLogin"
            and identity_type == "Root"
        ):
            return self._alert(
                event=event,
                rule_id="AWS-IDENTITY-001",
                title="AWS Root Account Console Login",
                description=(
                    "The AWS root identity was used for a console login."
                ),
                risk_score=92,
                mitre_techniques=["T1078.004"],
                recommended_action=(
                    "Validate the activity immediately, confirm MFA usage, "
                    "and avoid root account use for routine administration."
                ),
                false_positive_notes=[
                    "Documented emergency root-account procedure"
                ],
            )

        if event.action == "StopLogging":
            return self._alert(
                event=event,
                rule_id="AWS-LOGGING-001",
                title="AWS CloudTrail Logging Stopped",
                description=(
                    "CloudTrail logging was stopped for an audit trail."
                ),
                risk_score=100,
                mitre_techniques=["T1562.008"],
                recommended_action=(
                    "Restore logging immediately, preserve available audit "
                    "records, and investigate the responsible identity."
                ),
                false_positive_notes=[
                    "Approved logging migration or trail replacement"
                ],
            )

        if event.action == "AttachUserPolicy":
            request_parameters = event.attributes.get(
                "request_parameters",
                {},
            )
            policy_arn = str(
                request_parameters.get("policyArn", "")
            )

            matched_policies = [
                policy_name
                for policy_name in self.settings.aws.privileged_policies
                if policy_name.lower() in policy_arn.lower()
            ]

            if matched_policies:
                return self._alert(
                    event=event,
                    rule_id="AWS-IAM-001",
                    title="Privileged IAM Policy Attached",
                    description=(
                        "A highly privileged AWS managed policy was "
                        "attached directly to an IAM user."
                    ),
                    risk_score=91,
                    mitre_techniques=["T1098"],
                    recommended_action=(
                        "Validate the authorization, remove unnecessary "
                        "privileges, and prefer controlled role-based access."
                    ),
                    false_positive_notes=[
                        "Approved break-glass access assignment"
                    ],
                    extra_evidence=[
                        f"Policy: {policy_arn}"
                    ],
                )

        if event.action == "AuthorizeSecurityGroupIngress":
            request_parameters = event.attributes.get(
                "request_parameters",
                {},
            )

            public_exposure = self._find_public_admin_exposure(
                request_parameters
            )

            if public_exposure:
                return self._alert(
                    event=event,
                    rule_id="AWS-NETWORK-001",
                    title="Administrative Port Exposed Publicly",
                    description=(
                        "An AWS security-group rule exposed an "
                        "administrative port to the public internet."
                    ),
                    risk_score=97,
                    mitre_techniques=["T1562.007"],
                    recommended_action=(
                        "Remove public ingress, restrict the source CIDR, "
                        "and use Systems Manager Session Manager or VPN."
                    ),
                    false_positive_notes=[
                        "Temporary approved troubleshooting window"
                    ],
                    extra_evidence=public_exposure,
                )

        return None

    def _find_public_admin_exposure(
        self,
        request_parameters: dict[str, Any],
    ) -> list[str]:
        ip_permissions = request_parameters.get("ipPermissions")

        if not isinstance(ip_permissions, dict):
            return []

        from_port = ip_permissions.get("fromPort")
        to_port = ip_permissions.get("toPort")
        ip_ranges = ip_permissions.get("ipRanges", [])

        if not isinstance(ip_ranges, list):
            return []

        public_range_found = any(
            isinstance(item, dict)
            and item.get("cidrIp") in {"0.0.0.0/0", "::/0"}
            for item in ip_ranges
        )

        if not public_range_found:
            return []

        exposed_ports = [
            port
            for port in self.settings.aws.public_admin_ports
            if (
                isinstance(from_port, int)
                and isinstance(to_port, int)
                and from_port <= port <= to_port
            )
        ]

        if not exposed_ports:
            return []

        return [
            "Public CIDR: 0.0.0.0/0 or ::/0",
            (
                "Administrative ports: "
                + ", ".join(str(port) for port in exposed_ports)
            ),
        ]

    @staticmethod
    def _alert(
        *,
        event: SecurityEvent,
        rule_id: str,
        title: str,
        description: str,
        risk_score: int,
        mitre_techniques: list[str],
        recommended_action: str,
        false_positive_notes: list[str],
        extra_evidence: list[str] | None = None,
    ) -> DetectionAlert:
        evidence = [
            f"Action: {event.action}",
            f"Message: {event.message}",
        ]

        if extra_evidence:
            evidence.extend(extra_evidence)

        return DetectionAlert(
            rule_id=rule_id,
            title=title,
            description=description,
            detected_at=event.timestamp,
            severity=severity_from_score(risk_score),
            risk_score=risk_score,
            source=event.source,
            source_ip=event.source_ip,
            user_name=event.user_name,
            resource=event.resource,
            mitre_techniques=mitre_techniques,
            event_ids=[event.event_id],
            evidence=evidence,
            recommended_action=recommended_action,
            false_positive_notes=false_positive_notes,
        )