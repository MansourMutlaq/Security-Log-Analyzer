"""AWS CloudTrail JSON Lines parser."""

from __future__ import annotations

import json
from datetime import datetime
from ipaddress import ip_address
from typing import Any

from security_analytics.exceptions import LogParseError
from security_analytics.models import (
    EventOutcome,
    LogSource,
    SecurityEvent,
)
from security_analytics.parsers.base import BaseParser


class CloudTrailParser(BaseParser):
    """Parse AWS CloudTrail records into normalized security events."""

    def parse_line(
        self,
        raw_event: str,
        *,
        line_number: int = 1,
    ) -> SecurityEvent:
        try:
            record = json.loads(raw_event)
        except json.JSONDecodeError as exc:
            raise LogParseError(
                f"Invalid CloudTrail JSON at line {line_number}"
            ) from exc

        if not isinstance(record, dict):
            raise LogParseError(
                f"CloudTrail record must be an object at line {line_number}"
            )

        event_time = record.get("eventTime")
        event_name = record.get("eventName")
        event_source = record.get("eventSource")

        if not event_time or not event_name or not event_source:
            raise LogParseError(
                f"CloudTrail record missing required fields at line {line_number}"
            )

        try:
            timestamp = datetime.fromisoformat(
                str(event_time).replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise LogParseError("Invalid CloudTrail eventTime") from exc

        identity = record.get("userIdentity") or {}
        request_parameters = record.get("requestParameters") or {}
        error_code = record.get("errorCode")

        identity_type = identity.get("type")
        user_name = self._extract_user_name(identity)
        source_ip, original_source = self._extract_source_ip(
            record.get("sourceIPAddress")
        )

        category, event_type = self._classify_event(
            str(event_source),
            str(event_name),
        )

        outcome = (
            EventOutcome.FAILURE
            if error_code
            else EventOutcome.SUCCESS
        )

        return SecurityEvent(
            timestamp=timestamp,
            source=LogSource.AWS_CLOUDTRAIL,
            category=category,
            event_type=event_type,
            outcome=outcome,
            action=str(event_name),
            message=f"{event_name} recorded by {event_source}",
            host_name=record.get("recipientAccountId"),
            source_ip=source_ip,
            user_name=user_name,
            resource=self._extract_resource(request_parameters),
            raw_event=record,
            attributes={
                "event_source": event_source,
                "aws_region": record.get("awsRegion"),
                "identity_type": identity_type,
                "source_identity": original_source,
                "error_code": error_code,
                "error_message": record.get("errorMessage"),
                "request_parameters": request_parameters,
            },
        )

    @staticmethod
    def _extract_user_name(identity: dict[str, Any]) -> str | None:
        if identity.get("userName"):
            return str(identity["userName"])

        if identity.get("type") == "Root":
            return "root"

        if identity.get("arn"):
            return str(identity["arn"]).rsplit("/", maxsplit=1)[-1]

        return None

    @staticmethod
    def _extract_source_ip(
        value: Any,
    ) -> tuple[Any | None, str | None]:
        if value is None:
            return None, None

        source_value = str(value)

        try:
            return ip_address(source_value), source_value
        except ValueError:
            return None, source_value

    @staticmethod
    def _extract_resource(
        request_parameters: dict[str, Any],
    ) -> str | None:
        candidate_fields = (
            "groupId",
            "policyArn",
            "bucketName",
            "roleName",
            "userName",
            "trailName",
        )

        for field in candidate_fields:
            value = request_parameters.get(field)
            if value:
                return str(value)

        return None

    @staticmethod
    def _classify_event(
        event_source: str,
        event_name: str,
    ) -> tuple[list[str], list[str]]:
        if event_name == "ConsoleLogin":
            return ["authentication"], ["start"]

        if event_source == "iam.amazonaws.com":
            return ["iam"], ["change"]

        if event_source == "ec2.amazonaws.com":
            return ["network", "configuration"], ["change"]

        if event_source == "cloudtrail.amazonaws.com":
            return ["configuration"], ["change"]

        return ["configuration"], ["info"]