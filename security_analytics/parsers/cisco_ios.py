"""Cisco IOS syslog parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from ipaddress import ip_address

from security_analytics.exceptions import LogParseError
from security_analytics.models import (
    EventOutcome,
    LogSource,
    SecurityEvent,
)
from security_analytics.parsers.base import BaseParser

SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"%(?P<facility>[A-Z0-9_]+)-"
    r"(?P<severity>\d)-"
    r"(?P<mnemonic>[A-Z0-9_]+):\s*"
    r"(?P<message>.+)$"
)

USER_PATTERN = re.compile(r"\[user:\s*(?P<user>[^\]]+)\]", re.IGNORECASE)
SOURCE_PATTERN = re.compile(
    r"\[Source:\s*(?P<source>[^\]]+)\]",
    re.IGNORECASE,
)
CONFIG_USER_PATTERN = re.compile(
    r"\bby\s+(?P<user>[A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)
PARENTHESIZED_IP_PATTERN = re.compile(
    r"\((?P<source>\d{1,3}(?:\.\d{1,3}){3})\)"
)
INTERFACE_PATTERN = re.compile(
    r"Interface\s+(?P<interface>[^,]+),\s+"
    r"changed state to\s+(?P<state>\w+)",
    re.IGNORECASE,
)


class CiscoIOSParser(BaseParser):
    """Parse selected Cisco IOS operational and security syslog events."""

    def __init__(self, *, year: int = 2026) -> None:
        self.year = year

    def parse_line(
        self,
        raw_event: str,
        *,
        line_number: int = 1,
    ) -> SecurityEvent:
        match = SYSLOG_PATTERN.match(raw_event)

        if not match:
            raise LogParseError(
                f"Unsupported Cisco IOS syslog format at line {line_number}"
            )

        data = match.groupdict()
        timestamp = self._parse_timestamp(
            data["month"],
            data["day"],
            data["time"],
        )
        mnemonic = data["mnemonic"]
        message = data["message"]

        source_ip = self._extract_source_ip(message)
        user_name = self._extract_user(message)

        category = ["network"]
        event_type = ["info"]
        outcome = EventOutcome.UNKNOWN
        action = f"cisco_{mnemonic.lower()}"
        resource: str | None = None

        if mnemonic == "LOGIN_FAILED":
            category = ["authentication"]
            event_type = ["start"]
            outcome = EventOutcome.FAILURE
            action = "cisco_login_failed"

        elif mnemonic == "LOGIN_SUCCESS":
            category = ["authentication"]
            event_type = ["start"]
            outcome = EventOutcome.SUCCESS
            action = "cisco_login_success"

        elif mnemonic == "CONFIG_I":
            category = ["configuration"]
            event_type = ["change"]
            outcome = EventOutcome.SUCCESS
            action = "cisco_configuration_change"

            config_user = CONFIG_USER_PATTERN.search(message)
            if config_user:
                user_name = config_user.group("user")

            parenthesized_ip = PARENTHESIZED_IP_PATTERN.search(message)
            if parenthesized_ip:
                source_ip = ip_address(parenthesized_ip.group("source"))

        elif mnemonic == "UPDOWN":
            category = ["network"]
            event_type = ["change"]
            action = "cisco_interface_state_change"

            interface_match = INTERFACE_PATTERN.search(message)
            if interface_match:
                resource = interface_match.group("interface")
                state = interface_match.group("state").lower()
                outcome = (
                    EventOutcome.SUCCESS
                    if state == "up"
                    else EventOutcome.FAILURE
                )

        return SecurityEvent(
            timestamp=timestamp,
            source=LogSource.CISCO_IOS,
            category=category,
            event_type=event_type,
            outcome=outcome,
            action=action,
            message=message,
            host_name=data["host"],
            source_ip=source_ip,
            user_name=user_name,
            resource=resource,
            raw_event=raw_event,
            attributes={
                "facility": data["facility"],
                "severity_code": int(data["severity"]),
                "mnemonic": mnemonic,
            },
        )

    def _parse_timestamp(
        self,
        month: str,
        day: str,
        time_value: str,
    ) -> datetime:
        try:
            parsed = datetime.strptime(
                f"{self.year} {month} {day} {time_value}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError as exc:
            raise LogParseError("Invalid Cisco IOS timestamp") from exc

        return parsed.replace(tzinfo=UTC)

    @staticmethod
    def _extract_user(message: str) -> str | None:
        match = USER_PATTERN.search(message)
        return match.group("user").strip() if match else None

    @staticmethod
    def _extract_source_ip(message: str):
        match = SOURCE_PATTERN.search(message)

        if not match:
            return None

        try:
            return ip_address(match.group("source").strip())
        except ValueError:
            return None