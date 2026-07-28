"""Linux authentication and sudo log parser."""

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

HEADER_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_.-]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

FAILED_SSH_PATTERN = re.compile(
    r"Failed password for "
    r"(?P<invalid>invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<source>\S+)\s+port\s+"
    r"(?P<port>\d+)",
    re.IGNORECASE,
)

ACCEPTED_SSH_PATTERN = re.compile(
    r"Accepted \S+ for "
    r"(?P<user>\S+)\s+from\s+"
    r"(?P<source>\S+)\s+port\s+"
    r"(?P<port>\d+)",
    re.IGNORECASE,
)

SUDO_PATTERN = re.compile(
    r"(?P<user>\S+)\s*:\s*"
    r"TTY=(?P<tty>[^;]+)\s*;\s*"
    r"PWD=(?P<pwd>[^;]+)\s*;\s*"
    r"USER=(?P<target>[^;]+)\s*;\s*"
    r"COMMAND=(?P<command>.+)$",
    re.IGNORECASE,
)


class LinuxAuthParser(BaseParser):
    """Parse SSH authentication and sudo activity from Linux auth logs."""

    def __init__(self, *, year: int = 2026) -> None:
        self.year = year

    def parse_line(
        self,
        raw_event: str,
        *,
        line_number: int = 1,
    ) -> SecurityEvent:
        header = HEADER_PATTERN.match(raw_event)

        if not header:
            raise LogParseError(
                f"Unsupported Linux auth format at line {line_number}"
            )

        data = header.groupdict()
        message = data["message"]
        timestamp = self._parse_timestamp(
            data["month"],
            data["day"],
            data["time"],
        )

        failed_match = FAILED_SSH_PATTERN.search(message)
        if failed_match:
            return SecurityEvent(
                timestamp=timestamp,
                source=LogSource.LINUX_AUTH,
                category=["authentication"],
                event_type=["start"],
                outcome=EventOutcome.FAILURE,
                action="ssh_login_failed",
                message=message,
                host_name=data["host"],
                source_ip=ip_address(failed_match.group("source")),
                user_name=failed_match.group("user"),
                raw_event=raw_event,
                attributes={
                    "process": data["process"],
                    "pid": data["pid"],
                    "source_port": int(failed_match.group("port")),
                    "invalid_user": bool(failed_match.group("invalid")),
                },
            )

        accepted_match = ACCEPTED_SSH_PATTERN.search(message)
        if accepted_match:
            return SecurityEvent(
                timestamp=timestamp,
                source=LogSource.LINUX_AUTH,
                category=["authentication"],
                event_type=["start"],
                outcome=EventOutcome.SUCCESS,
                action="ssh_login_success",
                message=message,
                host_name=data["host"],
                source_ip=ip_address(accepted_match.group("source")),
                user_name=accepted_match.group("user"),
                raw_event=raw_event,
                attributes={
                    "process": data["process"],
                    "pid": data["pid"],
                    "source_port": int(accepted_match.group("port")),
                },
            )

        sudo_match = SUDO_PATTERN.search(message)
        if sudo_match:
            command = sudo_match.group("command").strip()

            return SecurityEvent(
                timestamp=timestamp,
                source=LogSource.LINUX_AUTH,
                category=["process", "configuration"],
                event_type=["start"],
                outcome=EventOutcome.SUCCESS,
                action="sudo_command",
                message=message,
                host_name=data["host"],
                user_name=sudo_match.group("user"),
                resource=command,
                raw_event=raw_event,
                attributes={
                    "process": data["process"],
                    "target_user": sudo_match.group("target").strip(),
                    "working_directory": sudo_match.group("pwd").strip(),
                    "tty": sudo_match.group("tty").strip(),
                    "command": command,
                },
            )

        raise LogParseError(
            f"Unsupported Linux authentication event at line {line_number}"
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
            raise LogParseError("Invalid Linux auth timestamp") from exc

        return parsed.replace(tzinfo=UTC)