"""Common parser interface and safe file-processing behavior."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from security_analytics.exceptions import LogParseError
from security_analytics.models import ParseBatch, ParseFailure, SecurityEvent


class BaseParser(ABC):
    """Base class implemented by every infrastructure log parser."""

    @abstractmethod
    def parse_line(
        self,
        raw_event: str,
        *,
        line_number: int = 1,
    ) -> SecurityEvent | None:
        """Parse one raw log record into a normalized security event."""

    def parse_file(self, path: str | Path) -> ParseBatch:
        """Parse a UTF-8 log file while isolating malformed records."""

        log_path = Path(path)

        if not log_path.is_file():
            raise FileNotFoundError(f"Log file not found: {log_path}")

        events: list[SecurityEvent] = []
        rejected: list[ParseFailure] = []

        with log_path.open("r", encoding="utf-8") as log_file:
            for line_number, raw_line in enumerate(log_file, start=1):
                raw_event = raw_line.strip()

                if not raw_event:
                    continue

                try:
                    event = self.parse_line(
                        raw_event,
                        line_number=line_number,
                    )
                except (LogParseError, ValueError, TypeError) as exc:
                    rejected.append(
                        ParseFailure(
                            line_number=line_number,
                            reason=str(exc),
                            raw_event=raw_event,
                        )
                    )
                    continue

                if event is not None:
                    events.append(event)

        return ParseBatch(events=events, rejected=rejected)