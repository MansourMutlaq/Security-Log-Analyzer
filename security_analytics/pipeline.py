"""End-to-end orchestration for multi-source security analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from security_analytics.config import load_settings
from security_analytics.detection import DetectionEngine
from security_analytics.models import (
    DetectionAlert,
    ParseFailure,
    SecurityEvent,
)
from security_analytics.parsers import (
    CiscoIOSParser,
    CloudTrailParser,
    LinuxAuthParser,
)


@dataclass(frozen=True, slots=True)
class SourceSummary:
    """Parsing statistics for one log source."""

    name: str
    path: str
    parsed_events: int
    rejected_events: int


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Complete result returned by the analytics pipeline."""

    started_at: datetime
    completed_at: datetime
    events: list[SecurityEvent]
    rejected: list[ParseFailure]
    alerts: list[DetectionAlert]
    source_summaries: list[SourceSummary]

    @property
    def duration_seconds(self) -> float:
        """Return total pipeline runtime in seconds."""

        return round(
            (self.completed_at - self.started_at).total_seconds(),
            4,
        )


def run_analysis(
    *,
    cisco_path: str | Path,
    linux_path: str | Path,
    cloudtrail_path: str | Path,
    config_path: str | Path = "config/detection_rules.yml",
) -> AnalysisResult:
    """Parse all supported sources and run every detection rule."""

    started_at = datetime.now(UTC)

    parser_jobs = [
        (
            "Cisco IOS Syslog",
            CiscoIOSParser(),
            Path(cisco_path),
        ),
        (
            "Linux Authentication",
            LinuxAuthParser(),
            Path(linux_path),
        ),
        (
            "AWS CloudTrail",
            CloudTrailParser(),
            Path(cloudtrail_path),
        ),
    ]

    events: list[SecurityEvent] = []
    rejected: list[ParseFailure] = []
    source_summaries: list[SourceSummary] = []

    for source_name, parser, source_path in parser_jobs:
        batch = parser.parse_file(source_path)

        events.extend(batch.events)
        rejected.extend(batch.rejected)

        source_summaries.append(
            SourceSummary(
                name=source_name,
                path=str(source_path),
                parsed_events=len(batch.events),
                rejected_events=len(batch.rejected),
            )
        )

    settings = load_settings(config_path)
    engine = DetectionEngine(settings.detection)
    alerts = engine.analyze(events)

    completed_at = datetime.now(UTC)

    return AnalysisResult(
        started_at=started_at,
        completed_at=completed_at,
        events=events,
        rejected=rejected,
        alerts=alerts,
        source_summaries=source_summaries,
    )