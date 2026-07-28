"""HTML incident-report generation."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import (
    Environment,
    FileSystemLoader,
    select_autoescape,
)

from security_analytics.pipeline import AnalysisResult

SOURCE_LABELS = {
    "aws_cloudtrail": "AWS CloudTrail",
    "linux_auth": "Linux Authentication",
    "cisco_ios": "Cisco IOS Syslog",
}


def _format_utc_datetime(value: Any) -> str:
    """Render an ISO timestamp as a readable UTC value."""

    if isinstance(value, str):
        value = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

    if not isinstance(value, datetime):
        return str(value)

    return value.astimezone(UTC).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def export_html_report(
    result: AnalysisResult,
    output_directory: str | Path,
    template_path: str | Path = (
        "templates/security_report.html.j2"
    ),
) -> Path:
    """Render a standalone HTML security-analysis report."""

    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    template_file = Path(template_path)

    environment = Environment(
        loader=FileSystemLoader(str(template_file.parent)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    environment.filters["utc_datetime"] = _format_utc_datetime

    template = environment.get_template(template_file.name)

    severity_counts = Counter(
        alert.severity.value for alert in result.alerts
    )
    source_counts = Counter(
        alert.source.value for alert in result.alerts
    )

    alerts = [
        alert.model_dump(mode="json")
        for alert in result.alerts
    ]

    report_html = template.render(
        generated_at=result.completed_at,
        duration_milliseconds=round(
            result.duration_seconds * 1000,
            2,
        ),
        event_count=len(result.events),
        rejected_count=len(result.rejected),
        alert_count=len(result.alerts),
        severity_counts=dict(severity_counts),
        source_counts=dict(source_counts),
        source_labels=SOURCE_LABELS,
        source_summaries=result.source_summaries,
        alerts=alerts,
    )

    report_path = output_path / "security-report.html"
    report_path.write_text(
        report_html,
        encoding="utf-8",
    )

    return report_path
