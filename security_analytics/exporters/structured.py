"""JSON and CSV exporters for analysis results."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from security_analytics.pipeline import AnalysisResult


def _source_summary_payload(
    result: AnalysisResult,
) -> list[dict[str, Any]]:
    return [
        {
            "name": summary.name,
            "path": summary.path,
            "parsed_events": summary.parsed_events,
            "rejected_events": summary.rejected_events,
        }
        for summary in result.source_summaries
    ]


def export_json_report(
    result: AnalysisResult,
    output_directory: str | Path,
) -> Path:
    """Write events, alerts, failures, and metadata to JSON."""

    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    report_path = output_path / "security-analysis.json"

    payload = {
        "metadata": {
            "started_at": result.started_at.isoformat(),
            "completed_at": result.completed_at.isoformat(),
            "duration_seconds": result.duration_seconds,
        },
        "summary": {
            "events_analyzed": len(result.events),
            "events_rejected": len(result.rejected),
            "alerts_generated": len(result.alerts),
        },
        "sources": _source_summary_payload(result),
        "alerts": [
            alert.model_dump(mode="json")
            for alert in result.alerts
        ],
        "events": [
            event.model_dump(mode="json")
            for event in result.events
        ],
        "rejected_events": [
            failure.model_dump(mode="json")
            for failure in result.rejected
        ],
    }

    report_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return report_path


def export_alerts_csv(
    result: AnalysisResult,
    output_directory: str | Path,
) -> Path:
    """Write a flattened alert list to CSV."""

    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)

    report_path = output_path / "security-alerts.csv"

    fieldnames = [
        "alert_id",
        "detected_at",
        "rule_id",
        "title",
        "severity",
        "risk_score",
        "source",
        "source_ip",
        "user_name",
        "resource",
        "mitre_techniques",
        "evidence",
        "recommended_action",
        "false_positive_notes",
    ]

    with report_path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for alert in result.alerts:
            writer.writerow(
                {
                    "alert_id": str(alert.alert_id),
                    "detected_at": alert.detected_at.isoformat(),
                    "rule_id": alert.rule_id,
                    "title": alert.title,
                    "severity": alert.severity.value,
                    "risk_score": alert.risk_score,
                    "source": alert.source.value,
                    "source_ip": (
                        str(alert.source_ip)
                        if alert.source_ip
                        else ""
                    ),
                    "user_name": alert.user_name or "",
                    "resource": alert.resource or "",
                    "mitre_techniques": "; ".join(
                        alert.mitre_techniques
                    ),
                    "evidence": " | ".join(alert.evidence),
                    "recommended_action": alert.recommended_action,
                    "false_positive_notes": " | ".join(
                        alert.false_positive_notes
                    ),
                }
            )

    return report_path


def export_structured_reports(
    result: AnalysisResult,
    output_directory: str | Path,
) -> dict[str, Path]:
    """Generate all machine-readable reports."""

    return {
        "json": export_json_report(
            result,
            output_directory,
        ),
        "csv": export_alerts_csv(
            result,
            output_directory,
        ),
    }