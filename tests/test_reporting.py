"""Pipeline, reporting, ECS, and CLI tests."""

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from security_analytics.cli import app
from security_analytics.exporters import (
    export_html_report,
    export_structured_reports,
)
from security_analytics.normalization import to_ecs_document
from security_analytics.pipeline import AnalysisResult

ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_summary(
    analysis_result: AnalysisResult,
) -> None:
    assert len(analysis_result.events) == 15
    assert len(analysis_result.rejected) == 0
    assert len(analysis_result.alerts) == 10
    assert len(analysis_result.source_summaries) == 3


def test_json_and_csv_reports(
    analysis_result: AnalysisResult,
    tmp_path: Path,
) -> None:
    reports = export_structured_reports(
        analysis_result,
        tmp_path,
    )

    payload = json.loads(reports["json"].read_text(encoding="utf-8"))

    assert payload["summary"] == {
        "events_analyzed": 15,
        "events_rejected": 0,
        "alerts_generated": 10,
    }

    with reports["csv"].open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert len(rows) == 10
    assert rows[0]["rule_id"] == "AWS-LOGGING-001"


def test_html_report_content(
    analysis_result: AnalysisResult,
    tmp_path: Path,
) -> None:
    report = export_html_report(
        analysis_result,
        tmp_path,
        ROOT / "templates/security_report.html.j2",
    )
    content = report.read_text(encoding="utf-8")

    assert "Infrastructure Security Analytics Report" in content
    assert "AWS CloudTrail Logging Stopped" in content
    assert "Successful Login After Repeated Failures" in content
    assert "ops-admin" in content
    repository_root = ROOT.resolve()

    assert str(repository_root) not in content
    assert repository_root.as_posix() not in content

    assert "security_events.log" in content
    assert "auth_attack.log" in content
    assert "cloudtrail_events.jsonl" in content


def test_ecs_normalization(
    analysis_result: AnalysisResult,
) -> None:
    event = analysis_result.events[0]
    document = to_ecs_document(event)

    assert document["@timestamp"].endswith("Z")
    assert document["event"]["dataset"] == "cisco_ios"
    assert document["event"]["id"] == str(event.event_id)
    assert document["host"]["name"] == "CORE-01"


def test_cli_runs_end_to_end(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "analyze",
            "--cisco",
            str(ROOT / "samples/cisco_ios/security_events.log"),
            "--linux",
            str(ROOT / "samples/linux/auth_attack.log"),
            "--aws",
            str(ROOT / "samples/aws/cloudtrail_events.jsonl"),
            "--config",
            str(ROOT / "config/detection_rules.yml"),
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0
    assert (tmp_path / "security-analysis.json").is_file()
    assert (tmp_path / "security-alerts.csv").is_file()
    assert (tmp_path / "security-report.html").is_file()
