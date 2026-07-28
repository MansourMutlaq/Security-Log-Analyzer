"""CLI tests for optional OpenSearch integration."""

from pathlib import Path
from typing import Any

from opensearchpy.exceptions import OpenSearchException
from typer.testing import CliRunner

from security_analytics.cli import app
from security_analytics.exporters.opensearch import (
    OpenSearchExportSummary,
)
from security_analytics.pipeline import AnalysisResult

runner = CliRunner()


def test_analyze_command_exports_to_opensearch(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """The CLI should export when an endpoint is explicitly supplied."""
    captured: dict[str, Any] = {}

    def fake_export(
        result: AnalysisResult,
        **kwargs: Any,
    ) -> OpenSearchExportSummary:
        captured["result"] = result
        captured.update(kwargs)

        return OpenSearchExportSummary(
            event_index="security-analytics-events-2026.07.28",
            alert_index="security-analytics-alerts-2026.07.28",
            events_indexed=len(result.events),
            alerts_indexed=len(result.alerts),
        )

    monkeypatch.setattr(
        "security_analytics.cli.export_to_opensearch",
        fake_export,
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "--output",
            str(tmp_path),
            "--opensearch-endpoint",
            "http://localhost:9200",
            "--opensearch-index-prefix",
            "Infrastructure Security",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["endpoint"] == "http://localhost:9200"
    assert captured["index_prefix"] == "Infrastructure Security"
    assert captured["verify_certs"] is True
    assert "OpenSearch export:" in result.output
    assert "Events:" in result.output
    assert "Alerts:" in result.output


def test_analyze_command_survives_opensearch_failure(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """A failed optional export must not discard local reports."""

    def failing_export(
        result: AnalysisResult,
        **kwargs: Any,
    ) -> OpenSearchExportSummary:
        raise OpenSearchException("OpenSearch is unavailable")

    monkeypatch.setattr(
        "security_analytics.cli.export_to_opensearch",
        failing_export,
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "--output",
            str(tmp_path),
            "--opensearch-endpoint",
            "http://localhost:9200",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "OpenSearch export skipped:" in result.output
    assert (tmp_path / "security-analysis.json").is_file()
    assert (tmp_path / "security-alerts.csv").is_file()
    assert (tmp_path / "security-report.html").is_file()


def test_analyze_command_does_not_require_opensearch(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Local analysis should not call OpenSearch by default."""
    called = False

    def unexpected_export(
        result: AnalysisResult,
        **kwargs: Any,
    ) -> OpenSearchExportSummary:
        nonlocal called
        called = True
        raise AssertionError("OpenSearch should not have been called.")

    monkeypatch.setattr(
        "security_analytics.cli.export_to_opensearch",
        unexpected_export,
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            "--output",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert called is False
