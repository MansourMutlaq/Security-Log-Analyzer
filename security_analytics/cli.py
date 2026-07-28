"""Command-line interface for infrastructure security analysis."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import typer
from opensearchpy.exceptions import OpenSearchException
from rich.console import Console
from rich.table import Table

from security_analytics.exceptions import SecurityAnalyticsError
from security_analytics.exporters import (
    export_html_report,
    export_structured_reports,
)
from security_analytics.exporters.opensearch import export_to_opensearch
from security_analytics.pipeline import AnalysisResult, run_analysis

app = typer.Typer(
    name="security-analytics",
    help=(
        "Analyze AWS, Linux, and Cisco infrastructure logs "
        "and generate correlated security alerts."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.callback()
def main() -> None:
    """Multi-source infrastructure security analytics platform."""


def _display_source_summary(result: AnalysisResult) -> None:
    table = Table(
        title="Log Ingestion Summary",
        show_lines=True,
    )
    table.add_column("Source", style="cyan")
    table.add_column("Parsed", justify="right")
    table.add_column("Rejected", justify="right")
    table.add_column("Input File")

    for summary in result.source_summaries:
        table.add_row(
            summary.name,
            str(summary.parsed_events),
            str(summary.rejected_events),
            summary.path,
        )

    console.print(table)


def _display_alerts(result: AnalysisResult) -> None:
    table = Table(
        title="Correlated Security Alerts",
        show_lines=True,
    )
    table.add_column("Severity")
    table.add_column("Risk", justify="right")
    table.add_column("Rule")
    table.add_column("Source")
    table.add_column("Finding")
    table.add_column("Principal")

    severity_styles = {
        "critical": "bold red",
        "high": "bold dark_orange",
        "medium": "bold yellow",
        "low": "green",
        "informational": "blue",
    }

    for alert in result.alerts:
        severity = alert.severity.value

        principal = (
            alert.user_name
            or (
                str(alert.source_ip)
                if alert.source_ip
                else "-"
            )
        )

        table.add_row(
            f"[{severity_styles[severity]}]"
            f"{severity.upper()}"
            f"[/{severity_styles[severity]}]",
            str(alert.risk_score),
            alert.rule_id,
            alert.source.value,
            alert.title,
            principal,
        )

    console.print(table)


@app.command()
def analyze(
    cisco: Path = typer.Option(
        Path("samples/cisco_ios/security_events.log"),
        "--cisco",
        help="Cisco IOS syslog input file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    linux: Path = typer.Option(
        Path("samples/linux/auth_attack.log"),
        "--linux",
        help="Linux authentication log input file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    aws: Path = typer.Option(
        Path("samples/aws/cloudtrail_events.jsonl"),
        "--aws",
        help="AWS CloudTrail JSON Lines input file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    config: Path = typer.Option(
        Path("config/detection_rules.yml"),
        "--config",
        help="Detection-rule configuration file.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Path = typer.Option(
        Path("reports"),
        "--output",
        help="Directory for generated reports.",
    ),
    opensearch_endpoint: str | None = typer.Option(
        None,
        "--opensearch-endpoint",
        help=(
            "Optional OpenSearch endpoint, such as "
            "http://localhost:9200."
        ),
    ),
    opensearch_index_prefix: str = typer.Option(
        "security-analytics",
        "--opensearch-index-prefix",
        help="Prefix used for generated OpenSearch indices.",
    ),
    opensearch_username: str | None = typer.Option(
        None,
        "--opensearch-username",
        help="Optional OpenSearch username.",
    ),
    opensearch_password_env: str = typer.Option(
        "OPENSEARCH_PASSWORD",
        "--opensearch-password-env",
        help=(
            "Environment variable containing the OpenSearch "
            "password."
        ),
    ),
    opensearch_insecure: bool = typer.Option(
        False,
        "--opensearch-insecure",
        help=(
            "Disable TLS certificate verification for local "
            "development only."
        ),
    ),
) -> None:
    """Run the full analysis, detection, and reporting pipeline."""

    try:
        result = run_analysis(
            cisco_path=cisco,
            linux_path=linux,
            cloudtrail_path=aws,
            config_path=config,
        )

        reports = export_structured_reports(
            result,
            output,
        )
        reports["html"] = export_html_report(
            result,
            output,
        )

        if opensearch_endpoint is not None:
            password = os.getenv(opensearch_password_env)

            if opensearch_username is not None and password is None:
                console.print(
                    "[bold yellow]OpenSearch export skipped:"
                    "[/bold yellow] environment variable "
                    f"{opensearch_password_env!r} is not set."
                )
            else:
                try:
                    summary = export_to_opensearch(
                        result,
                        endpoint=opensearch_endpoint,
                        index_prefix=opensearch_index_prefix,
                        username=opensearch_username,
                        password=password,
                        verify_certs=not opensearch_insecure,
                    )
                except (
                    OpenSearchException,
                    OSError,
                    ValueError,
                ) as exc:
                    console.print(
                        "[bold yellow]OpenSearch export skipped:"
                        f"[/bold yellow] {exc}"
                    )
                else:
                    console.print(
                        "\n[bold cyan]OpenSearch export:[/bold cyan]"
                    )
                    console.print(
                        "  Events: "
                        f"[bold]{summary.events_indexed}[/bold] "
                        f"-> {summary.event_index}"
                    )
                    console.print(
                        "  Alerts: "
                        f"[bold]{summary.alerts_indexed}[/bold] "
                        f"-> {summary.alert_index}"
                    )

    except (
        SecurityAnalyticsError,
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        console.print(
            f"[bold red]Analysis failed:[/bold red] {exc}"
        )
        raise typer.Exit(code=1) from exc

    console.print(
        "\n[bold cyan]"
        "Multi-Source Infrastructure Security Analysis"
        "[/bold cyan]\n"
    )

    _display_source_summary(result)
    _display_alerts(result)

    severity_counts = Counter(
        alert.severity.value for alert in result.alerts
    )

    console.print(
        "\n[bold green]Analysis completed successfully[/bold green]"
    )
    console.print(f"Events analyzed: [bold]{len(result.events)}[/bold]")
    console.print(f"Events rejected: [bold]{len(result.rejected)}[/bold]")
    console.print(f"Alerts generated: [bold]{len(result.alerts)}[/bold]")
    console.print(
        "Severity distribution: "
        f"[bold]{dict(severity_counts)}[/bold]"
    )
    console.print(
        f"Pipeline duration: [bold]{result.duration_seconds}s[/bold]"
    )

    console.print("\n[bold cyan]Generated reports:[/bold cyan]")

    for report_type, report_path in reports.items():
        console.print(
            f"  {report_type.upper()}: {report_path}"
        )


if __name__ == "__main__":
    app()