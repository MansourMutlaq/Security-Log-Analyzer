"""Shared fixtures for the security analytics test suite."""

from pathlib import Path

import pytest

from security_analytics.config import ApplicationSettings, load_settings
from security_analytics.models import SecurityEvent
from security_analytics.parsers import (
    CiscoIOSParser,
    CloudTrailParser,
    LinuxAuthParser,
)
from security_analytics.pipeline import AnalysisResult, run_analysis

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_events() -> list[SecurityEvent]:
    """Return all sanitized events from the three supported sources."""

    parser_jobs = [
        (
            CiscoIOSParser(),
            ROOT / "samples/cisco_ios/security_events.log",
        ),
        (
            LinuxAuthParser(),
            ROOT / "samples/linux/auth_attack.log",
        ),
        (
            CloudTrailParser(),
            ROOT / "samples/aws/cloudtrail_events.jsonl",
        ),
    ]

    events: list[SecurityEvent] = []

    for parser, path in parser_jobs:
        events.extend(parser.parse_file(path).events)

    return events


@pytest.fixture
def settings() -> ApplicationSettings:
    """Return validated detection settings."""

    return load_settings(ROOT / "config/detection_rules.yml")


@pytest.fixture
def analysis_result() -> AnalysisResult:
    """Run the complete pipeline against the sanitized dataset."""

    return run_analysis(
        cisco_path=ROOT / "samples/cisco_ios/security_events.log",
        linux_path=ROOT / "samples/linux/auth_attack.log",
        cloudtrail_path=ROOT / "samples/aws/cloudtrail_events.jsonl",
        config_path=ROOT / "config/detection_rules.yml",
    )
