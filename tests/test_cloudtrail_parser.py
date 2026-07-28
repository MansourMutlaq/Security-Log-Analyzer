"""AWS CloudTrail parser tests."""

import json
from ipaddress import ip_address
from pathlib import Path

from security_analytics.models import EventOutcome
from security_analytics.parsers import CloudTrailParser

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/aws/cloudtrail_events.jsonl"


def test_cloudtrail_sample_batch() -> None:
    batch = CloudTrailParser().parse_file(SAMPLE)

    assert len(batch.events) == 4
    assert len(batch.rejected) == 0
    assert [event.action for event in batch.events] == [
        "ConsoleLogin",
        "StopLogging",
        "AttachUserPolicy",
        "AuthorizeSecurityGroupIngress",
    ]


def test_cloudtrail_root_console_login() -> None:
    event = CloudTrailParser().parse_file(SAMPLE).events[0]

    assert event.user_name == "root"
    assert event.source_ip == ip_address("198.51.100.50")
    assert event.outcome == EventOutcome.SUCCESS
    assert event.attributes["identity_type"] == "Root"


def test_cloudtrail_stop_logging_resource() -> None:
    event = CloudTrailParser().parse_file(SAMPLE).events[1]

    assert event.action == "StopLogging"
    assert event.resource == "organization-trail"
    assert event.user_name == "audit-admin"


def test_cloudtrail_public_ingress_resource() -> None:
    event = CloudTrailParser().parse_file(SAMPLE).events[3]

    assert event.action == "AuthorizeSecurityGroupIngress"
    assert event.resource == "sg-0123456789abcdef0"
    assert event.user_name == "session-01"


def test_cloudtrail_invalid_json_is_rejected(tmp_path: Path) -> None:
    valid_record = {
        "eventTime": "2026-07-27T17:20:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "198.51.100.50",
        "userIdentity": {"type": "Root"},
    }

    log_file = tmp_path / "cloudtrail.jsonl"
    log_file.write_text(
        "{invalid json}\n" + json.dumps(valid_record) + "\n",
        encoding="utf-8",
    )

    batch = CloudTrailParser().parse_file(log_file)

    assert len(batch.events) == 1
    assert len(batch.rejected) == 1
