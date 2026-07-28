"""Cisco IOS parser tests."""

from ipaddress import ip_address
from pathlib import Path

from security_analytics.models import EventOutcome
from security_analytics.parsers import CiscoIOSParser

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/cisco_ios/security_events.log"


def test_cisco_sample_batch() -> None:
    batch = CiscoIOSParser().parse_file(SAMPLE)

    assert len(batch.events) == 5
    assert len(batch.rejected) == 0
    assert [event.action for event in batch.events] == [
        "cisco_login_failed",
        "cisco_login_success",
        "cisco_configuration_change",
        "cisco_interface_state_change",
        "cisco_interface_state_change",
    ]


def test_cisco_failed_login_fields() -> None:
    event = CiscoIOSParser().parse_file(SAMPLE).events[0]

    assert event.host_name == "CORE-01"
    assert event.user_name == "admin"
    assert event.source_ip == ip_address("198.51.100.10")
    assert event.outcome == EventOutcome.FAILURE
    assert event.attributes["mnemonic"] == "LOGIN_FAILED"


def test_cisco_configuration_change_fields() -> None:
    event = CiscoIOSParser().parse_file(SAMPLE).events[2]

    assert event.action == "cisco_configuration_change"
    assert event.user_name == "netadmin"
    assert event.source_ip == ip_address("198.51.100.11")
    assert event.outcome == EventOutcome.SUCCESS


def test_cisco_interface_state_outcomes() -> None:
    events = CiscoIOSParser().parse_file(SAMPLE).events[3:]

    assert events[0].resource == "GigabitEthernet0/1"
    assert events[0].outcome == EventOutcome.FAILURE
    assert events[1].outcome == EventOutcome.SUCCESS


def test_cisco_invalid_record_is_rejected(tmp_path: Path) -> None:
    log_file = tmp_path / "cisco.log"

    records = [
        "invalid Cisco log record",
        (
            "Jul 27 20:10:12 CORE-01 "
            "%SEC_LOGIN-5-LOGIN_SUCCESS: "
            "Login Success [user: netadmin] "
            "[Source: 198.51.100.11]"
        ),
    ]

    log_file.write_text(
        "\n".join(records) + "\n",
        encoding="utf-8",
    )

    batch = CiscoIOSParser().parse_file(log_file)

    assert len(batch.events) == 1
    assert len(batch.rejected) == 1
    assert batch.rejected[0].line_number == 1