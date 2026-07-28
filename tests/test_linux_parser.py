"""Linux authentication parser tests."""

from ipaddress import ip_address
from pathlib import Path

from security_analytics.models import EventOutcome
from security_analytics.parsers import LinuxAuthParser

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/linux/auth_attack.log"


def test_linux_sample_batch() -> None:
    batch = LinuxAuthParser().parse_file(SAMPLE)

    assert len(batch.events) == 6
    assert len(batch.rejected) == 0
    assert [event.action for event in batch.events].count("ssh_login_failed") == 4


def test_linux_invalid_user_failure() -> None:
    event = LinuxAuthParser().parse_file(SAMPLE).events[0]

    assert event.user_name == "admin"
    assert event.source_ip == ip_address("198.51.100.24")
    assert event.outcome == EventOutcome.FAILURE
    assert event.attributes["invalid_user"] is True


def test_linux_successful_authentication() -> None:
    event = LinuxAuthParser().parse_file(SAMPLE).events[4]

    assert event.action == "ssh_login_success"
    assert event.user_name == "ops-admin"
    assert event.outcome == EventOutcome.SUCCESS
    assert event.attributes["source_port"] == 51005


def test_linux_sensitive_sudo_command() -> None:
    event = LinuxAuthParser().parse_file(SAMPLE).events[5]

    assert event.action == "sudo_command"
    assert event.user_name == "ops-admin"
    assert event.resource == "/usr/bin/cat /etc/shadow"
    assert event.attributes["target_user"] == "root"


def test_linux_invalid_record_is_rejected(tmp_path: Path) -> None:
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "not a supported auth event\n"
        "Jul 27 20:16:28 srv-auth-01 "
        "sshd[4105]: Accepted password for ops-admin "
        "from 198.51.100.24 port 51005 ssh2\n",
        encoding="utf-8",
    )

    batch = LinuxAuthParser().parse_file(log_file)

    assert len(batch.events) == 1
    assert len(batch.rejected) == 1
