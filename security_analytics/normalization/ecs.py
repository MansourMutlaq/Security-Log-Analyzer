"""Conversion of normalized events into ECS-compatible documents."""

from __future__ import annotations

from typing import Any

from security_analytics.models import SecurityEvent


def _utc_isoformat(event: SecurityEvent) -> str:
    """Return an ECS-compatible UTC timestamp."""

    return event.timestamp.isoformat().replace("+00:00", "Z")


def to_ecs_document(event: SecurityEvent) -> dict[str, Any]:
    """Convert a normalized event into an ECS-compatible dictionary."""

    document: dict[str, Any] = {
        "@timestamp": _utc_isoformat(event),
        "message": event.message,
        "event": {
            "id": str(event.event_id),
            "category": event.category,
            "type": event.event_type,
            "outcome": event.outcome.value,
            "action": event.action,
            "dataset": event.source.value,
        },
        "labels": {
            "log_source": event.source.value,
        },
        "security_analytics": {
            "attributes": event.attributes,
        },
    }

    if event.host_name:
        document["host"] = {"name": event.host_name}

    if event.source_ip:
        document["source"] = {"ip": str(event.source_ip)}

    if event.user_name:
        document["user"] = {"name": event.user_name}

    if event.resource:
        document["resource"] = {"name": event.resource}

    return document