
"""OpenSearch export support for normalized events and security alerts."""



from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from opensearchpy import OpenSearch
from pydantic import BaseModel

from security_analytics.normalization import to_ecs_document
from security_analytics.pipeline import AnalysisResult


@dataclass(frozen=True, slots=True)

class OpenSearchExportSummary:

    """Describe the documents exported during one analysis run."""



    event_index: str

    alert_index: str

    events_indexed: int

    alerts_indexed: int





def create_opensearch_client(

    endpoint: str,

    *,

    username: str | None = None,

    password: str | None = None,

    verify_certs: bool = True,

    request_timeout: int = 10,

) -> OpenSearch:

    """Create an OpenSearch client from one HTTP or HTTPS endpoint."""

    parsed = urlparse(endpoint)



    if parsed.scheme not in {"http", "https"}:

        raise ValueError(

            "OpenSearch endpoint must use the http or https scheme."

        )



    if parsed.hostname is None:

        raise ValueError("OpenSearch endpoint must include a hostname.")



    if bool(username) != bool(password):

        raise ValueError(

            "OpenSearch username and password must be provided together."

        )



    use_ssl = parsed.scheme == "https"

    host: dict[str, Any] = {

        "host": parsed.hostname,

        "port": parsed.port or (443 if use_ssl else 80),

        "scheme": parsed.scheme,

    }



    client_options: dict[str, Any] = {

        "hosts": [host],

        "use_ssl": use_ssl,

        "verify_certs": verify_certs,

        "timeout": request_timeout,

        "max_retries": 2,

        "retry_on_timeout": True,

    }



    if use_ssl:

        client_options["ssl_assert_hostname"] = verify_certs

        client_options["ssl_show_warn"] = verify_certs



    if username is not None and password is not None:

        client_options["http_auth"] = (username, password)



    return OpenSearch(**client_options)





def export_to_opensearch(

    result: AnalysisResult,

    *,

    endpoint: str = "http://localhost:9200",

    index_prefix: str = "security-analytics",

    username: str | None = None,

    password: str | None = None,

    verify_certs: bool = True,

    client: OpenSearch | None = None,

) -> OpenSearchExportSummary:

    """Index normalized events and alerts into OpenSearch."""

    normalized_prefix = _normalize_index_prefix(index_prefix)

    date_suffix = result.started_at.strftime("%Y.%m.%d")



    event_index = f"{normalized_prefix}-events-{date_suffix}"

    alert_index = f"{normalized_prefix}-alerts-{date_suffix}"



    opensearch = client or create_opensearch_client(

        endpoint,

        username=username,

        password=password,

        verify_certs=verify_certs,

    )



    for event in result.events:

        opensearch.index(

            index=event_index,

            body=to_ecs_document(event),

            refresh=False,

        )



    for alert in result.alerts:

        opensearch.index(

            index=alert_index,

            body=_alert_to_document(alert),

            refresh=False,

        )



    if result.events:

        opensearch.indices.refresh(index=event_index)



    if result.alerts:

        opensearch.indices.refresh(index=alert_index)



    return OpenSearchExportSummary(

        event_index=event_index,

        alert_index=alert_index,

        events_indexed=len(result.events),

        alerts_indexed=len(result.alerts),

    )





def _alert_to_document(alert: object) -> dict[str, Any]:

    """Convert one alert dataclass into a JSON-compatible document."""

    document = _serialize_value(alert)



    if not isinstance(document, dict):

        raise TypeError("Security alert must serialize into a mapping.")



    document["document_kind"] = "security_alert"



    detected_at = document.get("detected_at")

    if detected_at is not None:

        document.setdefault("@timestamp", detected_at)



    return document





def _serialize_value(value: Any) -> Any:

    """Recursively convert Python values into JSON-compatible values."""

    if isinstance(value, BaseModel):
        return _serialize_value(value.model_dump(mode="json"))

    if is_dataclass(value) and not isinstance(value, type):

        return _serialize_value(asdict(value))



    if isinstance(value, Enum):

        return _serialize_value(value.value)



    if isinstance(value, (datetime, date)):

        return value.isoformat()



    if isinstance(value, (UUID, Path)):

        return str(value)



    if isinstance(value, Mapping):

        return {

            str(key): _serialize_value(item)

            for key, item in value.items()

        }



    if isinstance(value, (list, tuple, set, frozenset)):

        return [_serialize_value(item) for item in value]



    return value





def _normalize_index_prefix(index_prefix: str) -> str:

    """Return an OpenSearch-compatible lowercase index prefix."""

    normalized = re.sub(

        r"[^a-z0-9_-]+",

        "-",

        index_prefix.strip().lower(),

    ).strip("-_")



    if not normalized:

        raise ValueError("OpenSearch index prefix cannot be empty.")



    return normalized

