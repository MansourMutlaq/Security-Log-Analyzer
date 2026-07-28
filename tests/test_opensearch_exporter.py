
"""Tests for OpenSearch document export."""



from unittest.mock import MagicMock

import pytest

from security_analytics.exporters.opensearch import (
    create_opensearch_client,
    export_to_opensearch,
)
from security_analytics.pipeline import AnalysisResult


def test_export_to_opensearch_indexes_events_and_alerts(

    analysis_result: AnalysisResult,

) -> None:

    """All normalized events and alerts should be indexed."""

    client = MagicMock()



    summary = export_to_opensearch(

        analysis_result,

        client=client,

        index_prefix="Infrastructure Security",

    )



    assert summary.events_indexed == len(analysis_result.events)

    assert summary.alerts_indexed == len(analysis_result.alerts)



    assert summary.event_index.startswith(

        "infrastructure-security-events-"

    )

    assert summary.alert_index.startswith(

        "infrastructure-security-alerts-"

    )



    assert client.index.call_count == (

        len(analysis_result.events)

        + len(analysis_result.alerts)

    )



    first_event_call = client.index.call_args_list[0]

    assert first_event_call.kwargs["index"] == summary.event_index

    assert "@timestamp" in first_event_call.kwargs["body"]

    assert "event" in first_event_call.kwargs["body"]



    first_alert_call = client.index.call_args_list[

        len(analysis_result.events)

    ]

    assert first_alert_call.kwargs["index"] == summary.alert_index

    assert (

        first_alert_call.kwargs["body"]["document_kind"]

        == "security_alert"

    )



    client.indices.refresh.assert_any_call(

        index=summary.event_index

    )

    client.indices.refresh.assert_any_call(

        index=summary.alert_index

    )





def test_export_to_opensearch_rejects_empty_index_prefix(

    analysis_result: AnalysisResult,

) -> None:

    """An empty index prefix should be rejected before indexing."""

    with pytest.raises(

        ValueError,

        match="index prefix cannot be empty",

    ):

        export_to_opensearch(

            analysis_result,

            client=MagicMock(),

            index_prefix="---",

        )





def test_create_client_rejects_invalid_endpoint() -> None:

    """The client factory should reject unsupported endpoint schemes."""

    with pytest.raises(

        ValueError,

        match="http or https",

    ):

        create_opensearch_client("ftp://localhost:9200")





def test_create_client_requires_complete_credentials() -> None:

    """Partial OpenSearch credentials should not be accepted."""

    with pytest.raises(

        ValueError,

        match="provided together",

    ):

        create_opensearch_client(

            "https://localhost:9200",

            username="admin",

        )

