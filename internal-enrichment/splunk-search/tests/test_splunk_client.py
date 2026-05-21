from unittest.mock import Mock, patch

import pytest
from internal_enrichment_connector.services.splunk_client import SplunkClient


@patch("internal_enrichment_connector.services.splunk_client.client.connect")
def test_init_connects_with_splunk_sdk(connect):
    service = Mock()
    connect.return_value = service

    client = SplunkClient(
        host="splunk.example.com",
        port="8089",
        token="token",
        app="search",
        scheme="https",
        verify=True,
    )

    assert client.service is service
    connect.assert_called_once_with(
        host="splunk.example.com",
        port=8089,
        token="token",
        app="search",
        scheme="https",
    )


@patch("internal_enrichment_connector.services.splunk_client.time.sleep")
@patch("internal_enrichment_connector.services.splunk_client.results.JSONResultsReader")
@patch("internal_enrichment_connector.services.splunk_client.client.connect")
def test_run_search_normalizes_query_and_returns_dict_rows(connect, reader, sleep):
    job = Mock()
    job.is_done.return_value = True
    job.results.return_value = "stream"
    service = Mock()
    service.jobs.create.return_value = job
    connect.return_value = service
    reader.return_value = [{"src": "1.2.3.4"}, "message", {"dest": "example.com"}]
    splunk = SplunkClient("splunk", 8089, "token")

    rows = splunk.run_search("index=main src=1.2.3.4", max_results=25)

    assert rows == [{"src": "1.2.3.4"}, {"dest": "example.com"}]
    service.jobs.create.assert_called_once_with(
        "search index=main src=1.2.3.4",
        earliest_time="-30d@d",
        latest_time="now",
        exec_mode="normal",
        max_count=25,
    )
    job.results.assert_called_once_with(output_mode="json", count=25)
    sleep.assert_not_called()


@patch("internal_enrichment_connector.services.splunk_client.results.JSONResultsReader")
@patch("internal_enrichment_connector.services.splunk_client.client.connect")
def test_run_search_keeps_pipeline_query(connect, reader):
    job = Mock()
    job.is_done.return_value = True
    job.results.return_value = "stream"
    service = Mock()
    service.jobs.create.return_value = job
    connect.return_value = service
    reader.return_value = []
    splunk = SplunkClient("splunk", 8089, "token")

    splunk.run_search("| tstats count", earliest_time="-1d", latest_time="now")

    assert service.jobs.create.call_args.args[0] == "| tstats count"


@patch("internal_enrichment_connector.services.splunk_client.time.sleep")
@patch("internal_enrichment_connector.services.splunk_client.client.connect")
def test_run_search_cancels_on_timeout(connect, sleep):
    job = Mock()
    job.is_done.return_value = False
    service = Mock()
    service.jobs.create.return_value = job
    connect.return_value = service
    splunk = SplunkClient("splunk", 8089, "token")

    with pytest.raises(TimeoutError, match="timed out"):
        splunk.run_search("index=main", timeout=2, wait_seconds=2)

    job.cancel.assert_called_once()


@patch("internal_enrichment_connector.services.splunk_client.client.connect")
def test_health_check_reports_success_and_failure(connect):
    service = Mock()
    connect.return_value = service
    splunk = SplunkClient("splunk", 8089, "token")

    assert splunk.health_check() is True

    service.apps.list.side_effect = RuntimeError("boom")
    assert splunk.health_check() is False
