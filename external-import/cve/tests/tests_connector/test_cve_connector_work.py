"""Tests for the work lifecycle of CVEConnector runs.

Validates that:
- Each run sends its bundles with its own work, never with a previous run's work.
- A successful run marks its work as processed.
- A failed run closes its work in error, and the next run still starts its own.
- A run that sends no bundle starts no work.

A work kept across runs stops being alive once it is deleted ("Clear all
works", connector manager cleanup) or its Redis key is lost, and the platform
then silently drops every bundle sent with it.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from src.connector.cve_connector import CVEConnector
from src.services.converter.vulnerability_to_stix2 import CVEConverter

from tests.conftest import make_vulnerability

INTERVAL = 2 * 60 * 60

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_connector(runs: list[list], work_ids: list[str]) -> CVEConnector:
    """Build a CVEConnector whose converter runs the real ingestion pipeline.

    Only the NVD client and the platform calls are mocked. Each item of `runs`
    describes what the NVD client returns during one run: a list of pages
    (lists of CVE ids), where an exception instance is raised when reached,
    once the bundles of the previous pages have been sent (as when the request
    for the next page fails).
    """
    mock_helper = MagicMock()
    mock_helper.connect_id = "test-connector-id"
    mock_helper.connect_name = "CVE Test"
    mock_helper.api.work.initiate_work.side_effect = work_ids

    pending_runs = list(runs)

    async def fake_get_vulnerabilities(cve_params=None):
        expected_sends = mock_helper.send_stix2_bundle.call_count
        for page in pending_runs.pop(0):
            if isinstance(page, Exception):
                async with asyncio.timeout(5):
                    while mock_helper.send_stix2_bundle.call_count < expected_sends:
                        await asyncio.sleep(0.01)
                raise page
            expected_sends += len(page)
            yield [make_vulnerability(cve_id) for cve_id in page]

    with patch.object(CVEConverter, "__init__", lambda self, *a, **kw: None):
        converter = CVEConverter.__new__(CVEConverter)

    converter.helper = mock_helper
    converter.import_software = False
    converter.cpe_max_concurrency = 1
    converter.cpe_history_interval = None
    converter.cve_max_concurrency = 2
    converter.work_id = None
    converter.author = CVEConverter._create_author()
    converter._rate_limiter = MagicMock()
    converter.client_api = MagicMock()
    converter.client_api.get_vulnerabilities = fake_get_vulnerabilities
    converter.client_api.close = AsyncMock()
    converter.cpe_match_client = MagicMock()
    converter.cpe_match_client.close = AsyncMock()

    connector = object.__new__(CVEConnector)
    connector.helper = mock_helper
    connector.converter = converter
    connector.config = MagicMock()
    connector.config.cve.maintain_data = True
    connector.interval = INTERVAL
    return connector


def _run(connector: CVEConnector) -> None:
    """Run process_data once, with a last_run older than the interval."""
    last_run = int(datetime.now(tz=timezone.utc).timestamp()) - INTERVAL - 1
    connector.helper.get_state.return_value = {"last_run": last_run}
    with patch("src.connector.cve_connector.time.sleep"):
        connector.process_data()


def _sent_work_ids(connector: CVEConnector) -> list[str]:
    """Work id of every bundle sent, in order."""
    return [
        call.kwargs["work_id"]
        for call in connector.helper.send_stix2_bundle.call_args_list
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_run_does_not_reuse_a_work_left_by_a_previous_run():
    """A run starts its own work even if the converter still holds an old one."""
    connector = _make_connector(runs=[[["CVE-2024-0001"]]], work_ids=["work_1"])
    connector.converter.work_id = "old_work"

    _run(connector)

    assert _sent_work_ids(connector) == ["work_1"]
    connector.helper.api.work.to_processed.assert_called_once()
    assert connector.helper.api.work.to_processed.call_args.args[0] == "work_1"
    connector.helper.set_state.assert_called_once()


def test_each_run_sends_its_bundles_with_its_own_work():
    """Two runs of the same process start two works and never mix them."""
    connector = _make_connector(
        runs=[[["CVE-2024-0001", "CVE-2024-0002"]], [["CVE-2024-0003"]]],
        work_ids=["work_1", "work_2"],
    )

    _run(connector)
    _run(connector)

    assert connector.helper.api.work.initiate_work.call_count == 2
    assert _sent_work_ids(connector) == ["work_1", "work_1", "work_2"]
    processed = [
        call.args[0] for call in connector.helper.api.work.to_processed.call_args_list
    ]
    assert processed == ["work_1", "work_2"]


def test_failed_run_closes_its_work_in_error():
    """A run failing after sending bundles closes its work in error."""
    connector = _make_connector(
        runs=[
            [["CVE-2024-0001"], RuntimeError("NVD unavailable")],
            [["CVE-2024-0002"]],
        ],
        work_ids=["work_1", "work_2"],
    )

    _run(connector)

    connector.helper.api.work.to_processed.assert_called_once()
    call = connector.helper.api.work.to_processed.call_args
    assert call.args[0] == "work_1"
    assert "NVD unavailable" in call.args[1]
    assert call.kwargs == {"in_error": True}
    connector.helper.set_state.assert_not_called()

    _run(connector)

    assert _sent_work_ids(connector) == ["work_1", "work_2"]


def test_run_failing_before_any_bundle_has_no_work_to_close():
    """A run failing before sending any bundle neither starts nor closes a work."""
    connector = _make_connector(
        runs=[[RuntimeError("Invalid apiKey")]],
        work_ids=["work_1"],
    )

    _run(connector)

    assert "Invalid apiKey" in connector.helper.connector_logger.error.call_args.args[0]
    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()
    connector.helper.set_state.assert_not_called()


def test_failure_to_close_the_work_does_not_hide_the_run_error():
    """If closing the failed run's work fails, the run's error is still logged."""
    connector = _make_connector(
        runs=[
            [["CVE-2024-0001"], RuntimeError("NVD unavailable")],
            [["CVE-2024-0002"]],
        ],
        work_ids=["work_1", "work_2"],
    )
    connector.helper.api.work.to_processed.side_effect = [
        RuntimeError("API down"),
        None,
    ]

    _run(connector)

    error_message = connector.helper.connector_logger.error.call_args.args[0]
    assert "NVD unavailable" in error_message
    connector.helper.connector_logger.warning.assert_called_once()

    _run(connector)

    assert _sent_work_ids(connector) == ["work_1", "work_2"]


def test_run_without_vulnerabilities_starts_no_work():
    """A run with nothing to import starts no work and still stores its state."""
    connector = _make_connector(runs=[[]], work_ids=[])

    _run(connector)

    connector.helper.api.work.initiate_work.assert_not_called()
    connector.helper.api.work.to_processed.assert_not_called()
    connector.helper.set_state.assert_called_once()
