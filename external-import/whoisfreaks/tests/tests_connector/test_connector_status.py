"""Tests for the WhoisFreaks connector callback."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from main import WhoisFreaksExternalImportConnector
from whoisfreaks_client.status import FeedStatus, WhoisFreaksStatus


def _build_status() -> WhoisFreaksStatus:
    """Build a representative WhoisFreaks status snapshot."""
    feed_status = FeedStatus(
        last_update="2026-09-27",
        available_from="2026-09-27",
    )

    return WhoisFreaksStatus(
        malware=feed_status,
        phishing=feed_status,
        spam=feed_status,
        gtld=feed_status,
        cctld=feed_status,
    )


def _build_connector(
    processors: list[MagicMock],
) -> WhoisFreaksExternalImportConnector:
    """Build a connector with lightweight test settings and state."""
    settings = SimpleNamespace(
        connector=SimpleNamespace(
            name="WhoisFreaks",
        ),
        whoisfreaks=SimpleNamespace(
            api_key=MagicMock(),
            api_base_url="https://files.whoisfreaks.com/v3.4/stream",
            status_api_base_url="https://files.whoisfreaks.com",
            feed_types=["malware", "phishing", "spam"],
            nrd_feed_types=[
                "nrd_gtld_with_whois",
                "nrd_cctld_with_whois",
            ],
        ),
    )

    state = MagicMock()
    state.last_run = None

    connector = WhoisFreaksExternalImportConnector(
        settings=settings,
        state=state,
        data_processors=processors,
    )

    connector.logger = MagicMock()

    return connector


def test_callback_fetches_status_once_and_shares_same_snapshot() -> None:
    """The connector fetches status once and shares it with all processors."""
    first_processor = MagicMock()
    second_processor = MagicMock()

    status = _build_status()

    connector = _build_connector(
        [
            first_processor,
            second_processor,
        ]
    )

    with patch.object(
        connector.status_client,
        "get_status",
        return_value=status,
    ) as get_status:
        connector.callback()

    get_status.assert_called_once_with()

    first_processor.set_status.assert_called_once_with(status)
    second_processor.set_status.assert_called_once_with(status)

    first_processor.process.assert_called_once_with()
    second_processor.process.assert_called_once_with()

    connector.state.save.assert_called()


def test_callback_does_not_fetch_status_per_processor() -> None:
    """Processors receive the connector snapshot instead of fetching status."""
    processors = [
        MagicMock(),
        MagicMock(),
        MagicMock(),
    ]

    status = _build_status()

    connector = _build_connector(processors)

    with patch.object(
        connector.status_client,
        "get_status",
        return_value=status,
    ) as get_status:
        connector.callback()

    get_status.assert_called_once_with()

    for processor in processors:
        processor.set_status.assert_called_once_with(status)
        processor.process.assert_called_once_with()


def test_callback_does_not_save_state_when_processor_fails() -> None:
    processor = MagicMock()
    processor.process.side_effect = RuntimeError("processor failed")
    connector = _build_connector([processor])

    with patch.object(
        connector.status_client, "get_status", return_value=_build_status()
    ):
        with pytest.raises(RuntimeError, match="processor failed"):
            connector.callback()

    connector.state.save.assert_not_called()
    assert connector.state.last_run is None
