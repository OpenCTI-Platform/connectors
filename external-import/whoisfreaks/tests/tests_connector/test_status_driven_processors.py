"""Tests for status-driven feed availability."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from connector.data_processors.nrd import NRDProcessor
from connector.data_processors.threat_feed import ThreatFeedProcessor
from whoisfreaks_client.status import FeedStatus, WhoisFreaksStatus

AVAILABLE_DATE = "2026-09-27"
UNAVAILABLE_DATE = "2026-09-26"
NEXT_DATE = "2026-09-27"


def _build_status(
    *,
    malware: str = AVAILABLE_DATE,
    phishing: str = AVAILABLE_DATE,
    spam: str = AVAILABLE_DATE,
    gtld: str = AVAILABLE_DATE,
    cctld: str = AVAILABLE_DATE,
) -> WhoisFreaksStatus:
    """Build a deterministic status snapshot."""
    return WhoisFreaksStatus(
        malware=FeedStatus(
            last_update=malware,
            available_from="2026-09-28T00:00:00Z",
        ),
        phishing=FeedStatus(
            last_update=phishing,
            available_from="2026-09-28T00:00:00Z",
        ),
        spam=FeedStatus(
            last_update=spam,
            available_from="2026-09-28T00:00:00Z",
        ),
        gtld=FeedStatus(
            last_update=gtld,
            available_from="2026-09-28T00:00:00Z",
        ),
        cctld=FeedStatus(
            last_update=cctld,
            available_from="2026-09-28T00:00:00Z",
        ),
    )


def _build_config() -> SimpleNamespace:
    """Build the configuration required by processor.collect()."""
    return SimpleNamespace(
        import_since=datetime(
            2026,
            9,
            1,
            tzinfo=timezone.utc,
        ),
        page_limit=100,
        checkpoint_every_pages=10,
        threat_timeout=180,
        nrd_timeout=180,
        max_retries=0,
        retry_backoff_seconds=0.1,
    )


def _build_processor_settings() -> SimpleNamespace:
    """Build processor settings with the WhoisFreaks configuration."""
    return SimpleNamespace(
        whoisfreaks=_build_config(),
    )


def _prepare_threat_processor(
    feed_type: str,
    status: WhoisFreaksStatus,
    *,
    last_completed: str = "",
    offset: int = 0,
) -> ThreatFeedProcessor:
    """Build a threat-feed processor with mocked runtime dependencies.

    By default last_completed is empty so a new snapshot is always treated
    as needing ingest. Pass last_completed=AVAILABLE_DATE and offset=0 to
    exercise the already-ingested skip path.
    """
    processor = ThreatFeedProcessor(feed_type=feed_type)

    processor.settings = _build_processor_settings()
    processor.state = MagicMock()
    processor.state.get_next_date.return_value = last_completed
    processor.state.get_threat_offset.return_value = offset
    processor.logger = MagicMock()
    processor.client = MagicMock()
    processor.client.iter_threat_feed.return_value = iter([])
    processor.work_manager = MagicMock()
    processor.set_status(status)

    return processor


def _prepare_nrd_processor(
    feed_name: str,
    status: WhoisFreaksStatus,
) -> NRDProcessor:
    """Build an NRD processor with mocked runtime dependencies."""
    processor = NRDProcessor(feed_name=feed_name)

    processor.settings = _build_processor_settings()
    processor.state = MagicMock()
    processor.state.get_next_nrd_date.return_value = NEXT_DATE
    processor.state.get_nrd_offset.return_value = 0
    processor.logger = MagicMock()
    processor.client = MagicMock()
    processor.client.iter_feed.return_value = iter([])
    processor.set_status(status)

    return processor


@pytest.mark.parametrize(
    "feed_type",
    [
        "malware",
        "phishing",
        "spam",
    ],
)
def test_threat_feed_fetches_only_last_update(
    feed_type: str,
) -> None:
    """Only the status last_update day is fetched (no historical multi-day backfill)."""
    processor = _prepare_threat_processor(
        feed_type,
        _build_status(),
        last_completed="",  # never ingested
        offset=0,
    )

    result = processor.collect()
    # Materialize generator so client is called
    list(result)

    calls = processor.client.iter_threat_feed.call_args_list
    assert len(calls) == 1
    assert calls[0].kwargs["feed_type"] == feed_type
    assert calls[0].kwargs["feed_date"].isoformat() == AVAILABLE_DATE
    assert calls[0].kwargs["limit"] == 100
    assert calls[0].kwargs["start_offset"] == 0


@pytest.mark.parametrize(
    "feed_type",
    [
        "malware",
        "phishing",
        "spam",
    ],
)
def test_threat_feed_skips_when_snapshot_already_ingested(
    feed_type: str,
) -> None:
    """Skip when the current status date was already fully ingested."""
    processor = _prepare_threat_processor(
        feed_type,
        _build_status(),
        last_completed=AVAILABLE_DATE,
        offset=0,
    )

    result = list(processor.collect())

    assert result == []
    processor.client.iter_threat_feed.assert_not_called()


@pytest.mark.parametrize(
    "feed_name",
    [
        "nrd_gtld_with_whois",
        "nrd_gtld_without_whois",
    ],
)
def test_gtld_nrd_uses_gtld_status(feed_name: str) -> None:
    """gTLD NRD feeds consult the gtld status entry."""
    processor = _prepare_nrd_processor(
        feed_name,
        _build_status(),
    )

    list(processor.collect())

    processor.client.iter_feed.assert_called_once()
    kwargs = processor.client.iter_feed.call_args.kwargs
    assert kwargs["feed_type"] == "gtld"
    assert kwargs["feed_date"].isoformat() == NEXT_DATE


@pytest.mark.parametrize(
    "feed_name",
    [
        "nrd_cctld_with_whois",
        "nrd_cctld_without_whois",
    ],
)
def test_cctld_nrd_uses_cctld_status(feed_name: str) -> None:
    """ccTLD NRD feeds consult the cctld status entry."""
    processor = _prepare_nrd_processor(
        feed_name,
        _build_status(),
    )

    list(processor.collect())

    processor.client.iter_feed.assert_called_once()
    kwargs = processor.client.iter_feed.call_args.kwargs
    assert kwargs["feed_type"] == "cctld"
