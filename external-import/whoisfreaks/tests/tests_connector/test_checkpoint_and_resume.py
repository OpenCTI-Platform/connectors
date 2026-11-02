"""Tests for checkpoint/resume and subscription error paths."""

from __future__ import annotations

from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from connector.data_processors.nrd import NRDProcessor
from connector.data_processors.threat_feed import ThreatFeedProcessor
from connector.state import ConnectorState
from whoisfreaks_client.api_client import (
    ThreatFeedPage,
    WhoisFreaksSubscriptionError,
)
from whoisfreaks_client.models import ThreatFeedRecord
from whoisfreaks_client.nrd_client import (
    NRDPage,
    NRDRecord,
    WhoisFreaksNRDSubscriptionError,
)
from whoisfreaks_client.status import FeedStatus, WhoisFreaksStatus

AVAILABLE_DATE = "2026-09-27"
_AVAILABLE_DATE = date(2026, 9, 27)


def _make_threat_record(domain: str = "example.com") -> ThreatFeedRecord:
    return ThreatFeedRecord(
        domain=domain,
        threat_type="malware",
        confidence_score=0.9,
        first_seen=datetime(2026, 9, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 2, tzinfo=timezone.utc),
        No_of_threat_matched_pivots=1,
    )


def _make_nrd_record(domain: str = "example.com") -> NRDRecord:
    return NRDRecord(domain_name=domain, fields={"domain_name": domain})


def _build_status(last_update: str = AVAILABLE_DATE) -> WhoisFreaksStatus:
    fs = FeedStatus(last_update=last_update, available_from="2026-09-28T00:00:00Z")
    return WhoisFreaksStatus(malware=fs, phishing=fs, spam=fs, gtld=fs, cctld=fs)


def _build_processor_settings(
    page_limit: int = 100, checkpoint_every: int = 2
) -> SimpleNamespace:
    return SimpleNamespace(
        whoisfreaks=SimpleNamespace(
            import_since=datetime(2026, 9, 27, tzinfo=timezone.utc),
            page_limit=page_limit,
            checkpoint_every_pages=checkpoint_every,
            threat_timeout=10,
            nrd_timeout=10,
            max_retries=0,
            retry_backoff_seconds=0.1,
        )
    )


# ---------------------------------------------------------------------------
# Checkpoint / resume — ThreatFeedProcessor
# ---------------------------------------------------------------------------


class TestThreatFeedCheckpoint:
    def _prepare(
        self,
        *,
        last_completed: str = "",
        start_offset: int = 0,
        offset_date: str = "",
        checkpoint_every: int = 2,
    ) -> ThreatFeedProcessor:
        processor = ThreatFeedProcessor("malware")
        processor.settings = _build_processor_settings(
            checkpoint_every=checkpoint_every
        )
        processor.state = MagicMock(spec=ConnectorState)
        processor.state.get_next_date.return_value = last_completed
        processor.state.get_threat_offset.return_value = start_offset
        processor.state.get_threat_offset_date.return_value = offset_date
        processor.logger = MagicMock()
        processor.client = MagicMock()
        processor.work_manager = MagicMock()
        processor.work_manager.helper = None
        processor.set_status(_build_status())
        return processor

    def test_offset_is_updated_every_n_pages(self):
        """The in-memory offset advances every checkpoint interval."""
        # New date detected: starts with last_completed="" (never completed)
        # and start_offset=0.
        processor = self._prepare(checkpoint_every=2, last_completed="")

        # 4 pages of 1 record each → 2 checkpoints mid-run + 1 on completion.
        processor.client.iter_threat_feed.return_value = iter(
            [[_make_threat_record(f"d{i}.com")] for i in range(4)]
        )

        result = list(processor.collect())
        assert len(result) == 4

        # Offsets advance for pages 2 and 4; completion advances the date.
        assert processor.state.set_threat_offset.call_count == 2
        assert processor.state.set_next_date.call_count == 1
        processor.state.save.assert_not_called()

    def test_resume_from_saved_offset(self):
        """Processor must forward the saved start_offset to the client."""
        # Same date as status -> resuming existing date with saved offset
        processor = self._prepare(
            start_offset=5000,
            last_completed="2026-09-26",
            offset_date=AVAILABLE_DATE,
        )

        processor.client.iter_threat_feed.return_value = iter([])

        list(processor.collect())

        kwargs = processor.client.iter_threat_feed.call_args.kwargs
        assert kwargs["start_offset"] == 5000

    def test_resume_offset_is_preserved_for_next_day(self):
        """A checkpoint resumes the incomplete day after the last completed day."""
        processor = self._prepare(
            start_offset=9999,
            last_completed="2026-09-26",
            offset_date=AVAILABLE_DATE,
        )

        processor.client.iter_threat_feed.return_value = iter([])

        list(processor.collect())

        # The incomplete day's offset is passed through unchanged.
        kwargs = processor.client.iter_threat_feed.call_args.kwargs
        assert kwargs["start_offset"] == 9999

    def test_initial_partial_run_resumes_from_matching_snapshot_date(self):
        processor = self._prepare(start_offset=5000, offset_date=AVAILABLE_DATE)
        processor.client.iter_threat_feed.return_value = iter([])

        list(processor.collect())

        assert (
            processor.client.iter_threat_feed.call_args.kwargs["start_offset"] == 5000
        )

    def test_offset_resets_when_status_advances(self):
        processor = self._prepare(start_offset=5000, offset_date=AVAILABLE_DATE)
        processor.set_status(_build_status("2026-09-28"))
        processor.client.iter_threat_feed.return_value = iter([])

        list(processor.collect())

        assert processor.client.iter_threat_feed.call_args.kwargs["start_offset"] == 0

    def test_checkpoint_counts_skipped_source_rows(self):
        processor = self._prepare(checkpoint_every=1)
        processor.client.iter_threat_feed.return_value = iter(
            [ThreatFeedPage([_make_threat_record()], 3)]
        )

        list(processor.collect())

        processor.state.set_threat_offset.assert_called_once_with(
            "malware",
            3,
            snapshot_date=AVAILABLE_DATE,
        )


# ---------------------------------------------------------------------------
# Checkpoint / resume — NRDProcessor
# ---------------------------------------------------------------------------


class TestNRDCheckpoint:
    def _prepare(
        self,
        *,
        next_date: str = AVAILABLE_DATE,
        start_offset: int = 0,
        offset_date: str = "",
        checkpoint_every: int = 2,
    ) -> NRDProcessor:
        processor = NRDProcessor("nrd_gtld_without_whois")
        processor.settings = _build_processor_settings(
            checkpoint_every=checkpoint_every
        )
        processor.state = MagicMock(spec=ConnectorState)
        processor.state.get_next_nrd_date.return_value = next_date
        processor.state.get_nrd_offset.return_value = start_offset
        processor.state.get_nrd_offset_date.return_value = offset_date
        processor.logger = MagicMock()
        processor.client = MagicMock()
        processor.set_status(_build_status())
        return processor

    def test_offset_is_updated_every_n_pages(self):
        """The in-memory offset advances every checkpoint interval."""
        processor = self._prepare(checkpoint_every=2)

        # 4 pages → 2 offset updates + 1 day completion.
        processor.client.iter_feed.return_value = iter(
            [[_make_nrd_record(f"d{i}.com")] for i in range(4)]
        )

        result = list(processor.collect())
        assert len(result) == 4
        assert processor.state.set_nrd_offset.call_count == 2
        assert processor.state.set_next_nrd_date.call_count == 1
        processor.state.save.assert_not_called()

    def test_resume_from_saved_offset(self):
        """Processor must forward the saved start_offset to the client."""
        processor = self._prepare(start_offset=3000, offset_date=AVAILABLE_DATE)

        processor.client.iter_feed.return_value = iter([])

        list(processor.collect())

        kwargs = processor.client.iter_feed.call_args.kwargs
        assert kwargs["start_offset"] == 3000

    def test_initial_partial_run_resumes_from_matching_snapshot_date(self):
        processor = self._prepare(
            next_date="",
            start_offset=3000,
            offset_date=AVAILABLE_DATE,
        )
        processor.client.iter_feed.return_value = iter([])

        list(processor.collect())

        assert processor.client.iter_feed.call_args.kwargs["start_offset"] == 3000

    def test_offset_resets_when_status_advances(self):
        processor = self._prepare(start_offset=3000, offset_date=AVAILABLE_DATE)
        processor.set_status(_build_status("2026-09-28"))
        processor.client.iter_feed.return_value = iter([])

        list(processor.collect())

        assert processor.client.iter_feed.call_args.kwargs["start_offset"] == 0

    def test_fetches_only_last_update_day(self):
        """collect() fetches only status last_update, even if next_date is older."""
        processor = self._prepare(next_date="2026-09-25")
        # Status says latest is 2026-09-27 → only that day is fetched.
        processor.client.iter_feed.return_value = iter([])

        list(processor.collect())

        assert processor.client.iter_feed.call_count == 1
        kwargs = processor.client.iter_feed.call_args.kwargs
        assert kwargs["feed_date"] == date(2026, 9, 27)
        assert kwargs["start_offset"] == 0

    def test_checkpoint_counts_skipped_source_rows(self):
        processor = self._prepare(checkpoint_every=1)
        processor.client.iter_feed.return_value = iter(
            [NRDPage([_make_nrd_record()], 3)]
        )

        list(processor.collect())

        processor.state.set_nrd_offset.assert_called_once_with(
            "nrd_gtld_without_whois",
            3,
            snapshot_date=AVAILABLE_DATE,
        )


# ---------------------------------------------------------------------------
# Subscription error path
# ---------------------------------------------------------------------------


class TestSubscriptionErrors:
    def test_threat_feed_subscription_error_is_logged_and_skipped(self):
        """A 401/403 must log WARNING and return empty, not re-raise."""
        processor = ThreatFeedProcessor("phishing")
        processor.settings = _build_processor_settings()
        processor.state = MagicMock(spec=ConnectorState)
        processor.state.get_next_date.return_value = ""
        processor.state.get_threat_offset.return_value = 0
        processor.logger = MagicMock()
        processor.client = MagicMock()
        processor.work_manager = MagicMock()
        processor.work_manager.helper = None
        processor.set_status(_build_status())

        processor.client.iter_threat_feed.side_effect = WhoisFreaksSubscriptionError(
            "Access denied to phishing feed"
        )

        # collect() must return an iterable, not raise.
        result = list(processor.collect())
        assert result == []

        processor.logger.warning.assert_called()
        warning_msg = processor.logger.warning.call_args[0][0]
        assert (
            "Subscription error" in warning_msg or "subscription" in warning_msg.lower()
        )
        meta = processor.logger.warning.call_args.kwargs["meta"]
        assert meta["feed_type"] == "phishing"
        assert "Access denied" in meta["error"]

    def test_nrd_subscription_error_is_logged_and_skipped(self):
        """A 401/403 on an NRD feed must log WARNING and return empty, not re-raise."""
        processor = NRDProcessor("nrd_cctld_with_whois")
        processor.settings = _build_processor_settings()
        processor.state = MagicMock(spec=ConnectorState)
        processor.state.get_next_nrd_date.return_value = AVAILABLE_DATE
        processor.state.get_nrd_offset.return_value = 0
        processor.logger = MagicMock()
        processor.client = MagicMock()
        processor.set_status(_build_status())

        processor.client.iter_feed.side_effect = WhoisFreaksNRDSubscriptionError(
            "Access denied to cctld NRD feed"
        )

        result = list(processor.collect())
        assert result == []

        processor.logger.warning.assert_called()
        warning_msg = processor.logger.warning.call_args[0][0]
        assert (
            "Subscription error" in warning_msg or "subscription" in warning_msg.lower()
        )
        meta = processor.logger.warning.call_args.kwargs["meta"]
        assert meta["feed_name"] == "nrd_cctld_with_whois"
        assert "Access denied" in meta["error"]


# ---------------------------------------------------------------------------
# Conversion failures must not advance checkpoints
# ---------------------------------------------------------------------------


def _fail_on(domains: set[str], original):
    def _to_stix(record, tlp, **kwargs):
        name = getattr(record, "domain", None) or record.domain_name
        if name in domains:
            raise ValueError("boom")
        return original(record, tlp, **kwargs)

    return _to_stix


def _domain_values(bundles) -> set[str]:
    return {
        obj["value"]
        for objects in bundles
        for obj in objects
        if getattr(obj, "type", None) == "domain-name"
    }


class TestConversionFailureCheckpoint:
    def _threat_processor(self, pages) -> ThreatFeedProcessor:
        processor = TestThreatFeedCheckpoint()._prepare(checkpoint_every=1)
        processor.settings.whoisfreaks.tlp_level = "amber"
        processor._author = MagicMock()
        processor.client.iter_threat_feed.return_value = iter(pages)
        return processor

    def _nrd_processor(self, pages) -> NRDProcessor:
        processor = TestNRDCheckpoint()._prepare(next_date="", checkpoint_every=1)
        processor.settings.whoisfreaks.tlp_level = "amber"
        processor.settings.whoisfreaks.create_indicators_for_nrd = False
        processor._author = MagicMock()
        processor.client.iter_feed.return_value = iter(pages)
        return processor

    def test_threat_mixed_success_freezes_checkpoint_before_failed_page(self):
        pages = [
            [_make_threat_record("ok1.com")],
            [_make_threat_record("bad.com"), _make_threat_record("ok2.com")],
            [_make_threat_record("ok3.com")],
        ]
        processor = self._threat_processor(pages)
        processor._to_stix = _fail_on({"bad.com"}, processor._to_stix)

        bundles = list(processor.transform(processor.collect()))

        # Valid records, including those after the failed page, are emitted.
        assert _domain_values(bundles) == {"ok1.com", "ok2.com", "ok3.com"}
        # Only the page before the failure is checkpointed.
        processor.state.set_threat_offset.assert_called_once_with(
            "malware", 1, snapshot_date=AVAILABLE_DATE
        )
        processor.state.set_next_date.assert_not_called()

    def test_threat_all_failed_page_does_not_complete_snapshot(self):
        pages = [[_make_threat_record("bad1.com"), _make_threat_record("bad2.com")]]
        processor = self._threat_processor(pages)
        processor._to_stix = _fail_on({"bad1.com", "bad2.com"}, processor._to_stix)

        bundles = list(processor.transform(processor.collect()))

        assert bundles == []
        processor.state.set_threat_offset.assert_not_called()
        processor.state.set_next_date.assert_not_called()

    def test_threat_successful_run_completes_snapshot(self):
        processor = self._threat_processor([[_make_threat_record("ok.com")]])

        list(processor.transform(processor.collect()))

        processor.state.set_next_date.assert_called_once_with("malware", AVAILABLE_DATE)

    def test_nrd_mixed_success_freezes_checkpoint_before_failed_page(self):
        pages = [
            [_make_nrd_record("ok1.com")],
            [_make_nrd_record("bad.com"), _make_nrd_record("ok2.com")],
            [_make_nrd_record("ok3.com")],
        ]
        processor = self._nrd_processor(pages)
        processor._to_stix = _fail_on({"bad.com"}, processor._to_stix)

        bundles = list(processor.transform(processor.collect()))

        assert _domain_values(bundles) == {"ok1.com", "ok2.com", "ok3.com"}
        processor.state.set_nrd_offset.assert_called_once_with(
            "nrd_gtld_without_whois", 1, snapshot_date=AVAILABLE_DATE
        )
        processor.state.set_next_nrd_date.assert_not_called()

    def test_nrd_all_failed_page_does_not_complete_day(self):
        pages = [[_make_nrd_record("bad1.com"), _make_nrd_record("bad2.com")]]
        processor = self._nrd_processor(pages)
        processor._to_stix = _fail_on({"bad1.com", "bad2.com"}, processor._to_stix)

        bundles = list(processor.transform(processor.collect()))

        assert bundles == []
        processor.state.set_nrd_offset.assert_not_called()
        processor.state.set_next_nrd_date.assert_not_called()

    def test_nrd_successful_run_completes_day(self):
        processor = self._nrd_processor([[_make_nrd_record("ok.com")]])

        list(processor.transform(processor.collect()))

        processor.state.set_next_nrd_date.assert_called_once_with(
            "nrd_gtld_without_whois", "2026-09-28"
        )
