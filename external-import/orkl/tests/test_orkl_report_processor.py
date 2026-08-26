"""Tests for the ORKL report processor pipeline."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

from orkl.converter_to_stix import OrklConverter
from orkl.processors.orkl_report_processor import (
    _CUTOFF_OVERLAP,
    OrklReportProcessor,
    _dedupe_by_id,
)

UTC = timezone.utc


# ---------------------------------------------------------------------------
# Test doubles / helpers
# ---------------------------------------------------------------------------


class FakeClient:
    """Lazy stand-in for OrklClient.iter_library_entries.

    Tracks how many pages have actually been consumed so tests can assert
    the early-break stops paging (the laziness is the feature under test).
    """

    def __init__(self, pages: list[list[dict[str, Any]]]) -> None:
        self._pages = pages
        self.pages_served = 0
        self.call_kwargs: dict[str, Any] | None = None

    def iter_library_entries(self, **kwargs: Any):
        self.call_kwargs = kwargs
        for page in self._pages:
            self.pages_served += 1
            yield page


class _Obj:
    """Minimal object exposing a STIX-like `id` for dedup tests."""

    def __init__(self, id: str) -> None:  # noqa: A002
        self.id = id


def _make_processor(
    *,
    config: Any = None,
    state: Any = None,
    client: Any = None,
    converter: Any = None,
) -> OrklReportProcessor:
    """Build a processor without a real OpenCTIConnectorHelper."""
    proc = OrklReportProcessor.__new__(OrklReportProcessor)
    proc.logger = MagicMock()
    proc._config = config or MagicMock(import_start_date=timedelta(days=30))
    proc.state = state if state is not None else MagicMock(last_run=None)
    proc._client = client or MagicMock()
    proc._converter = converter or MagicMock()
    return proc


def _real_converter() -> OrklConverter:
    return OrklConverter(api_base_url="https://orkl.eu/api/v1", tlp_level="clear")


def _reports(bundle: list[Any]) -> list[Any]:
    return [obj for obj in bundle if obj.id.startswith("report--")]


# ---------------------------------------------------------------------------
# _dedupe_by_id
# ---------------------------------------------------------------------------


class TestDedupeById:
    def test_removes_duplicate_ids_preserving_order(self):
        a, b, c = _Obj("report--a"), _Obj("threat--b"), _Obj("report--a")
        result = _dedupe_by_id([a, b, c])
        assert [o.id for o in result] == ["report--a", "threat--b"]

    def test_empty(self):
        assert _dedupe_by_id([]) == []


# ---------------------------------------------------------------------------
# _resolve_cutoff
# ---------------------------------------------------------------------------


class TestResolveCutoff:
    def test_uses_last_run_when_set(self):
        last_run = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
        proc = _make_processor(state=MagicMock(last_run=last_run))
        assert proc._resolve_cutoff() == last_run - _CUTOFF_OVERLAP

    def test_overlap_applied_to_last_run_path(self):
        last_run = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
        proc = _make_processor(state=MagicMock(last_run=last_run))
        # The cutoff is pulled back by exactly the safety overlap so entries
        # updated mid-run are re-scanned instead of being permanently missed.
        assert last_run - proc._resolve_cutoff() == _CUTOFF_OVERLAP

    def test_overlap_not_applied_to_import_start_date_path(self):
        proc = _make_processor(
            state=MagicMock(last_run=None),
            config=MagicMock(import_start_date=timedelta(days=30)),
        )
        cutoff = proc._resolve_cutoff()
        diff = datetime.now(UTC) - cutoff
        # No overlap here: the window is exactly import_start_date (30 days),
        # not 30 days + _CUTOFF_OVERLAP.
        assert timedelta(days=29, hours=23) <= diff <= timedelta(days=30, minutes=1)

    def test_falls_back_to_now_minus_import_start_date(self):
        proc = _make_processor(
            state=MagicMock(last_run=None),
            config=MagicMock(import_start_date=timedelta(days=30)),
        )
        cutoff = proc._resolve_cutoff()
        diff = datetime.now(UTC) - cutoff
        assert timedelta(days=29, hours=23) <= diff <= timedelta(days=30, minutes=1)

    def test_fallback_honours_configured_timedelta(self):
        proc = _make_processor(
            state=MagicMock(last_run=None),
            config=MagicMock(import_start_date=timedelta(days=7)),
        )
        cutoff = proc._resolve_cutoff()
        diff = datetime.now(UTC) - cutoff
        assert timedelta(days=6, hours=23) <= diff <= timedelta(days=7, minutes=1)

    def test_naive_last_run_made_utc_aware(self):
        proc = _make_processor(state=MagicMock(last_run=datetime(2025, 1, 1)))
        cutoff = proc._resolve_cutoff()
        assert cutoff.tzinfo is not None


# ---------------------------------------------------------------------------
# collect() — cutoff, early break, deleted, unparseable
# ---------------------------------------------------------------------------


class TestCollect:
    def test_sets_work_name_with_window(self, entries_page_data):
        state = MagicMock(last_run=datetime(2025, 1, 1, tzinfo=UTC))
        proc = _make_processor(state=state, client=FakeClient([entries_page_data]))
        list(proc.collect())
        # Cutoff is last_run minus the safety overlap (2025-01-01 - 5min).
        expected = (datetime(2025, 1, 1, tzinfo=UTC) - _CUTOFF_OVERLAP).isoformat()
        assert expected in proc.work_name

    def test_excludes_entries_older_than_cutoff(self, entries_page_data):
        # last_run 2025-01-01 keeps the three 2026 entries, drops the 2020 one.
        state = MagicMock(last_run=datetime(2025, 1, 1, tzinfo=UTC))
        proc = _make_processor(state=state, client=FakeClient([entries_page_data]))
        pages = list(proc.collect())
        surviving = [e for page in pages for e in page]
        ids = [e["id"] for e in surviving]
        assert len(surviving) == 3
        assert "16e09120-0576-4d9c-bec2-3a0ce381033c" not in ids  # the 2020 entry

    def test_early_break_stops_requesting_pages(self, entries_page_data):
        recent, _empty, _dup, old = entries_page_data
        client = FakeClient([[recent, old], [_empty]])
        state = MagicMock(last_run=datetime(2026, 8, 24, tzinfo=UTC))
        proc = _make_processor(state=state, client=client)
        pages = list(proc.collect())
        # `old` (2020) is <= cutoff → break; the second page is never fetched.
        assert client.pages_served == 1
        assert pages == [[recent]]

    def test_deleted_entry_skipped_but_does_not_stop_run(
        self, entries_page_data, library_entry_deleted_response
    ):
        deleted = library_entry_deleted_response["data"]
        live = entries_page_data[0]
        client = FakeClient([[deleted, live]])
        # Cutoff old enough that both entries are newer than it.
        state = MagicMock(last_run=datetime(2019, 1, 1, tzinfo=UTC))
        proc = _make_processor(state=state, client=client)
        pages = list(proc.collect())
        surviving = [e for page in pages for e in page]
        ids = [e["id"] for e in surviving]
        assert live["id"] in ids
        assert deleted["id"] not in ids

    def test_unparseable_updated_at_kept_and_does_not_stop(self, entries_page_data):
        bad = copy.deepcopy(entries_page_data[0])
        bad["id"] = "bad-date-entry"
        bad["updated_at"] = None
        live = entries_page_data[0]
        client = FakeClient([[bad, live]])
        state = MagicMock(last_run=datetime(2025, 1, 1, tzinfo=UTC))
        proc = _make_processor(state=state, client=client)
        pages = list(proc.collect())
        surviving = [e for page in pages for e in page]
        ids = [e["id"] for e in surviving]
        assert "bad-date-entry" in ids
        assert live["id"] in ids

    def test_fully_filtered_page_not_yielded(
        self, entries_page_data, library_entry_deleted_response
    ):
        deleted = library_entry_deleted_response["data"]
        live = entries_page_data[0]
        client = FakeClient([[deleted], [live]])
        state = MagicMock(last_run=datetime(2019, 1, 1, tzinfo=UTC))
        proc = _make_processor(state=state, client=client)
        pages = list(proc.collect())
        assert pages == [[live]]


# ---------------------------------------------------------------------------
# transform()
# ---------------------------------------------------------------------------


class TestTransform:
    def test_yields_report_per_entry_and_dedupes(self, entries_page_data):
        recent, _empty, dup_actors, _old = entries_page_data
        proc = _make_processor(converter=_real_converter())
        results = list(proc.transform(iter([[recent, dup_actors]])))
        assert len(results) == 1
        bundle = results[0]
        assert len(_reports(bundle)) == 2
        ids = [obj.id for obj in bundle]
        assert len(ids) == len(set(ids))

    def test_skips_malformed_row_and_converts_the_rest(self, entries_page_data):
        recent = entries_page_data[0]
        proc = _make_processor(converter=_real_converter())
        results = list(proc.transform(iter([[{"no_id_field": True}, recent]])))
        assert len(results) == 1
        assert len(_reports(results[0])) == 1
        proc.logger.error.assert_called()

    def test_conversion_error_skipped_and_rest_converts(self, entries_page_data):
        recent, empty, _dup, _old = entries_page_data
        converter = MagicMock()
        calls: list[Any] = []

        def _convert(entry):
            calls.append(entry)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return [_Obj("report--ok")]

        converter.convert_entry.side_effect = _convert
        proc = _make_processor(converter=converter)
        results = list(proc.transform(iter([[recent, empty]])))
        assert len(results) == 1
        assert len(results[0]) == 1
        proc.logger.error.assert_called()

    def test_empty_page_yields_nothing(self):
        proc = _make_processor(converter=_real_converter())
        results = list(proc.transform(iter([[]])))
        assert results == []


# ---------------------------------------------------------------------------
# post_init()
# ---------------------------------------------------------------------------


class TestPostInit:
    def test_builds_client_and_converter_from_config(self):
        proc = OrklReportProcessor.__new__(OrklReportProcessor)
        proc.settings = MagicMock()
        proc.settings.orkl = MagicMock(
            api_base_url="https://orkl.eu/api/v1/",
            tlp_level=MagicMock(value="green"),
            threat_actor_as_intrusion_set=False,
            ingest_tools=True,
        )
        with patch(
            "orkl.processors.orkl_report_processor.OrklClient"
        ) as mock_client, patch(
            "orkl.processors.orkl_report_processor.OrklConverter"
        ) as mock_converter:
            proc.post_init()

        mock_client.assert_called_once_with(base_url="https://orkl.eu/api/v1")
        mock_converter.assert_called_once_with(
            api_base_url="https://orkl.eu/api/v1",
            tlp_level="green",
            threat_actor_as_intrusion_set=False,
            ingest_tools=True,
        )


# ---------------------------------------------------------------------------
# State ownership rule
# ---------------------------------------------------------------------------


class TestStateOwnership:
    def test_processor_never_loads_or_saves_state(
        self, entries_page_data, library_entry_deleted_response
    ):
        state = MagicMock(last_run=datetime(2025, 1, 1, tzinfo=UTC))
        client = FakeClient([entries_page_data])
        proc = _make_processor(state=state, client=client, converter=_real_converter())
        list(proc.transform(proc.collect()))
        state.load.assert_not_called()
        state.save.assert_not_called()
