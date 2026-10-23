"""Tests for the ORKL report processor (collection, transform and conversion)."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk import ApiClientError, ApiNotFoundError, ApiServerError
from connectors_sdk.models import (
    IntrusionSet,
    Relationship,
    Report,
    ThreatActorGroup,
    TLPMarking,
    Tool,
)
from connectors_sdk.models.enums import RelationshipType
from orkl.client_api import PAGE_SIZE
from orkl.models import OrklLibraryEntry
from orkl.processors.orkl_report_processor import (
    _ID_STABILITY_SENTINEL_DATE,
    _MAX_FETCH_FAILURES,
    ORKL_AUTHOR,
    OrklReportProcessor,
    _dedupe_by_id,
)
from orkl.state import OrklState

UTC = timezone.utc
API_BASE_URL = "https://orkl.eu/api/v1"


# ---------------------------------------------------------------------------
# Test doubles / helpers
# ---------------------------------------------------------------------------


class FakeClient:
    """Stand-in for OrklClient covering both sync modes.

    ``pages`` feeds the full walk (``iter_library_entries``); ``versions`` and
    ``entries_by_id`` feed the incremental walk. Counters let tests assert
    laziness and the number of per-entry fetches.
    """

    def __init__(
        self,
        pages: list[list[dict[str, Any]]] | None = None,
        *,
        version: int = 100,
        versions: list[dict[str, Any]] | None = None,
        entries_by_id: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._pages = pages or []
        self._version = version
        self._versions = versions or []
        self._entries_by_id = entries_by_id or {}
        self.pages_served = 0
        self.versions_requested_since: int | None = None
        self.fetched_ids: list[str] = []

    def get_library_version(self) -> int:
        return self._version

    def iter_library_entries(self, **kwargs: Any):
        for page in self._pages:
            self.pages_served += 1
            yield page

    def iter_library_versions_since(self, version: int, **kwargs: Any):
        self.versions_requested_since = version
        for entry in self._versions:
            if entry["ID"] <= version:
                return
            yield entry

    def get_library_entry(self, entry_id: str) -> dict[str, Any] | None:
        self.fetched_ids.append(entry_id)
        if entry_id not in self._entries_by_id:
            raise ApiNotFoundError(f"No LibraryEntry found with ID {entry_id}")
        value = self._entries_by_id[entry_id]
        if isinstance(value, Exception):
            raise value
        return value


class _Obj:
    """Minimal object exposing a STIX-like `id` for dedup tests."""

    def __init__(self, id: str) -> None:  # noqa: A002
        self.id = id


def _make_processor(
    *,
    config: Any = None,
    state: Any = None,
    client: Any = None,
    tlp_level: str = "clear",
    threat_actor_as_intrusion_set: bool = True,
    ingest_actor_aliases: bool = False,
    ingest_tools: bool = False,
    api_base_url: str = API_BASE_URL,
) -> OrklReportProcessor:
    """Build a processor without a real OpenCTIConnectorHelper.

    The conversion config is set directly (exactly as ``post_init`` would), so
    ``_convert_entry`` and the ``_build_*`` helpers run for real.
    """
    proc = OrklReportProcessor.__new__(OrklReportProcessor)
    proc.logger = MagicMock()
    proc._config = config or MagicMock(full_resync_period=timedelta(days=30))
    proc.state = state if state is not None else OrklState()
    proc._client = client or MagicMock()
    proc._api_base_url = api_base_url.rstrip("/")
    proc._marking = TLPMarking(level=tlp_level)
    proc._threat_actor_as_intrusion_set = threat_actor_as_intrusion_set
    proc._ingest_actor_aliases = ingest_actor_aliases
    proc._ingest_tools = ingest_tools
    return proc


def _reports(bundle: list[Any]) -> list[Any]:
    return [obj for obj in bundle if obj.id.startswith("report--")]


def _report(bundle: list[Any]) -> Any:
    """Return the single Report in a bundle.

    The bundle also carries the author and marking SDOs, so the Report is not
    at a fixed position.
    """
    reports = _reports(bundle)
    assert len(reports) == 1
    return reports[0]


def _payload(bundle: list[Any]) -> list[Any]:
    """Return the bundle without the author and marking SDOs."""
    return [
        obj
        for obj in bundle
        if obj is not ORKL_AUTHOR and not isinstance(obj, TLPMarking)
    ]


def _actors(result: list) -> list:
    return [obj for obj in result if isinstance(obj, (IntrusionSet, ThreatActorGroup))]


@pytest.fixture
def converter() -> OrklReportProcessor:
    """Default converter processor: IntrusionSets, no tools, TLP:CLEAR."""
    return _make_processor()


@pytest.fixture
def full_entry(full_entry_data: dict) -> OrklLibraryEntry:
    """Real 33k-char capture, 10 actors, year-1 file_creation_date sentinel."""
    return OrklLibraryEntry.model_validate(full_entry_data)


@pytest.fixture
def page_entries(entries_page_data: list) -> list[OrklLibraryEntry]:
    """The four hand-written page entries, parsed."""
    return [OrklLibraryEntry.model_validate(entry) for entry in entries_page_data]


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
# _full_resync_due
# ---------------------------------------------------------------------------


class TestFullResyncDue:
    def test_due_when_never_fully_synced(self):
        proc = _make_processor(state=OrklState(last_library_version=10))
        assert proc._full_resync_due() is True

    def test_not_due_within_period(self):
        state = OrklState(last_full_sync=datetime.now(UTC) - timedelta(days=10))
        proc = _make_processor(state=state)
        assert proc._full_resync_due() is False

    def test_due_once_period_elapsed(self):
        state = OrklState(last_full_sync=datetime.now(UTC) - timedelta(days=31))
        proc = _make_processor(state=state)
        assert proc._full_resync_due() is True

    def test_zero_period_disables_periodic_resync(self):
        state = OrklState(last_full_sync=datetime(2000, 1, 1, tzinfo=UTC))
        proc = _make_processor(
            state=state, config=MagicMock(full_resync_period=timedelta(0))
        )
        assert proc._full_resync_due() is False

    def test_naive_last_full_sync_treated_as_utc(self):
        state = OrklState(last_full_sync=datetime.now() - timedelta(days=1))
        proc = _make_processor(state=state)
        assert proc._full_resync_due() is False


# ---------------------------------------------------------------------------
# collect() — full sync (first run / periodic) and incremental sync
# ---------------------------------------------------------------------------


class TestCollectFullSync:
    def test_first_run_walks_the_whole_library(self, entries_page_data):
        client = FakeClient([entries_page_data[:2], entries_page_data[2:]], version=588)
        proc = _make_processor(client=client)
        pages = list(proc.collect())
        assert client.pages_served == 2
        assert [e["id"] for page in pages for e in page] == [
            e["id"] for e in entries_page_data
        ]
        assert client.versions_requested_since is None
        assert "full sync" in proc.work_name
        assert "588" in proc.work_name

    def test_first_run_records_version_and_full_sync_time(self, entries_page_data):
        state = OrklState()
        proc = _make_processor(state=state, client=FakeClient([entries_page_data]))
        list(proc.collect())
        assert state.last_library_version == 100
        assert state.last_full_sync is not None
        assert datetime.now(UTC) - state.last_full_sync < timedelta(minutes=1)

    def test_periodic_resync_when_period_elapsed(self, entries_page_data):
        state = OrklState(
            last_library_version=90,
            last_full_sync=datetime.now(UTC) - timedelta(days=45),
        )
        client = FakeClient([entries_page_data], version=100)
        proc = _make_processor(state=state, client=client)
        pages = list(proc.collect())
        assert client.pages_served == 1
        assert len(pages[0]) == 4
        assert state.last_library_version == 100

    def test_deleted_entry_skipped_and_empty_page_not_yielded(
        self, entries_page_data, library_entry_deleted_response
    ):
        deleted = library_entry_deleted_response["data"]
        live = entries_page_data[0]
        proc = _make_processor(client=FakeClient([[deleted], [live, deleted]]))
        pages = list(proc.collect())
        assert pages == [[live]]

    def test_state_not_advanced_when_consumer_stops_early(self, entries_page_data):
        state = OrklState()
        client = FakeClient([entries_page_data[:2], entries_page_data[2:]])
        proc = _make_processor(state=state, client=client)
        gen = proc.collect()
        next(gen)
        gen.close()
        # The run did not consume every page (e.g. a send failed): the cursor
        # must stay where it was so the next run redoes the import.
        assert state.last_library_version is None
        assert state.last_full_sync is None

    def test_entries_arrive_regardless_of_updated_at(self, entries_page_data):
        # ORKL rewrites updated_at nightly; it must play no role in collection.
        for entry in entries_page_data:
            entry["updated_at"] = "2026-10-22T02:30:00.000000Z"
        proc = _make_processor(client=FakeClient([entries_page_data]))
        pages = list(proc.collect())
        assert len(pages[0]) == 4


class TestCollectIncremental:
    @pytest.fixture
    def recent_state(self) -> OrklState:
        return OrklState(
            last_library_version=9,
            last_full_sync=datetime.now(UTC) - timedelta(days=1),
        )

    @pytest.fixture
    def incremental_client(
        self,
        entries_page_data,
        library_versions_page_response,
        library_entry_deleted_response,
    ) -> FakeClient:
        deleted = library_entry_deleted_response["data"]
        return FakeClient(
            version=12,
            versions=library_versions_page_response["data"]["entries"],
            entries_by_id={
                **{e["id"]: e for e in entries_page_data},
                deleted["id"]: deleted,
            },
        )

    def test_fetches_entries_created_in_newer_versions_only(
        self, recent_state, incremental_client
    ):
        proc = _make_processor(state=recent_state, client=incremental_client)
        pages = list(proc.collect())
        ids = [e["id"] for page in pages for e in page]
        # Versions 12 and 11 are newer than 9; version 7 is not read.
        assert incremental_client.versions_requested_since == 9
        assert "709bf9ad-7489-460c-b5f6-03d9737d5c77" not in ids
        assert "bb301bd1-f53f-481f-9425-c60d9a2ca521" in ids
        assert "dde3cc0c-8158-4e2a-b258-c632546bdbca" in ids
        assert incremental_client.pages_served == 0
        assert "new entries" in proc.work_name
        assert "10 to 12" in proc.work_name

    def test_entry_listed_in_two_versions_fetched_once(
        self, recent_state, incremental_client
    ):
        proc = _make_processor(state=recent_state, client=incremental_client)
        list(proc.collect())
        fetched = incremental_client.fetched_ids
        assert fetched.count("bb301bd1-f53f-481f-9425-c60d9a2ca521") == 1

    def test_deleted_entry_fetched_but_skipped(self, recent_state, incremental_client):
        proc = _make_processor(state=recent_state, client=incremental_client)
        pages = list(proc.collect())
        ids = [e["id"] for page in pages for e in page]
        assert "3f34e1e6-fa38-4804-8cb7-7e555415269c" not in ids

    def test_missing_entry_is_skipped_with_warning(
        self, recent_state, library_versions_page_response, entries_page_data
    ):
        client = FakeClient(
            version=12,
            versions=library_versions_page_response["data"]["entries"],
            entries_by_id={entries_page_data[0]["id"]: entries_page_data[0]},
        )
        proc = _make_processor(state=recent_state, client=client)
        pages = list(proc.collect())
        ids = [e["id"] for page in pages for e in page]
        assert ids == [entries_page_data[0]["id"]]
        proc.logger.warning.assert_called()
        assert recent_state.last_library_version == 12

    def test_advances_version_without_touching_full_sync_time(
        self, recent_state, incremental_client
    ):
        before = recent_state.last_full_sync
        proc = _make_processor(state=recent_state, client=incremental_client)
        list(proc.collect())
        assert recent_state.last_library_version == 12
        assert recent_state.last_full_sync == before

    def test_nothing_new_yields_nothing_but_advances_version(self, recent_state):
        # Versions 10..12 exist upstream but created nothing: the cursor still
        # moves to 12 so they are not re-read next time.
        client = FakeClient(
            version=12,
            versions=[{"ID": i, "created_library_entries": []} for i in (12, 11, 10)],
        )
        proc = _make_processor(state=recent_state, client=client)
        assert list(proc.collect()) == []
        assert recent_state.last_library_version == 12

    def test_version_rollback_triggers_full_sync(self, entries_page_data):
        # ORKL rolled back from 500 to 480 and rebuilt 481: the version log can
        # no longer tell what changed, so the whole library is walked again.
        state = OrklState(
            last_library_version=500,
            last_full_sync=datetime.now(UTC) - timedelta(days=1),
        )
        client = FakeClient(
            [entries_page_data],
            version=481,
            versions=[{"ID": 481, "created_library_entries": []}],
        )
        proc = _make_processor(state=state, client=client)
        pages = list(proc.collect())
        assert client.pages_served == 1
        assert client.versions_requested_since is None
        assert len(pages[0]) == 4
        assert "full sync" in proc.work_name
        assert state.last_library_version == 481
        assert datetime.now(UTC) - state.last_full_sync < timedelta(minutes=1)

    def test_one_failing_fetch_is_skipped_and_cursor_advances(
        self, recent_state, library_versions_page_response, entries_page_data
    ):
        live = entries_page_data[0]
        client = FakeClient(
            version=12,
            versions=library_versions_page_response["data"]["entries"],
            entries_by_id={
                live["id"]: live,
                "dde3cc0c-8158-4e2a-b258-c632546bdbca": ApiServerError("boom"),
                "3f34e1e6-fa38-4804-8cb7-7e555415269c": ApiServerError("boom"),
            },
        )
        proc = _make_processor(state=recent_state, client=client)
        pages = list(proc.collect())
        assert [e["id"] for page in pages for e in page] == [live["id"]]
        assert recent_state.last_library_version == 12
        assert proc.logger.warning.call_count == 2

    def test_every_fetch_failing_fails_the_run_without_advancing(
        self, recent_state, library_versions_page_response
    ):
        ids = {
            ref["id"]: ApiServerError("ORKL down")
            for v in library_versions_page_response["data"]["entries"]
            for ref in (v["created_library_entries"] or [])
        }
        client = FakeClient(
            version=12,
            versions=library_versions_page_response["data"]["entries"],
            entries_by_id=ids,
        )
        proc = _make_processor(state=recent_state, client=client)
        with pytest.raises(ApiClientError):
            list(proc.collect())
        assert recent_state.last_library_version == 9

    def test_too_many_failures_fail_the_run(self, recent_state, entries_page_data):
        template = entries_page_data[0]
        entries: dict[str, Any] = {}
        refs = []
        for i in range(_MAX_FETCH_FAILURES + 5):
            entry_id = f"00000000-0000-4000-8000-{i:012d}"
            refs.append({"id": entry_id, "label": f"Synthetic {i}"})
            if i <= _MAX_FETCH_FAILURES:  # _MAX_FETCH_FAILURES + 1 failures
                entries[entry_id] = ApiServerError("boom")
            else:
                entry = copy.deepcopy(template)
                entry["id"] = entry_id
                entries[entry_id] = entry
        client = FakeClient(
            version=10,
            versions=[{"ID": 10, "created_library_entries": refs}],
            entries_by_id=entries,
        )
        proc = _make_processor(state=recent_state, client=client)
        with pytest.raises(ApiClientError):
            list(proc.collect())
        assert recent_state.last_library_version == 9

    def test_new_entries_are_chunked_in_pages(self, recent_state, entries_page_data):
        template = entries_page_data[0]
        entries = {}
        refs = []
        for i in range(PAGE_SIZE + 5):
            entry = copy.deepcopy(template)
            entry["id"] = f"00000000-0000-4000-8000-{i:012d}"
            entries[entry["id"]] = entry
            refs.append({"id": entry["id"], "label": f"Synthetic {i}"})
        client = FakeClient(
            version=10,
            versions=[{"ID": 10, "created_library_entries": refs}],
            entries_by_id=entries,
        )
        proc = _make_processor(state=recent_state, client=client)
        pages = list(proc.collect())
        assert [len(page) for page in pages] == [PAGE_SIZE, 5]


# ---------------------------------------------------------------------------
# transform()
# ---------------------------------------------------------------------------


class TestTransform:
    def test_yields_report_per_entry_and_dedupes(self, entries_page_data):
        recent, _empty, dup_actors, _old = entries_page_data
        proc = _make_processor()
        results = list(proc.transform(iter([[recent, dup_actors]])))
        assert len(results) == 1
        bundle = results[0]
        assert len(_reports(bundle)) == 2
        ids = [obj.id for obj in bundle]
        assert len(ids) == len(set(ids))

    def test_skips_malformed_row_and_converts_the_rest(self, entries_page_data):
        recent = entries_page_data[0]
        proc = _make_processor()
        results = list(proc.transform(iter([[{"no_id_field": True}, recent]])))
        assert len(results) == 1
        assert len(_reports(results[0])) == 1
        proc.logger.error.assert_called()

    def test_conversion_error_skipped_and_rest_converts(self, entries_page_data):
        recent, empty, _dup, _old = entries_page_data
        calls: list[Any] = []

        def _convert(entry):
            calls.append(entry)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return [_Obj("report--ok")]

        proc = _make_processor()
        proc._convert_entry = MagicMock(side_effect=_convert)
        results = list(proc.transform(iter([[recent, empty]])))
        assert len(results) == 1
        assert len(results[0]) == 1
        proc.logger.error.assert_called()

    def test_empty_page_yields_nothing(self):
        proc = _make_processor()
        results = list(proc.transform(iter([[]])))
        assert results == []


# ---------------------------------------------------------------------------
# post_init()
# ---------------------------------------------------------------------------


class TestPostInit:
    def test_builds_client_and_config_from_settings(self):
        proc = OrklReportProcessor.__new__(OrklReportProcessor)
        proc.logger = MagicMock()
        proc.settings = MagicMock()
        proc.settings.orkl = MagicMock(
            api_base_url="https://orkl.eu/api/v1/",
            tlp_level=MagicMock(value="green"),
            threat_actor_as_intrusion_set=False,
            ingest_actor_aliases=True,
            ingest_tools=True,
        )
        with patch("orkl.processors.orkl_report_processor.OrklClient") as mock_client:
            proc.post_init()

        mock_client.assert_called_once_with(base_url="https://orkl.eu/api/v1")
        assert proc._api_base_url == "https://orkl.eu/api/v1"
        assert proc._marking.level == "green"
        assert proc._threat_actor_as_intrusion_set is False
        assert proc._ingest_actor_aliases is True
        assert proc._ingest_tools is True


# ---------------------------------------------------------------------------
# State ownership rule
# ---------------------------------------------------------------------------


class TestStateOwnership:
    def test_processor_never_loads_or_saves_state(
        self, entries_page_data, library_entry_deleted_response
    ):
        state = MagicMock(last_library_version=None, last_full_sync=None)
        client = FakeClient([entries_page_data])
        proc = _make_processor(state=state, client=client)
        list(proc.transform(proc.collect()))
        state.load.assert_not_called()
        state.save.assert_not_called()


# ---------------------------------------------------------------------------
# Conversion: report basics
# ---------------------------------------------------------------------------


class TestReportBasics:
    def test_report_present_and_has_non_empty_name(self, converter, full_entry):
        report = _report(converter._convert_entry(full_entry))
        assert isinstance(report, Report)
        assert report.name.strip()

    def test_empty_title_entry_still_yields_valid_name(self, converter, page_entries):
        entry = page_entries[1]  # title == "" upstream
        assert entry.title == ""
        report = _report(converter._convert_entry(entry))
        assert report.name.strip()

    def test_report_objects_none_when_no_actors(self, converter, page_entries):
        entry = page_entries[1]  # no threat actors
        result = converter._convert_entry(entry)
        assert _payload(result) == [_report(result)]
        assert _report(result).objects is None

    def test_deleted_entry_still_produces_report(
        self, converter, library_entry_deleted_response
    ):
        entry = OrklLibraryEntry.model_validate(library_entry_deleted_response["data"])
        report = _report(converter._convert_entry(entry))
        assert isinstance(report, Report)
        assert report.name.strip()


# ---------------------------------------------------------------------------
# Conversion: publication date fallback chain
# ---------------------------------------------------------------------------


def _blank_all_dates(data: dict) -> None:
    """Null every date field so `_resolve_publication_date` reaches the sentinel."""
    for field in (
        "created_at",
        "updated_at",
        "file_creation_date",
        "file_modification_date",
        "ts_created_at",
        "ts_updated_at",
        "ts_creation_date",
        "ts_modification_date",
    ):
        data[field] = None


class TestPublicationDate:
    def test_publication_date_set_and_timezone_aware_for_sentinel_entry(
        self, converter, full_entry
    ):
        # file_creation_date is the year-1 sentinel; a date must still be produced.
        report = _report(converter._convert_entry(full_entry))
        assert report.publication_date is not None
        assert report.publication_date.utcoffset() is not None

    def test_publication_date_ignores_updated_at_and_uses_sentinel(
        self, converter, full_entry_data
    ):
        # Only `updated_at` is populated; every stable date is absent. The update
        # timestamp must NOT feed the id, so the fixed sentinel is used instead.
        _blank_all_dates(full_entry_data)
        full_entry_data["updated_at"] = "2026-08-20T12:00:00Z"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.publication_date is None  # precondition
        assert entry.updated_datetime is not None  # updated_at is genuinely present
        report = _report(converter._convert_entry(entry))
        assert report.publication_date == _ID_STABILITY_SENTINEL_DATE

    def test_report_id_stable_when_only_updated_at_changes(
        self, converter, full_entry_data
    ):
        # Regression guard: an entry re-fetched because its `updated_at` moved
        # must keep the same Report id, otherwise each re-fetch duplicates it.
        _blank_all_dates(full_entry_data)
        full_entry_data["updated_at"] = "2026-08-20T12:00:00Z"
        first = converter._convert_entry(
            OrklLibraryEntry.model_validate(full_entry_data)
        )[0]
        full_entry_data["updated_at"] = "2026-08-25T18:30:00Z"
        second = converter._convert_entry(
            OrklLibraryEntry.model_validate(full_entry_data)
        )[0]
        assert first.id == second.id

    def test_publication_date_falls_back_to_deterministic_sentinel(
        self, converter, full_entry_data
    ):
        _blank_all_dates(full_entry_data)
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.publication_date is None
        assert entry.updated_datetime is None
        report = _report(converter._convert_entry(entry))
        assert report.publication_date == _ID_STABILITY_SENTINEL_DATE
        assert report.publication_date.utcoffset() is not None

    def test_dateless_entry_yields_same_report_id_across_conversions(
        self, converter, full_entry_data
    ):
        _blank_all_dates(full_entry_data)
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        first = _report(converter._convert_entry(entry))
        second = _report(converter._convert_entry(entry))
        assert first.id == second.id

    def test_publication_date_uses_file_modification_date_before_sentinel(
        self, converter, full_entry_data
    ):
        _blank_all_dates(full_entry_data)
        full_entry_data["file_modification_date"] = "2026-08-19T00:00:00Z"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.publication_date is None  # file_creation_date/created_at unusable
        report = _report(converter._convert_entry(entry))
        assert report.publication_date == datetime(2026, 8, 19, tzinfo=timezone.utc)
        assert report.publication_date != _ID_STABILITY_SENTINEL_DATE


# ---------------------------------------------------------------------------
# Conversion: external references
# ---------------------------------------------------------------------------


def _all_external_references(objects: list) -> list:
    refs = []
    for obj in objects:
        refs.extend(getattr(obj, "external_references", None) or [])
    return refs


class TestExternalReferences:
    def test_report_external_references_cover_all_sources(
        self, converter, page_entries
    ):
        entry = page_entries[0]  # APT28: sha1 + one reference + files present
        report = _report(converter._convert_entry(entry))
        refs = report.external_references

        entry_ref = refs[0]
        assert entry_ref.source_name == "ORKL"
        assert entry_ref.external_id == entry.id
        assert entry_ref.url == f"{API_BASE_URL}/library/entry/{entry.id}"

        sha_refs = [r for r in refs if r.external_id == entry.sha1_hash]
        assert len(sha_refs) == 1
        assert sha_refs[0].url is None

        publisher_refs = [r for r in refs if r.url == entry.references[0]]
        assert len(publisher_refs) == 1
        assert publisher_refs[0].source_name == "example.com"

        archive_refs = [r for r in refs if r.source_name == "ORKL Archive"]
        assert {r.url for r in archive_refs} == {
            entry.files.pdf,
            entry.files.text,
            entry.files.img,
        }
        assert len({r.description for r in archive_refs}) == 3

    def test_reference_source_name_strips_www(self, converter, full_entry):
        report = _report(converter._convert_entry(full_entry))
        ref = next(
            r for r in report.external_references if r.url == full_entry.references[0]
        )
        assert ref.source_name == "bitdefender.com"

    def test_sha1_reference_skipped_when_absent(self, converter, full_entry_data):
        full_entry_data["sha1_hash"] = None
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        report = _report(converter._convert_entry(entry))
        # The SHA1 ref is the only ORKL-sourced ref without a URL.
        orkl_no_url = [
            r
            for r in report.external_references
            if r.source_name == "ORKL" and r.url is None
        ]
        assert orkl_no_url == []

    def test_unusable_reference_urls_are_skipped(self, converter, full_entry_data):
        full_entry_data["references"] = [
            "not a url",
            "ftp://",
            "https://good.example.com/report",
        ]
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        report = _report(converter._convert_entry(entry))
        publisher_refs = [
            r
            for r in report.external_references
            if r.source_name not in ("ORKL", "ORKL Archive")
        ]
        assert [r.url for r in publisher_refs] == ["https://good.example.com/report"]
        assert publisher_refs[0].source_name == "good.example.com"

    def test_report_has_no_associated_files(self, converter, page_entries):
        report = _report(converter._convert_entry(page_entries[0]))
        assert report.files is None

    def test_every_external_reference_satisfies_at_least_one_property(
        self, full_entry, page_entries
    ):
        # The STIX invariant: every ExternalReference must populate at least one
        # of description / external_id / url. Pin it once across every fixture
        # and both ingest_tools modes rather than case by case.
        converters = [
            _make_processor(),
            _make_processor(ingest_tools=True),
        ]
        entries = [full_entry, *page_entries]
        for conv in converters:
            for entry in entries:
                objects = conv._convert_entry(entry)
                for ref in _all_external_references(objects):
                    assert any((ref.description, ref.external_id, ref.url)), ref


# ---------------------------------------------------------------------------
# Conversion: labels
# ---------------------------------------------------------------------------


class TestLabels:
    def test_labels_are_the_sources_only(self, converter, full_entry):
        report = _report(converter._convert_entry(full_entry))
        assert report.labels == ["MISPGALAXY", "Malpedia"]


# ---------------------------------------------------------------------------
# Conversion: threat actors
# ---------------------------------------------------------------------------


class TestThreatActors:
    def test_actors_are_intrusion_sets_by_default(self, converter, page_entries):
        entry = page_entries[0]  # single actor: APT28
        result = converter._convert_entry(entry)
        actors = [obj for obj in result if isinstance(obj, IntrusionSet)]
        assert len(actors) == 1
        assert actors[0].name == "APT28"
        # Aliases are opt-in: ORKL aliases overlap across distinct actors and
        # OpenCTI rejects an alias already carried by another entity.
        assert actors[0].aliases is None

    def test_actor_aliases_sent_when_opted_in(self, page_entries):
        converter = _make_processor(ingest_actor_aliases=True)
        entry = page_entries[0]  # single actor: APT28
        actors = _actors(converter._convert_entry(entry))
        assert "APT28" not in (actors[0].aliases or [])
        assert set(actors[0].aliases) == {"Fancy Bear", "Sofacy", "STRONTIUM", "Sednit"}

    def test_actors_are_threat_actor_groups_when_configured(self, page_entries):
        converter = _make_processor(threat_actor_as_intrusion_set=False)
        result = converter._convert_entry(page_entries[0])
        assert any(isinstance(obj, ThreatActorGroup) for obj in result)
        assert not any(isinstance(obj, IntrusionSet) for obj in result)

    def test_actor_external_reference_preserves_cross_source_identifier(
        self, converter, page_entries
    ):
        actor = next(
            obj
            for obj in converter._convert_entry(page_entries[0])
            if isinstance(obj, IntrusionSet)
        )
        ref = actor.external_references[0]
        assert ref.source_name == "MITRE"
        assert ref.external_id == "MITRE:APT28"

    def test_actor_source_name_falls_back_to_orkl(self, converter, entries_page_data):
        data = entries_page_data[0]
        data["threat_actors"][0]["source_id"] = ""
        entry = OrklLibraryEntry.model_validate(data)
        actor = next(
            obj
            for obj in converter._convert_entry(entry)
            if isinstance(obj, IntrusionSet)
        )
        assert actor.external_references[0].source_name == "ORKL"

    @pytest.mark.parametrize("source_name", [None, ""])
    def test_actor_without_source_name_omits_external_reference(
        self, converter, entries_page_data, source_name
    ):
        # A null/empty source_name has no cross-source identifier to record; the
        # reference must be omitted rather than built with only a source_name,
        # which would fail STIX serialization with AtLeastOnePropertyError.
        data = entries_page_data[0]
        data["threat_actors"][0]["source_name"] = source_name
        entry = OrklLibraryEntry.model_validate(data)
        result = converter._convert_entry(entry)
        actor = next(obj for obj in result if isinstance(obj, IntrusionSet))
        assert actor.external_references is None
        # convert succeeds AND every object serializes without raising.
        for obj in result:
            assert obj.to_stix2_object().get("id") == obj.id

    def test_actor_aliases_none_when_empty(self, entries_page_data):
        converter = _make_processor(ingest_actor_aliases=True)
        data = entries_page_data[0]
        data["threat_actors"][0]["aliases"] = ["APT28"]  # equals main_name -> excluded
        entry = OrklLibraryEntry.model_validate(data)
        actor = next(
            obj
            for obj in converter._convert_entry(entry)
            if isinstance(obj, IntrusionSet)
        )
        assert actor.aliases is None

    def test_every_actor_appears_in_report_objects(self, converter, page_entries):
        result = converter._convert_entry(page_entries[2])  # four actors
        report = _report(result)
        object_ids = {obj.id for obj in report.objects}
        for actor in _actors(result):
            assert actor.id in object_ids

    def test_four_duplicate_actors_yield_four_distinct_entities(
        self, converter, page_entries
    ):
        result = converter._convert_entry(page_entries[2])
        actors = _actors(result)
        assert len(actors) == 4
        assert {a.name for a in actors} == {"SaintBear", "Ember Bear", "Saint Bear"}

    def test_actor_with_blank_main_name_is_skipped(self, converter, entries_page_data):
        data = entries_page_data[0]
        data["threat_actors"].append(
            {
                "id": "d4d4d4d4-4444-4444-8444-444444444444",
                "main_name": "   ",
                "aliases": [],
                "source_name": "MITRE:Blank",
                "source_id": "MITRE",
                "tools": [],
            }
        )
        entry = OrklLibraryEntry.model_validate(data)
        actors = _actors(converter._convert_entry(entry))
        assert len(actors) == 1
        assert actors[0].name == "APT28"


# ---------------------------------------------------------------------------
# Conversion: tools (opt-in)
# ---------------------------------------------------------------------------


class TestTools:
    def test_no_tools_or_uses_relationships_by_default(self, converter, page_entries):
        result = converter._convert_entry(page_entries[2])  # actors carry tools
        assert not any(isinstance(obj, Tool) for obj in result)
        assert not any(isinstance(obj, Relationship) for obj in result)
        report = _report(result)
        assert all(
            not isinstance(obj, (Tool, Relationship)) for obj in (report.objects or [])
        )

    def test_tools_deduplicated_across_actors(self, full_entry):
        converter = _make_processor(ingest_tools=True)
        result = converter._convert_entry(full_entry)
        tool_names = [obj.name for obj in result if isinstance(obj, Tool)]
        assert len(tool_names) == len(set(tool_names))
        expected = {
            tool.strip()
            for actor in full_entry.threat_actors
            for tool in actor.tools
            if tool.strip()
        }
        assert set(tool_names) == expected

    def test_uses_relationship_per_actor_tool_pair(self, full_entry):
        converter = _make_processor(ingest_tools=True)
        result = converter._convert_entry(full_entry)
        relationships = [obj for obj in result if isinstance(obj, Relationship)]
        expected_pairs = sum(
            len([tool for tool in actor.tools if tool.strip()])
            for actor in full_entry.threat_actors
            if actor.main_name.strip()
        )
        assert len(relationships) == expected_pairs
        assert all(rel.type == RelationshipType.USES for rel in relationships)

        report = _report(result)
        object_ids = {obj.id for obj in report.objects}
        for obj in _payload(result):
            if obj is report:
                continue
            assert obj.id in object_ids


# ---------------------------------------------------------------------------
# Conversion: author and markings
# ---------------------------------------------------------------------------


class TestAuthorAndMarkings:
    def test_author_and_marking_are_in_the_bundle(self, converter, full_entry):
        # Without the SDOs themselves, created_by_ref/object_marking_refs
        # dangle and the platform shows no author on any entity.
        result = converter._convert_entry(full_entry)
        assert any(obj is ORKL_AUTHOR for obj in result)
        assert any(obj is converter._marking for obj in result)

    def test_all_payload_objects_have_orkl_author(self, full_entry):
        converter = _make_processor(ingest_tools=True)
        result = converter._convert_entry(full_entry)
        payload = _payload(result)
        assert payload
        assert all(obj.author is ORKL_AUTHOR for obj in payload)

    def test_marking_reflects_configured_tlp_level(self, full_entry):
        clear = _make_processor(tlp_level="clear")
        amber = _make_processor(tlp_level="amber")
        result_clear = clear._convert_entry(full_entry)
        result_amber = amber._convert_entry(full_entry)
        assert all(obj.markings[0].level == "clear" for obj in _payload(result_clear))
        assert all(obj.markings[0].level == "amber" for obj in _payload(result_amber))
        assert (
            _report(result_clear).markings[0].id != _report(result_amber).markings[0].id
        )


# ---------------------------------------------------------------------------
# Conversion: deterministic STIX ids
# ---------------------------------------------------------------------------


class TestDeterministicIds:
    def test_objects_are_stix_serializable_with_deterministic_ids(self, full_entry):
        converter = _make_processor(ingest_tools=True)
        first = converter._convert_entry(full_entry)
        second = converter._convert_entry(full_entry)
        assert [obj.id for obj in first] == [obj.id for obj in second]
        for obj in first:
            stix_object = obj.to_stix2_object()
            assert stix_object.get("id") == obj.id
