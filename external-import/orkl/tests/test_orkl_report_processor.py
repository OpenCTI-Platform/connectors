"""Tests for the ORKL report processor (collection, transform and conversion)."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from connectors_sdk.models import (
    IntrusionSet,
    Relationship,
    Report,
    ThreatActorGroup,
    TLPMarking,
    Tool,
)
from connectors_sdk.models.enums import RelationshipType
from orkl.models import OrklLibraryEntry
from orkl.processors.orkl_report_processor import (
    _CUTOFF_OVERLAP,
    _ID_STABILITY_SENTINEL_DATE,
    ORKL_AUTHOR,
    OrklReportProcessor,
    _dedupe_by_id,
)

UTC = timezone.utc
API_BASE_URL = "https://orkl.eu/api/v1"


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
    tlp_level: str = "clear",
    threat_actor_as_intrusion_set: bool = True,
    ingest_tools: bool = False,
    api_base_url: str = API_BASE_URL,
) -> OrklReportProcessor:
    """Build a processor without a real OpenCTIConnectorHelper.

    The conversion config is set directly (exactly as ``post_init`` would), so
    ``_convert_entry`` and the ``_build_*`` helpers run for real.
    """
    proc = OrklReportProcessor.__new__(OrklReportProcessor)
    proc.logger = MagicMock()
    proc._config = config or MagicMock(import_start_date=timedelta(days=30))
    proc.state = state if state is not None else MagicMock(last_run=None)
    proc._client = client or MagicMock()
    proc._api_base_url = api_base_url.rstrip("/")
    proc._marking = TLPMarking(level=tlp_level)
    proc._threat_actor_as_intrusion_set = threat_actor_as_intrusion_set
    proc._ingest_tools = ingest_tools
    return proc


def _reports(bundle: list[Any]) -> list[Any]:
    return [obj for obj in bundle if obj.id.startswith("report--")]


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
            ingest_tools=True,
        )
        with patch("orkl.processors.orkl_report_processor.OrklClient") as mock_client:
            proc.post_init()

        mock_client.assert_called_once_with(
            base_url="https://orkl.eu/api/v1", logger=proc.logger
        )
        assert proc._api_base_url == "https://orkl.eu/api/v1"
        assert proc._marking.level == "green"
        assert proc._threat_actor_as_intrusion_set is False
        assert proc._ingest_tools is True


# ---------------------------------------------------------------------------
# State ownership rule
# ---------------------------------------------------------------------------


class TestStateOwnership:
    def test_processor_never_loads_or_saves_state(
        self, entries_page_data, library_entry_deleted_response
    ):
        state = MagicMock(last_run=datetime(2025, 1, 1, tzinfo=UTC))
        client = FakeClient([entries_page_data])
        proc = _make_processor(state=state, client=client)
        list(proc.transform(proc.collect()))
        state.load.assert_not_called()
        state.save.assert_not_called()


# ---------------------------------------------------------------------------
# Conversion: report basics
# ---------------------------------------------------------------------------


class TestReportBasics:
    def test_report_is_first_and_has_non_empty_name(self, converter, full_entry):
        result = converter._convert_entry(full_entry)
        assert isinstance(result[0], Report)
        assert result[0].name.strip()

    def test_empty_title_entry_still_yields_valid_name(self, converter, page_entries):
        entry = page_entries[1]  # title == "" upstream
        assert entry.title == ""
        report = converter._convert_entry(entry)[0]
        assert report.name.strip()

    def test_report_objects_none_when_no_actors(self, converter, page_entries):
        entry = page_entries[1]  # no threat actors
        result = converter._convert_entry(entry)
        assert len(result) == 1
        assert result[0].objects is None

    def test_deleted_entry_still_produces_report(
        self, converter, library_entry_deleted_response
    ):
        entry = OrklLibraryEntry.model_validate(library_entry_deleted_response["data"])
        result = converter._convert_entry(entry)
        assert isinstance(result[0], Report)
        assert result[0].name.strip()


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
        report = converter._convert_entry(full_entry)[0]
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
        report = converter._convert_entry(entry)[0]
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
        report = converter._convert_entry(entry)[0]
        assert report.publication_date == _ID_STABILITY_SENTINEL_DATE
        assert report.publication_date.utcoffset() is not None

    def test_dateless_entry_yields_same_report_id_across_conversions(
        self, converter, full_entry_data
    ):
        _blank_all_dates(full_entry_data)
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        first = converter._convert_entry(entry)[0]
        second = converter._convert_entry(entry)[0]
        assert first.id == second.id

    def test_publication_date_uses_file_modification_date_before_sentinel(
        self, converter, full_entry_data
    ):
        _blank_all_dates(full_entry_data)
        full_entry_data["file_modification_date"] = "2026-08-19T00:00:00Z"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.publication_date is None  # file_creation_date/created_at unusable
        report = converter._convert_entry(entry)[0]
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
        report = converter._convert_entry(entry)[0]
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
        report = converter._convert_entry(full_entry)[0]
        ref = next(
            r for r in report.external_references if r.url == full_entry.references[0]
        )
        assert ref.source_name == "bitdefender.com"

    def test_sha1_reference_skipped_when_absent(self, converter, full_entry_data):
        full_entry_data["sha1_hash"] = None
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        report = converter._convert_entry(entry)[0]
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
        report = converter._convert_entry(entry)[0]
        publisher_refs = [
            r
            for r in report.external_references
            if r.source_name not in ("ORKL", "ORKL Archive")
        ]
        assert [r.url for r in publisher_refs] == ["https://good.example.com/report"]
        assert publisher_refs[0].source_name == "good.example.com"

    def test_report_has_no_associated_files(self, converter, page_entries):
        report = converter._convert_entry(page_entries[0])[0]
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
    def test_labels_merge_sources_and_origins(self, converter, full_entry):
        report = converter._convert_entry(full_entry)[0]
        assert set(report.labels) == {"MISPGALAXY", "Malpedia", "web"}


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

    def test_actor_aliases_none_when_empty(self, converter, entries_page_data):
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
        report = result[0]
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
        report = result[0]
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

        report = result[0]
        object_ids = {obj.id for obj in report.objects}
        for obj in result[1:]:
            assert obj.id in object_ids


# ---------------------------------------------------------------------------
# Conversion: author and markings
# ---------------------------------------------------------------------------


class TestAuthorAndMarkings:
    def test_all_objects_have_orkl_author(self, full_entry):
        converter = _make_processor(ingest_tools=True)
        result = converter._convert_entry(full_entry)
        assert result  # non-empty
        assert all(obj.author is ORKL_AUTHOR for obj in result)

    def test_marking_reflects_configured_tlp_level(self, full_entry):
        clear = _make_processor(tlp_level="clear")
        amber = _make_processor(tlp_level="amber")
        result_clear = clear._convert_entry(full_entry)
        result_amber = amber._convert_entry(full_entry)
        assert all(obj.markings[0].level == "clear" for obj in result_clear)
        assert all(obj.markings[0].level == "amber" for obj in result_amber)
        assert result_clear[0].markings[0].id != result_amber[0].markings[0].id


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
