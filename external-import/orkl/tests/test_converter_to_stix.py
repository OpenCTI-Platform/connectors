"""Tests for the ORKL -> STIX converter (converter_to_stix)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from connectors_sdk.models import (
    IntrusionSet,
    Relationship,
    Report,
    ThreatActorGroup,
    Tool,
)
from connectors_sdk.models.enums import RelationshipType
from orkl.converter_to_stix import (
    _ID_STABILITY_SENTINEL_DATE,
    ORKL_AUTHOR,
    OrklConverter,
)
from orkl.models import OrklLibraryEntry

API_BASE_URL = "https://orkl.eu/api/v1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def converter() -> OrklConverter:
    """Default converter: IntrusionSets, no tools, TLP:CLEAR."""
    return OrklConverter(api_base_url=API_BASE_URL, tlp_level="clear")


@pytest.fixture
def full_entry(full_entry_data: dict) -> OrklLibraryEntry:
    """Real 33k-char capture, 10 actors, year-1 file_creation_date sentinel."""
    return OrklLibraryEntry.model_validate(full_entry_data)


@pytest.fixture
def page_entries(entries_page_data: list) -> list[OrklLibraryEntry]:
    """The four hand-written page entries, parsed."""
    return [OrklLibraryEntry.model_validate(entry) for entry in entries_page_data]


def _actors(result: list) -> list:
    return [obj for obj in result if isinstance(obj, (IntrusionSet, ThreatActorGroup))]


# ---------------------------------------------------------------------------
# Report basics
# ---------------------------------------------------------------------------


def test_report_is_first_and_has_non_empty_name(converter, full_entry):
    result = converter.convert_entry(full_entry)
    assert isinstance(result[0], Report)
    assert result[0].name.strip()


def test_empty_title_entry_still_yields_valid_name(converter, page_entries):
    entry = page_entries[1]  # title == "" upstream
    assert entry.title == ""
    report = converter.convert_entry(entry)[0]
    assert report.name.strip()


def test_report_objects_none_when_no_actors(converter, page_entries):
    entry = page_entries[1]  # no threat actors
    result = converter.convert_entry(entry)
    assert len(result) == 1
    assert result[0].objects is None


def test_deleted_entry_still_produces_report(converter, library_entry_deleted_response):
    entry = OrklLibraryEntry.model_validate(library_entry_deleted_response["data"])
    result = converter.convert_entry(entry)
    assert isinstance(result[0], Report)
    assert result[0].name.strip()


# ---------------------------------------------------------------------------
# Publication date fallback chain
# ---------------------------------------------------------------------------


def test_publication_date_set_and_timezone_aware_for_sentinel_entry(
    converter, full_entry
):
    # file_creation_date is the year-1 sentinel; a date must still be produced.
    report = converter.convert_entry(full_entry)[0]
    assert report.publication_date is not None
    assert report.publication_date.utcoffset() is not None


def test_publication_date_ignores_updated_at_and_uses_sentinel(
    converter, full_entry_data
):
    # Only `updated_at` is populated; every stable date is absent. The update
    # timestamp must NOT feed the id, so the fixed sentinel is used instead.
    _blank_all_dates(full_entry_data)
    full_entry_data["updated_at"] = "2026-08-20T12:00:00Z"
    entry = OrklLibraryEntry.model_validate(full_entry_data)
    assert entry.publication_date is None  # precondition
    assert entry.updated_datetime is not None  # updated_at is genuinely present
    report = converter.convert_entry(entry)[0]
    assert report.publication_date == _ID_STABILITY_SENTINEL_DATE


def test_report_id_stable_when_only_updated_at_changes(converter, full_entry_data):
    # Regression guard: an entry re-fetched because its `updated_at` moved must
    # keep the same Report id, otherwise each re-fetch duplicates the Report.
    _blank_all_dates(full_entry_data)
    full_entry_data["updated_at"] = "2026-08-20T12:00:00Z"
    first = converter.convert_entry(OrklLibraryEntry.model_validate(full_entry_data))[0]
    full_entry_data["updated_at"] = "2026-08-25T18:30:00Z"
    second = converter.convert_entry(OrklLibraryEntry.model_validate(full_entry_data))[
        0
    ]
    assert first.id == second.id


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


def test_publication_date_falls_back_to_deterministic_sentinel(
    converter, full_entry_data
):
    _blank_all_dates(full_entry_data)
    entry = OrklLibraryEntry.model_validate(full_entry_data)
    assert entry.publication_date is None
    assert entry.updated_datetime is None
    report = converter.convert_entry(entry)[0]
    assert report.publication_date == _ID_STABILITY_SENTINEL_DATE
    assert report.publication_date.utcoffset() is not None


def test_dateless_entry_yields_same_report_id_across_conversions(
    converter, full_entry_data
):
    _blank_all_dates(full_entry_data)
    entry = OrklLibraryEntry.model_validate(full_entry_data)
    first = converter.convert_entry(entry)[0]
    second = converter.convert_entry(entry)[0]
    assert first.id == second.id


def test_publication_date_uses_file_modification_date_before_sentinel(
    converter, full_entry_data
):
    _blank_all_dates(full_entry_data)
    full_entry_data["file_modification_date"] = "2026-08-19T00:00:00Z"
    entry = OrklLibraryEntry.model_validate(full_entry_data)
    assert entry.publication_date is None  # file_creation_date/created_at unusable
    report = converter.convert_entry(entry)[0]
    assert report.publication_date == datetime(2026, 8, 19, tzinfo=timezone.utc)
    assert report.publication_date != _ID_STABILITY_SENTINEL_DATE


# ---------------------------------------------------------------------------
# External references
# ---------------------------------------------------------------------------


def test_report_external_references_cover_all_sources(converter, page_entries):
    entry = page_entries[0]  # APT28: sha1 + one reference + files present
    report = converter.convert_entry(entry)[0]
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


def test_reference_source_name_strips_www(converter, full_entry):
    report = converter.convert_entry(full_entry)[0]
    ref = next(
        r for r in report.external_references if r.url == full_entry.references[0]
    )
    assert ref.source_name == "bitdefender.com"


def test_sha1_reference_skipped_when_absent(converter, full_entry_data):
    full_entry_data["sha1_hash"] = None
    entry = OrklLibraryEntry.model_validate(full_entry_data)
    report = converter.convert_entry(entry)[0]
    # The SHA1 ref is the only ORKL-sourced ref without a URL.
    orkl_no_url = [
        r
        for r in report.external_references
        if r.source_name == "ORKL" and r.url is None
    ]
    assert orkl_no_url == []


def test_unusable_reference_urls_are_skipped(converter, full_entry_data):
    full_entry_data["references"] = [
        "not a url",
        "ftp://",
        "https://good.example.com/report",
    ]
    entry = OrklLibraryEntry.model_validate(full_entry_data)
    report = converter.convert_entry(entry)[0]
    publisher_refs = [
        r
        for r in report.external_references
        if r.source_name not in ("ORKL", "ORKL Archive")
    ]
    assert [r.url for r in publisher_refs] == ["https://good.example.com/report"]
    assert publisher_refs[0].source_name == "good.example.com"


def test_report_has_no_associated_files(converter, page_entries):
    report = converter.convert_entry(page_entries[0])[0]
    assert report.files is None


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


def test_labels_merge_sources_and_origins(converter, full_entry):
    report = converter.convert_entry(full_entry)[0]
    assert set(report.labels) == {"MISPGALAXY", "Malpedia", "web"}


# ---------------------------------------------------------------------------
# Threat actors
# ---------------------------------------------------------------------------


def test_actors_are_intrusion_sets_by_default(converter, page_entries):
    entry = page_entries[0]  # single actor: APT28
    result = converter.convert_entry(entry)
    actors = [obj for obj in result if isinstance(obj, IntrusionSet)]
    assert len(actors) == 1
    assert actors[0].name == "APT28"
    assert "APT28" not in (actors[0].aliases or [])
    assert set(actors[0].aliases) == {"Fancy Bear", "Sofacy", "STRONTIUM", "Sednit"}


def test_actors_are_threat_actor_groups_when_configured(page_entries):
    converter = OrklConverter(
        api_base_url=API_BASE_URL,
        tlp_level="clear",
        threat_actor_as_intrusion_set=False,
    )
    result = converter.convert_entry(page_entries[0])
    assert any(isinstance(obj, ThreatActorGroup) for obj in result)
    assert not any(isinstance(obj, IntrusionSet) for obj in result)


def test_actor_external_reference_preserves_cross_source_identifier(
    converter, page_entries
):
    actor = next(
        obj
        for obj in converter.convert_entry(page_entries[0])
        if isinstance(obj, IntrusionSet)
    )
    ref = actor.external_references[0]
    assert ref.source_name == "MITRE"
    assert ref.external_id == "MITRE:APT28"


def test_actor_source_name_falls_back_to_orkl(converter, entries_page_data):
    data = entries_page_data[0]
    data["threat_actors"][0]["source_id"] = ""
    entry = OrklLibraryEntry.model_validate(data)
    actor = next(
        obj for obj in converter.convert_entry(entry) if isinstance(obj, IntrusionSet)
    )
    assert actor.external_references[0].source_name == "ORKL"


@pytest.mark.parametrize("source_name", [None, ""])
def test_actor_without_source_name_omits_external_reference(
    converter, entries_page_data, source_name
):
    # A null/empty source_name has no cross-source identifier to record; the
    # reference must be omitted rather than built with only a source_name, which
    # would fail STIX serialization with AtLeastOnePropertyError.
    data = entries_page_data[0]
    data["threat_actors"][0]["source_name"] = source_name
    entry = OrklLibraryEntry.model_validate(data)
    result = converter.convert_entry(entry)
    actor = next(obj for obj in result if isinstance(obj, IntrusionSet))
    assert actor.external_references is None
    # convert_entry succeeds AND every object serializes without raising.
    for obj in result:
        assert obj.to_stix2_object().get("id") == obj.id


def _all_external_references(objects: list) -> list:
    refs = []
    for obj in objects:
        refs.extend(getattr(obj, "external_references", None) or [])
    return refs


def test_every_external_reference_satisfies_at_least_one_property(
    full_entry, page_entries
):
    # The STIX invariant: every ExternalReference must populate at least one of
    # description / external_id / url. Pin it once across every fixture and both
    # ingest_tools modes rather than case by case.
    converters = [
        OrklConverter(api_base_url=API_BASE_URL, tlp_level="clear"),
        OrklConverter(api_base_url=API_BASE_URL, tlp_level="clear", ingest_tools=True),
    ]
    entries = [full_entry, *page_entries]
    for conv in converters:
        for entry in entries:
            objects = conv.convert_entry(entry)
            for ref in _all_external_references(objects):
                assert any((ref.description, ref.external_id, ref.url)), ref


def test_actor_aliases_none_when_empty(converter, entries_page_data):
    data = entries_page_data[0]
    data["threat_actors"][0]["aliases"] = ["APT28"]  # equals main_name -> excluded
    entry = OrklLibraryEntry.model_validate(data)
    actor = next(
        obj for obj in converter.convert_entry(entry) if isinstance(obj, IntrusionSet)
    )
    assert actor.aliases is None


def test_every_actor_appears_in_report_objects(converter, page_entries):
    result = converter.convert_entry(page_entries[2])  # four actors
    report = result[0]
    object_ids = {obj.id for obj in report.objects}
    for actor in _actors(result):
        assert actor.id in object_ids


def test_four_duplicate_actors_yield_four_distinct_entities(converter, page_entries):
    result = converter.convert_entry(page_entries[2])
    actors = _actors(result)
    assert len(actors) == 4
    assert {a.name for a in actors} == {"SaintBear", "Ember Bear", "Saint Bear"}


def test_actor_with_blank_main_name_is_skipped(converter, entries_page_data):
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
    actors = _actors(converter.convert_entry(entry))
    assert len(actors) == 1
    assert actors[0].name == "APT28"


# ---------------------------------------------------------------------------
# Tools (opt-in)
# ---------------------------------------------------------------------------


def test_no_tools_or_uses_relationships_by_default(converter, page_entries):
    result = converter.convert_entry(page_entries[2])  # actors carry tools
    assert not any(isinstance(obj, Tool) for obj in result)
    assert not any(isinstance(obj, Relationship) for obj in result)
    report = result[0]
    assert all(
        not isinstance(obj, (Tool, Relationship)) for obj in (report.objects or [])
    )


def test_tools_deduplicated_across_actors(full_entry):
    converter = OrklConverter(
        api_base_url=API_BASE_URL, tlp_level="clear", ingest_tools=True
    )
    result = converter.convert_entry(full_entry)
    tool_names = [obj.name for obj in result if isinstance(obj, Tool)]
    assert len(tool_names) == len(set(tool_names))
    expected = {
        tool.strip()
        for actor in full_entry.threat_actors
        for tool in actor.tools
        if tool.strip()
    }
    assert set(tool_names) == expected


def test_uses_relationship_per_actor_tool_pair(full_entry):
    converter = OrklConverter(
        api_base_url=API_BASE_URL, tlp_level="clear", ingest_tools=True
    )
    result = converter.convert_entry(full_entry)
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
# Author and markings
# ---------------------------------------------------------------------------


def test_all_objects_have_orkl_author(full_entry):
    converter = OrklConverter(
        api_base_url=API_BASE_URL, tlp_level="clear", ingest_tools=True
    )
    result = converter.convert_entry(full_entry)
    assert result  # non-empty
    assert all(obj.author is ORKL_AUTHOR for obj in result)


def test_marking_reflects_configured_tlp_level(full_entry):
    clear = OrklConverter(api_base_url=API_BASE_URL, tlp_level="clear")
    amber = OrklConverter(api_base_url=API_BASE_URL, tlp_level="amber")
    result_clear = clear.convert_entry(full_entry)
    result_amber = amber.convert_entry(full_entry)
    assert all(obj.markings[0].level == "clear" for obj in result_clear)
    assert all(obj.markings[0].level == "amber" for obj in result_amber)
    assert result_clear[0].markings[0].id != result_amber[0].markings[0].id


# ---------------------------------------------------------------------------
# Deterministic STIX ids
# ---------------------------------------------------------------------------


def test_objects_are_stix_serializable_with_deterministic_ids(full_entry):
    converter = OrklConverter(
        api_base_url=API_BASE_URL, tlp_level="clear", ingest_tools=True
    )
    first = converter.convert_entry(full_entry)
    second = converter.convert_entry(full_entry)
    assert [obj.id for obj in first] == [obj.id for obj in second]
    for obj in first:
        stix_object = obj.to_stix2_object()
        assert stix_object.get("id") == obj.id
