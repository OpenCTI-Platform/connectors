"""Guard tests validating the ORKL API fixture corpus stays well-formed."""

from datetime import datetime, timezone

import pytest
from conftest import _load_resource

ENVELOPE_KEYS = {"data", "message", "status"}

ALL_RESOURCE_FILES = [
    "library_entry_full.json",
    "library_entries_page.json",
    "library_entries_empty.json",
    "library_entry_deleted.json",
]

# `library_entry_full.json` is a verified byte-for-byte copy of a real
# captured API payload and must never be edited to satisfy a test, so it is
# excluded from the hand-written fixture corpus checked below.
HAND_WRITTEN_RESOURCE_FILES = [
    "library_entries_page.json",
    "library_entry_deleted.json",
]

ISO_TO_EPOCH_FIELD_PAIRS = [
    ("created_at", "ts_created_at"),
    ("updated_at", "ts_updated_at"),
    ("file_creation_date", "ts_creation_date"),
    ("file_modification_date", "ts_modification_date"),
]


def _entries_from_resource(filename: str) -> list:
    # Reuses conftest's cached loader so collection-time parametrization
    # doesn't re-read the JSON files that fixtures already load lazily.
    raw = _load_resource(filename)
    data = raw["data"]
    if data is None:
        return []
    return data if isinstance(data, list) else [data]


def _iso_to_utc_epoch(iso_value: str) -> int:
    return int(
        datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
        .astimezone(timezone.utc)
        .timestamp()
    )


def _iso_epoch_pair_cases():
    cases = []
    for filename in HAND_WRITTEN_RESOURCE_FILES:
        for entry in _entries_from_resource(filename):
            for iso_field, ts_field in ISO_TO_EPOCH_FIELD_PAIRS:
                cases.append((filename, entry["id"], iso_field, ts_field))
    return cases


def _entry_files_match_hash(entry: dict) -> bool:
    sha1_hash = entry["sha1_hash"]
    files = entry["files"]
    return (
        files["pdf"] == f"https://archive.orkl.eu/{sha1_hash}.pdf"
        and files["text"] == f"https://archive.orkl.eu/{sha1_hash}.txt"
        and files["img"] == f"https://archive.orkl.eu/{sha1_hash}.jpg"
    )


def test_all_resource_files_parse_as_valid_envelopes():
    for filename in ALL_RESOURCE_FILES:
        parsed = _load_resource(filename)
        assert ENVELOPE_KEYS.issubset(parsed.keys())
        assert parsed["status"] == "success"


def test_library_entries_page_has_four_entries_sorted_desc(
    library_entries_page_response,
):
    entries = library_entries_page_response["data"]
    assert len(entries) == 4
    updated_ats = [entry["updated_at"] for entry in entries]
    assert updated_ats == sorted(updated_ats, reverse=True)
    assert len(updated_ats) == len(set(updated_ats))


def test_empty_response_data_is_none(library_entries_empty_response):
    assert library_entries_empty_response["data"] is None


def test_deleted_entry_has_non_null_deleted_at(library_entry_deleted_response):
    entry = library_entry_deleted_response["data"]
    assert entry["deleted_at"] is not None


def test_page_entry_two_has_empty_title_and_no_threat_actors(entries_page_data):
    entry = entries_page_data[1]
    assert entry["title"] == ""
    assert entry["threat_actors"] == []


def test_page_entry_three_has_four_actors_sharing_uac_0056_alias(entries_page_data):
    entry = entries_page_data[2]
    threat_actors = entry["threat_actors"]
    assert len(threat_actors) == 4
    for actor in threat_actors:
        assert "UAC-0056" in actor["aliases"]


def test_all_entries_have_files_urls_matching_their_own_sha1_hash(
    library_entry_full_response,
    library_entries_page_response,
    library_entry_deleted_response,
):
    entries = []
    entries.append(library_entry_full_response["data"])
    entries.extend(library_entries_page_response["data"])
    entries.append(library_entry_deleted_response["data"])

    for entry in entries:
        assert _entry_files_match_hash(entry)


def test_full_entry_has_long_plain_text_and_threat_actors(full_entry_data):
    assert len(full_entry_data["plain_text"]) > 10000
    assert len(full_entry_data["threat_actors"]) > 0


def test_mutating_full_entry_data_and_entries_page_data_leaks_into_next_test(
    full_entry_data, entries_page_data
):
    """Deliberately mutate fixtures in place to expose fixture-scope leakage.

    This test's name is alphabetically ordered (and precedes in source order)
    before `test_pristine_full_entry_data_and_entries_page_data_after_prior_
    mutation`, so pytest's default file-order execution actually runs this
    mutation before the following assertion test. If `full_entry_data` /
    `entries_page_data` (or their parent response fixtures) are session-scoped
    and return a shared mutable object instead of a fresh copy per test, this
    mutation will leak into the next test and cause it to fail.
    """
    del full_entry_data["title"]
    entries_page_data.clear()
    assert "title" not in full_entry_data
    assert entries_page_data == []


def test_pristine_full_entry_data_and_entries_page_data_after_prior_mutation(
    full_entry_data, entries_page_data
):
    """Assert the fixtures are pristine, independent of prior test mutation.

    This fails if `full_entry_data` / `entries_page_data` leak mutable state
    across tests (e.g. session-scoped fixtures returning the same object).
    """
    assert "title" in full_entry_data
    assert full_entry_data["title"] != ""
    assert len(entries_page_data) == 4


@pytest.mark.parametrize(
    "filename,entry_id,iso_field,ts_field", _iso_epoch_pair_cases()
)
def test_hand_written_fixture_iso_and_epoch_timestamps_agree_as_utc(
    filename, entry_id, iso_field, ts_field
):
    """ISO-8601 and unix-epoch timestamp pairs must be numerically consistent.

    ORKL API entries carry both an ISO-8601 datetime and its unix-epoch
    equivalent for several fields. In hand-written fixtures these must
    agree exactly, treating the ISO string as UTC, or a later task parsing
    one representation instead of the other could be silently masking a bug.
    """
    entry = next(e for e in _entries_from_resource(filename) if e["id"] == entry_id)
    expected_epoch = _iso_to_utc_epoch(entry[iso_field])
    assert entry[ts_field] == expected_epoch, (
        f"{filename} entry {entry_id}: {ts_field} ({entry[ts_field]}) does not "
        f"match {iso_field} ({entry[iso_field]}) interpreted as UTC "
        f"(expected {expected_epoch})"
    )
