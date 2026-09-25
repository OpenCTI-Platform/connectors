"""Tests for the ORKL Pydantic wire-format models."""

from __future__ import annotations

from datetime import datetime

import pytest
from orkl.models import DESCRIPTION_MAX_LENGTH, OrklLibraryEntry, OrklThreatActor
from pydantic import ValidationError


class TestOrklLibraryEntryParsing:
    def test_full_entry_parses_and_threat_actors_are_typed(self, full_entry_data):
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.id == full_entry_data["id"]
        assert len(entry.threat_actors) == len(full_entry_data["threat_actors"])
        assert all(isinstance(ta, OrklThreatActor) for ta in entry.threat_actors)

    def test_deleted_entry_is_deleted_true(self, library_entry_deleted_response):
        entry = OrklLibraryEntry.model_validate(library_entry_deleted_response["data"])
        assert entry.is_deleted is True

    def test_non_deleted_entries_are_not_deleted(
        self, full_entry_data, entries_page_data
    ):
        assert OrklLibraryEntry.model_validate(full_entry_data).is_deleted is False
        for raw in entries_page_data:
            assert OrklLibraryEntry.model_validate(raw).is_deleted is False

    def test_extra_field_does_not_raise(self, full_entry_data):
        full_entry_data["some_new_unknown_field"] = "unexpected"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.id == full_entry_data["id"]

    def test_none_list_fields_normalise_to_empty_list(self, full_entry_data):
        for field in (
            "sources",
            "origins",
            "references",
            "report_names",
            "threat_actors",
        ):
            full_entry_data[field] = None
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.sources == []
        assert entry.origins == []
        assert entry.references == []
        assert entry.report_names == []
        assert entry.threat_actors == []


class TestOrklLibraryEntryName:
    def test_name_uses_title_when_present(self, full_entry_data):
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.name == full_entry_data["title"]

    def test_name_falls_back_to_report_names_when_title_empty(self, entries_page_data):
        raw = entries_page_data[1]
        assert raw["title"] == ""
        entry = OrklLibraryEntry.model_validate(raw)
        assert entry.name == raw["report_names"][0]

    def test_name_falls_back_when_title_whitespace_only(self, full_entry_data):
        full_entry_data["title"] = "   "
        full_entry_data["llm_title"] = ""
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.name == full_entry_data["report_names"][0]

    def test_name_falls_back_to_sha1_hash_when_everything_empty(self, full_entry_data):
        full_entry_data["title"] = ""
        full_entry_data["llm_title"] = ""
        full_entry_data["report_names"] = []
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.name == f"ORKL report {full_entry_data['sha1_hash']}"

    def test_name_falls_back_to_id_when_sha1_hash_also_missing(self, full_entry_data):
        full_entry_data["title"] = ""
        full_entry_data["llm_title"] = ""
        full_entry_data["report_names"] = []
        del full_entry_data["sha1_hash"]
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.name == f"ORKL report {full_entry_data['id']}"

    def test_name_never_empty(self, entries_page_data):
        for raw in entries_page_data:
            entry = OrklLibraryEntry.model_validate(raw)
            assert entry.name.strip() != ""

    def test_name_skips_blank_report_names_to_find_later_real_name(
        self, full_entry_data
    ):
        full_entry_data["title"] = ""
        full_entry_data["llm_title"] = ""
        full_entry_data["report_names"] = ["", "  ", "Real Name"]
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.name == "Real Name"

    def test_name_falls_back_to_sha1_hash_when_all_report_names_blank(
        self, full_entry_data
    ):
        full_entry_data["title"] = ""
        full_entry_data["llm_title"] = ""
        full_entry_data["report_names"] = ["", "   "]
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.name == f"ORKL report {full_entry_data['sha1_hash']}"


class TestOrklLibraryEntryDescription:
    def test_short_text_returned_unchanged_without_ellipsis(self, entries_page_data):
        raw = entries_page_data[0]
        entry = OrklLibraryEntry.model_validate(raw)
        assert entry.description == " ".join(raw["plain_text"].split())
        assert "…" not in entry.description
        assert "..." not in entry.description

    def test_long_real_text_truncated_to_max_length_with_ellipsis(
        self, full_entry_data
    ):
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert len(full_entry_data["plain_text"]) > DESCRIPTION_MAX_LENGTH
        assert len(entry.description) == DESCRIPTION_MAX_LENGTH
        assert entry.description.endswith("…")

    def test_empty_plain_text_returns_none(self, full_entry_data):
        full_entry_data["plain_text"] = ""
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.description is None

    def test_missing_plain_text_returns_none(self, full_entry_data):
        del full_entry_data["plain_text"]
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.description is None

    def test_internal_whitespace_runs_are_collapsed(self, full_entry_data):
        full_entry_data["plain_text"] = "a\n\n  b"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.description == "a b"

    def test_exactly_max_length_returned_unchanged_without_ellipsis(
        self, full_entry_data
    ):
        full_entry_data["plain_text"] = "a" * DESCRIPTION_MAX_LENGTH
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.description == "a" * DESCRIPTION_MAX_LENGTH
        assert not entry.description.endswith("…")
        assert len(entry.description) == DESCRIPTION_MAX_LENGTH

    def test_one_over_max_length_truncated_with_ellipsis(self, full_entry_data):
        full_entry_data["plain_text"] = "a" * (DESCRIPTION_MAX_LENGTH + 1)
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.description.endswith("…")
        assert len(entry.description) == DESCRIPTION_MAX_LENGTH


class TestOrklLibraryEntryPublicationDate:
    def test_normal_case_uses_file_creation_date(self, entries_page_data):
        raw = entries_page_data[0]
        entry = OrklLibraryEntry.model_validate(raw)
        assert entry.publication_date == datetime.fromisoformat(
            raw["file_creation_date"].replace("Z", "+00:00")
        )

    def test_year_one_sentinel_falls_back_to_created_at(self, full_entry_data):
        assert full_entry_data["file_creation_date"] == "0001-01-01T00:00:00Z"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        expected = datetime.fromisoformat(
            full_entry_data["created_at"].replace("Z", "+00:00")
        )
        assert entry.publication_date == expected

    def test_returns_none_when_nothing_usable(self, full_entry_data):
        full_entry_data["file_creation_date"] = "0001-01-01T00:00:00Z"
        full_entry_data["created_at"] = None
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.publication_date is None


class TestOrklLibraryEntryUpdatedDatetime:
    def test_parses_each_page_entry_and_sorts_strictly_descending(
        self, entries_page_data
    ):
        entries = [OrklLibraryEntry.model_validate(raw) for raw in entries_page_data]
        updated = [entry.updated_datetime for entry in entries]
        assert all(dt is not None for dt in updated)
        assert all(dt.tzinfo is not None for dt in updated)
        assert updated == sorted(updated, reverse=True)
        assert len(updated) == len(set(updated))

    def test_unparseable_updated_at_returns_none(self, full_entry_data):
        full_entry_data["updated_at"] = "not-a-date"
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.updated_datetime is None


class TestOrklLibraryEntryLabels:
    def test_merges_sources_and_origins_deduplicated(self, full_entry_data):
        full_entry_data["sources"] = ["MISPGALAXY", "Malpedia", "web"]
        full_entry_data["origins"] = ["web", "pdf"]
        entry = OrklLibraryEntry.model_validate(full_entry_data)
        assert entry.labels == ["MISPGALAXY", "Malpedia", "web", "pdf"]


class TestOrklLibraryEntryAuthors:
    def test_all_fixtures_round_trip_with_authors_as_string(
        self, full_entry_data, entries_page_data, library_entry_deleted_response
    ):
        """`authors` is a plain string across every real/synthetic fixture.

        Verified against the live API (20/20 sampled entries return `authors`
        as a string, e.g. `""`, `"PWC"`, `"Trend Micro"`), and both captured
        real payloads agree. This guards against a future hand-written
        fixture reintroducing the list shape the model deliberately rejects.
        """
        raws = [
            full_entry_data,
            library_entry_deleted_response["data"],
            *entries_page_data,
        ]
        for raw in raws:
            entry = OrklLibraryEntry.model_validate(raw)
            assert entry.authors is None or isinstance(entry.authors, str)

    def test_authors_as_list_is_rejected(self, full_entry_data):
        """Documents that the model deliberately rejects the list shape.

        An earlier draft wrongly allowed `authors` to be a list; the model
        (and the synthetic fixtures) were corrected to match the verified
        API contract of a plain string.
        """
        full_entry_data["authors"] = ["PWC", "Trend Micro"]
        with pytest.raises(ValidationError):
            OrklLibraryEntry.model_validate(full_entry_data)


class TestOrklThreatActor:
    def test_other_aliases_excludes_main_name_and_deduplicates(self, entries_page_data):
        actors = entries_page_data[2]["threat_actors"]
        assert len(actors) == 4
        for raw_actor in actors:
            actor = OrklThreatActor.model_validate(raw_actor)
            assert actor.main_name not in actor.other_aliases
            assert "UAC-0056" in actor.other_aliases
            assert len(actor.other_aliases) == len(set(actor.other_aliases))

    def test_none_aliases_and_tools_normalise_to_empty_list(self):
        actor = OrklThreatActor.model_validate(
            {
                "id": "x",
                "main_name": "Foo",
                "aliases": None,
                "tools": None,
                "reports": None,
            }
        )
        assert actor.aliases == []
        assert actor.tools == []

    def test_extra_field_does_not_raise(self):
        actor = OrklThreatActor.model_validate(
            {"id": "x", "main_name": "Foo", "unexpected_field": "value"}
        )
        assert actor.main_name == "Foo"
