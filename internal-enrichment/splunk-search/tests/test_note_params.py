"""Tests for utils/note_params.py — YAML parsing and schema validation."""

from __future__ import annotations

import logging

from internal_enrichment_connector.utils.note_params import (
    KNOWN_NOTE_FIELDS,
    NOTE_SCHEMA,
    load_note_params,
    parse_note_params,
    validate_note_params,
)

# ---------------------------------------------------------------------------
# parse_note_params
# ---------------------------------------------------------------------------


class TestParseNoteParams:
    def test_valid_yaml_mapping(self):
        content = "earliest: -30d@d\nlatest: now\nmax_results: 500\n"
        result = parse_note_params(content)
        assert result == {"earliest": "-30d@d", "latest": "now", "max_results": 500}

    def test_empty_string_returns_empty_dict(self):
        assert parse_note_params("") == {}

    def test_whitespace_only_returns_empty_dict(self):
        assert parse_note_params("   \n  ") == {}

    def test_yaml_with_comments(self):
        content = (
            "# Time range for authentication search\n"
            "earliest: -30d@d\n"
            "latest: now\n"
            "max_results: 500\n"
        )
        result = parse_note_params(content)
        assert result == {"earliest": "-30d@d", "latest": "now", "max_results": 500}

    def test_malformed_yaml_returns_empty_dict_and_warns(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = parse_note_params("{[invalid yaml")
        assert result == {}
        assert "[NOTE] Failed to parse Note content as YAML" in caplog.text

    def test_plain_text_note_returns_empty_dict_and_warns(self, caplog):
        """Prose text parses as a YAML scalar (str), not a mapping."""
        with caplog.at_level(logging.WARNING):
            result = parse_note_params("This is just a plain text note with no YAML.")
        assert result == {}
        assert "[NOTE] Note content is not a YAML mapping" in caplog.text

    def test_yaml_list_returns_empty_dict_and_warns(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = parse_note_params("- item1\n- item2\n")
        assert result == {}
        assert "[NOTE] Note content is not a YAML mapping" in caplog.text

    def test_none_content_returns_empty_dict(self):
        # parse_note_params expects str; callers pass "" for missing content
        assert parse_note_params("") == {}


# ---------------------------------------------------------------------------
# validate_note_params
# ---------------------------------------------------------------------------


class TestValidateNoteParams:
    def test_known_fields_pass_through(self):
        params = {"earliest": "-7d@d", "latest": "now", "max_results": 100}
        result = validate_note_params(params)
        assert result == {"earliest": "-7d@d", "latest": "now", "max_results": 100}

    def test_unknown_field_is_dropped_and_warns(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = validate_note_params({"ealiest": "-30d@d"})  # typo
        assert result == {}
        assert "ealiest" in caplog.text
        assert "[NOTE] Unknown fields in Note params (ignored)" in caplog.text

    def test_wrong_type_is_dropped_and_warns(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = validate_note_params({"max_results": "five hundred"})
        assert result == {}
        assert "[NOTE] Field 'max_results' expected int" in caplog.text

    def test_max_results_as_int_is_accepted(self):
        result = validate_note_params({"max_results": 250})
        assert result == {"max_results": 250}

    def test_timeout_as_int_is_accepted(self):
        result = validate_note_params({"timeout": 60})
        assert result == {"timeout": 60}

    def test_fields_as_list_is_accepted(self):
        result = validate_note_params({"fields": ["src", "dest", "action"]})
        assert result == {"fields": ["src", "dest", "action"]}

    def test_fields_as_str_is_rejected(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = validate_note_params({"fields": "src,dest"})
        assert result == {}
        assert "[NOTE] Field 'fields' expected list" in caplog.text

    def test_empty_params_returns_empty(self):
        assert validate_note_params({}) == {}

    def test_multiple_unknown_fields_all_reported(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = validate_note_params({"foo": "bar", "baz": 1})
        assert result == {}
        # Both unknowns should appear in a single warning
        assert "foo" in caplog.text
        assert "baz" in caplog.text


# ---------------------------------------------------------------------------
# load_note_params (integrated)
# ---------------------------------------------------------------------------


class TestLoadNoteParams:
    def test_valid_yaml_is_parsed_and_validated(self):
        content = "earliest: -30d@d\nlatest: now\nmax_results: 500\n"
        result = load_note_params(content)
        assert result == {"earliest": "-30d@d", "latest": "now", "max_results": 500}

    def test_typo_in_field_name_is_ignored(self, caplog):
        content = "ealiest: -30d@d\n"  # common typo
        with caplog.at_level(logging.WARNING):
            result = load_note_params(content)
        assert result == {}
        assert "ealiest" in caplog.text

    def test_wrong_type_for_max_results(self, caplog):
        content = 'max_results: "five hundred"\n'
        with caplog.at_level(logging.WARNING):
            result = load_note_params(content)
        assert result == {}
        assert "max_results" in caplog.text

    def test_empty_note_content(self, caplog):
        with caplog.at_level(logging.DEBUG):
            result = load_note_params("")
        assert result == {}
        assert "[NOTE] No params found in Note, using connector defaults" in caplog.text

    def test_malformed_yaml(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = load_note_params("{[invalid")
        assert result == {}
        assert "[NOTE] Failed to parse Note content as YAML" in caplog.text

    def test_plain_text_note(self, caplog):
        with caplog.at_level(logging.WARNING):
            result = load_note_params("Just some prose, not YAML params.")
        assert result == {}

    def test_description_field_is_not_read(self):
        """Ensure params only come from 'content', not a description dict key."""
        # Simulate a caller accidentally passing note["description"] instead
        result = load_note_params("This is just a description string.")
        assert result == {}

    def test_alias_fields_pass_through(self):
        """earliest_time / latest_time aliases are in the schema."""
        content = "earliest_time: -7d@d\nlatest_time: now\n"
        result = load_note_params(content)
        assert result == {"earliest_time": "-7d@d", "latest_time": "now"}

    def test_successful_parse_logs_field_names(self, caplog):
        content = "earliest: -1h@h\nlatest: now\n"
        with caplog.at_level(logging.DEBUG):
            load_note_params(content)
        assert "[NOTE] Parsed params from Note" in caplog.text


# ---------------------------------------------------------------------------
# Schema integrity
# ---------------------------------------------------------------------------


class TestSchema:
    def test_known_note_fields_matches_schema_keys(self):
        assert KNOWN_NOTE_FIELDS == frozenset(NOTE_SCHEMA.keys())

    def test_all_schema_entries_have_type_and_description(self):
        for field_name, spec in NOTE_SCHEMA.items():
            assert "type" in spec, f"Missing 'type' for field '{field_name}'"
            assert (
                "description" in spec
            ), f"Missing 'description' for field '{field_name}'"
            assert isinstance(
                spec["type"], type
            ), f"'type' for '{field_name}' must be a Python type"
