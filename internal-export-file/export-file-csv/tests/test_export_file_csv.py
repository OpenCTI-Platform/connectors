"""Tests for the export-file-csv connector column-filtering logic.

The connector module file name is hyphenated (`export-file-csv.py`) and is not
importable as a normal package, so it is loaded by path via importlib.
"""

import csv
import importlib.util
import io
import os
from unittest.mock import MagicMock

import pytest

_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src", "export-file-csv.py")
)
_spec = importlib.util.spec_from_file_location("export_file_csv", _SRC)
if _spec is None or _spec.loader is None:
    raise ImportError(f"Could not load export-file-csv module from {_SRC}")
export_file_csv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(export_file_csv)
ExportFileCsv = export_file_csv.ExportFileCsv


def _make_connector():
    """Build an instance without running __init__ (which needs a live helper)."""
    connector = ExportFileCsv.__new__(ExportFileCsv)
    connector.export_file_csv_delimiter = ";"
    connector.errors = []
    connector.helper = MagicMock()
    return connector


def _csv_headers(csv_text):
    return next(csv.reader(io.StringIO(csv_text), delimiter=";"))


class TestSelectExportColumns:
    def test_no_columns_returns_all(self):
        data_headers = ["a", "b", "c"]
        expected = [("a", "a", None), ("b", "b", None), ("c", "c", None)]
        assert ExportFileCsv._select_export_columns(data_headers, None) == expected
        assert ExportFileCsv._select_export_columns(data_headers, []) == expected

    def test_filters_and_preserves_order(self):
        data_headers = ["a", "b", "c", "d"]
        assert ExportFileCsv._select_export_columns(data_headers, ["c", "a"]) == [
            ("c", "c", None),
            ("a", "a", None),
        ]

    def test_maps_presentation_ids_to_export_keys(self):
        data_headers = ["from", "to", "relationship_type", "creators", "created_at"]
        columns = ["fromName", "toName", "relationship_type", "creator"]
        assert ExportFileCsv._select_export_columns(data_headers, columns) == [
            ("fromName", "from", None),
            ("toName", "to", None),
            ("relationship_type", "relationship_type", None),
            ("creator", "creators", None),
        ]

    def test_from_name_and_type_are_distinct_columns(self):
        # fromName and fromType both read the "from" endpoint but project
        # different sub-fields, so they must stay two distinct columns.
        data_headers = ["from", "to"]
        assert ExportFileCsv._select_export_columns(
            data_headers, ["fromName", "fromType"]
        ) == [
            ("fromName", "from", None),
            ("fromType", "from", "entity_type"),
        ]

    def test_deduplicates_exact_duplicate_columns(self):
        data_headers = ["from", "to"]
        assert ExportFileCsv._select_export_columns(
            data_headers, ["fromName", "fromName"]
        ) == [("fromName", "from", None)]

    def test_drops_columns_without_matching_key(self):
        data_headers = ["from", "to", "relationship_type"]
        assert ExportFileCsv._select_export_columns(
            data_headers, ["toName", "does_not_exist"]
        ) == [("toName", "to", None)]

    def test_falls_back_to_all_when_nothing_matches(self):
        # A non-empty request that resolves to nothing must not yield an empty
        # export; fall back to all columns.
        data_headers = ["from", "to"]
        assert ExportFileCsv._select_export_columns(
            data_headers, ["does_not_exist"]
        ) == [("from", "from", None), ("to", "to", None)]


class TestExportDictListToCsv:
    def test_all_columns_when_no_filter(self):
        connector = _make_connector()
        data = [{"name": "A", "entity_type": "Malware"}]
        headers = _csv_headers(connector.export_dict_list_to_csv(data))
        assert headers == ["entity_type", "name"]

    def test_filters_to_visible_columns(self):
        connector = _make_connector()
        data = [{"name": "A", "entity_type": "Malware", "created_at": "2026"}]
        out = connector.export_dict_list_to_csv(data, ["name", "entity_type"])
        assert _csv_headers(out) == ["name", "entity_type"]

    def test_relationship_alias_end_to_end(self):
        connector = _make_connector()
        data = [
            {
                "from": {"name": "Actor"},
                "to": {"observable_value": "1.2.3.4"},
                "relationship_type": "uses",
                "created_at": "2026-01-01",
            }
        ]
        out = connector.export_dict_list_to_csv(
            data, ["fromName", "toName", "relationship_type"]
        )
        rows = list(csv.reader(io.StringIO(out), delimiter=";"))
        # The requested presentation ids are kept as the output headers.
        assert rows[0] == ["fromName", "toName", "relationship_type"]
        # Nested dicts are rendered via their representative value.
        assert rows[1] == ["Actor", "1.2.3.4", "uses"]

    def test_from_name_and_type_export_distinct_values(self):
        # Regression for the reviewer feedback: selecting both fromName and
        # fromType must yield two columns - the endpoint's name and its entity
        # type - instead of collapsing into a single "from" column.
        connector = _make_connector()
        data = [
            {
                "from": {"name": "Emotet", "entity_type": "Malware"},
                "to": {
                    "observable_value": "1.2.3.4",
                    "entity_type": "IPv4-Addr",
                },
                "relationship_type": "uses",
            }
        ]
        out = connector.export_dict_list_to_csv(
            data, ["fromName", "fromType", "toName", "toType"]
        )
        rows = list(csv.reader(io.StringIO(out), delimiter=";"))
        assert rows[0] == ["fromName", "fromType", "toName", "toType"]
        assert rows[1] == ["Emotet", "Malware", "1.2.3.4", "IPv4-Addr"]

    def test_hashes_expansion_still_applies(self):
        connector = _make_connector()
        data = [
            {
                "observable_value": "x",
                "hashes": [{"algorithm": "MD5", "hash": "abc"}],
            }
        ]
        rows = list(
            csv.reader(
                io.StringIO(
                    connector.export_dict_list_to_csv(
                        data, ["observable_value", "hashes"]
                    )
                ),
                delimiter=";",
            )
        )
        headers = rows[0]
        assert "hashes" in headers
        assert "hashes_SHA-256" in headers
        # The MD5 expansion header must use the "hashes_" prefix so the
        # row-generation logic actually populates it (regression test).
        assert "hashes_MD5" in headers
        assert rows[1][headers.index("hashes_MD5")] == "abc"


class TestExportListVisibleColumns:
    def test_export_list_reads_visible_columns(self):
        connector = _make_connector()
        data = {
            "file_name": "export.csv",
            "export_type": "simple",
            "file_markings": [],
            "entity_id": "id-1",
            "entity_type": "Stix-Domain-Object",
            "list_params": {"visible_columns": ["name"]},
        }
        entities_list = [{"name": "A", "entity_type": "Malware"}]

        connector._export_list(data, entities_list, "filters")

        push = connector.helper.api.stix_domain_object.push_list_export
        push.assert_called_once()
        # csv_data is the 5th positional arg (entity_id, entity_type, file_name,
        # file_markings, csv_data, list_filters).
        csv_data = push.call_args.args[4]
        assert _csv_headers(csv_data) == ["name"]

    def test_export_list_without_visible_columns_exports_all(self):
        connector = _make_connector()
        data = {
            "file_name": "export.csv",
            "export_type": "simple",
            "file_markings": [],
            "entity_id": "id-1",
            "entity_type": "Stix-Domain-Object",
            "list_params": {},
        }
        entities_list = [{"name": "A", "entity_type": "Malware"}]

        connector._export_list(data, entities_list, "filters")

        csv_data = (
            connector.helper.api.stix_domain_object.push_list_export.call_args.args[4]
        )
        assert _csv_headers(csv_data) == ["entity_type", "name"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
