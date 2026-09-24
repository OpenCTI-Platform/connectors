"""Unit tests for the export-file-threat-hunting-rules connector.

Covers the DataCollector rule grouping / zip packaging, the ConfigConnector
loader, and every export-scope branch of
``ConnectorExportFileThreatHunting.process_message`` (selection, query, single
simple, single full via container ids and via relationships, the invalid scope
and the generic error path).
"""

import io
import zipfile
from unittest.mock import MagicMock

from export_file_threat_hunting_rules_connector.connector import (
    ConnectorExportFileThreatHunting,
    DataCollector,
)


def _indicator(pattern_type, pattern="rule x {}", name="rule", _id="indicator--1"):
    return {
        "id": _id,
        "name": name,
        "pattern_type": pattern_type,
        "pattern": pattern,
    }


def _connector():
    return ConnectorExportFileThreatHunting(config=MagicMock(), helper=MagicMock())


def _base_data(**overrides):
    data = {
        "entity_id": "entity--1",
        "entity_type": "Indicator",
        "file_name": "export.zip",
        "export_type": "simple",
        "file_markings": [],
        "access_filter": None,
        "export_scope": "selection",
        "format": "application/zip",
    }
    data.update(overrides)
    return data


# --------------------------------------------------------------------------- #
# DataCollector
# --------------------------------------------------------------------------- #
class TestDataCollector:
    def test_extract_groups_patterns_by_type(self):
        collector = DataCollector(MagicMock())
        collector.extract(
            [
                _indicator("yara", "rule a {}"),
                _indicator("sigma", "title: x"),
                _indicator("snort", "alert tcp any any"),
            ]
        )
        assert collector.errors == []
        assert collector.patterns["yara"] == ["rule a {}"]
        assert collector.patterns["sigma"] == ["title: x"]
        assert collector.patterns["snort"] == ["alert tcp any any"]
        # compile() (called by extract) joins the collected patterns.
        assert "rule a {}" in collector.pattern_files["yara"]

    def test_extract_records_error_for_unknown_pattern_type(self):
        collector = DataCollector(MagicMock())
        collector.extract([_indicator("stix", "[ipv4-addr:value='1.1.1.1']", "bad")])
        assert collector.errors == ["bad"]
        collector.helper.connector_logger.warning.assert_called_once()

    def test_zip_files_only_includes_non_empty_formats(self):
        collector = DataCollector(MagicMock())
        collector.extract(
            [_indicator("yara", "rule a {}"), _indicator("snort", "alert tcp any any")]
        )
        names = zipfile.ZipFile(io.BytesIO(collector.zip_files())).namelist()
        assert "yara.yar" in names
        assert "snort.rules" in names
        assert "sigma.yml" not in names


# --------------------------------------------------------------------------- #
# process_message - selection / query
# --------------------------------------------------------------------------- #
class TestSelectionAndQuery:
    def test_selection_success_pushes_zip_and_renames_unknown(self):
        conn = _connector()
        conn.helper.api_impersonate.stix_domain_object.list.return_value = [
            _indicator("yara", "rule a {}")
        ]
        # .unknown must be rewritten to .zip
        data = _base_data(
            file_name="export.unknown", main_filter={}, export_scope="selection"
        )

        assert conn.process_message(data) == "Export done"

        push = conn.helper.api.stix_domain_object.push_list_export
        push.assert_called_once()
        assert push.call_args.kwargs["mime_type"] == "application/zip"
        assert push.call_args.kwargs["file_name"] == "export.zip"
        conn.helper.api.work.report_expectation.assert_not_called()

    def test_selection_all_failures_reports_expectation(self):
        conn = _connector()
        conn.helper.api_impersonate.stix_domain_object.list.return_value = [
            _indicator("stix", "x", "bad")
        ]
        data = _base_data(main_filter={}, export_scope="selection")

        conn.process_message(data)

        conn.helper.api.work.report_expectation.assert_called_once()

    def test_query_success_pushes_zip(self):
        conn = _connector()
        conn.helper.api_impersonate.stix2.export_entities_list.return_value = [
            _indicator("sigma", "title: x")
        ]
        data = _base_data(
            export_scope="query",
            list_params={
                "filters": None,
                "search": None,
                "orderBy": None,
                "orderMode": None,
            },
        )

        assert conn.process_message(data) == "Export done"
        conn.helper.api.stix_domain_object.push_list_export.assert_called_once()


# --------------------------------------------------------------------------- #
# process_message - single (simple)
# --------------------------------------------------------------------------- #
class TestSingleSimple:
    def test_single_simple_indicator_success(self):
        conn = _connector()
        conn.helper.api.stix2.get_reader.return_value = MagicMock(
            return_value=_indicator("yara", "rule a {}")
        )
        data = _base_data(export_scope="single", export_type="simple")

        assert conn.process_message(data) == "Export done"
        conn.helper.api.stix_domain_object.push_entity_export.assert_called_once()

    def test_single_simple_bad_pattern_reports_expectation(self):
        conn = _connector()
        conn.helper.api.stix2.get_reader.return_value = MagicMock(
            return_value=_indicator("stix", "x", "bad")
        )
        data = _base_data(export_scope="single", export_type="simple")

        conn.process_message(data)
        conn.helper.api.work.report_expectation.assert_called_once()
        conn.helper.api.stix_domain_object.push_entity_export.assert_not_called()

    def test_single_simple_non_indicator_reports_expectation(self):
        conn = _connector()
        conn.helper.api.stix2.get_reader.return_value = MagicMock(
            return_value={"id": "report--1", "name": "rep"}
        )
        data = _base_data(
            export_scope="single", export_type="simple", entity_type="Report"
        )

        conn.process_message(data)
        conn.helper.api.work.report_expectation.assert_called_once()


# --------------------------------------------------------------------------- #
# process_message - single (full)
# --------------------------------------------------------------------------- #
class TestSingleFull:
    def test_full_container_resolves_object_ids(self):
        conn = _connector()
        container = {
            "id": "report--1",
            "name": "rep",
            "objectsIds": ["a", "b"],
            "pattern_type": None,
        }
        conn.helper.api.stix2.get_reader.return_value = MagicMock(
            return_value=container
        )
        conn.helper.api_impersonate.opencti_stix_object_or_stix_relationship.list.return_value = [
            _indicator("yara", "rule a {}")
        ]
        data = _base_data(
            export_scope="single",
            export_type="full",
            entity_type="Report",
            access_filter={"mode": "and", "filters": [], "filterGroups": []},
        )

        assert conn.process_message(data) == "Export done"
        conn.helper.api.stix_domain_object.push_entity_export.assert_called_once()

    def test_full_container_via_relationships_skips_none_indicator(self):
        conn = _connector()
        container = {
            "id": "report--1",
            "name": "rep",
            "objectsIds": None,
            "pattern_type": None,
        }
        conn.helper.api.stix2.get_reader.return_value = MagicMock(
            return_value=container
        )
        conn.helper.api_impersonate.stix_core_relationship.list.return_value = [
            {"to": {"id": "indicator--x"}},
            {"to": {"id": "indicator--y"}},
        ]
        # Second read returns None and must be skipped (the guarded branch).
        conn.helper.api_impersonate.indicator.read.side_effect = [
            _indicator("snort", "alert tcp any any"),
            None,
        ]
        data = _base_data(
            export_scope="single", export_type="full", entity_type="Report"
        )

        assert conn.process_message(data) == "Export done"
        conn.helper.api.stix_domain_object.push_entity_export.assert_called_once()


# --------------------------------------------------------------------------- #
# process_message - error paths
# --------------------------------------------------------------------------- #
class TestErrorPaths:
    def test_invalid_scope_returns_export_failed(self):
        conn = _connector()
        data = _base_data(export_scope="nonsense")
        assert conn.process_message(data) == "Export failed"

    def test_unexpected_exception_returns_export_failed(self):
        conn = _connector()
        conn.helper.api_impersonate.stix_domain_object.list.side_effect = RuntimeError(
            "boom"
        )
        data = _base_data(main_filter={}, export_scope="selection")
        assert conn.process_message(data) == "Export failed"
        conn.helper.connector_logger.error.assert_called_once()


# --------------------------------------------------------------------------- #
# config loader + package entrypoints
# --------------------------------------------------------------------------- #
def test_config_loader_sets_connector_type():
    from export_file_threat_hunting_rules_connector.config_loader import ConfigConnector

    config = ConfigConnector()
    assert config.load["connector"]["type"] == "INTERNAL_EXPORT_FILE"


def test_main_module_is_importable():
    import main  # noqa: F401
