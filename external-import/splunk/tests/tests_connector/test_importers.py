from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

from splunk_connector.importers.base import BaseImporter
from splunk_connector.importers.identities import IdentitiesImporter
from splunk_connector.importers.incidents import IncidentsImporter
from splunk_connector.importers.indicators import IndicatorsImporter


class _ImporterForTest(BaseImporter):
    state_key = "dataset"

    @property
    def interval(self):
        return timedelta(minutes=5)


def _config(**overrides):
    splunk = SimpleNamespace(
        indicators_interval=timedelta(hours=1),
        identities_interval=timedelta(days=1),
        incidents_interval=timedelta(minutes=15),
        incidents_lookback=timedelta(days=1),
        indicators_search=None,
        identities_search=None,
        incidents_search=None,
        include_disabled=False,
        max_records_per_run=1,
        note_type_search_parameters="Search Parameters",
    )
    for key, value in overrides.items():
        setattr(splunk, key, value)
    return SimpleNamespace(splunk=splunk)


def test_base_importer_should_run_without_state():
    importer = _ImporterForTest(_config(), MagicMock(), MagicMock())

    assert importer.should_run({}, datetime.now(UTC)) is True


def test_base_importer_should_run_after_interval_elapsed():
    importer = _ImporterForTest(_config(), MagicMock(), MagicMock())
    now = datetime(2026, 5, 31, 12, 0, tzinfo=UTC)

    assert importer.should_run(
        {"dataset": {"last_success": "2026-05-31T11:54:00+00:00"}}, now
    )
    assert not importer.should_run(
        {"dataset": {"last_success": "2026-05-31T11:59:00+00:00"}}, now
    )


def test_base_importer_parse_state_datetime_handles_invalid_values():
    assert BaseImporter._parse_state_datetime(None) is None
    assert BaseImporter._parse_state_datetime("not-a-date") is None
    assert BaseImporter._parse_state_datetime("2026-05-31T12:00:00Z").tzinfo is not None


def test_base_importer_cap_records_honors_limit():
    records = [{"id": 1}, {"id": 2}]

    assert BaseImporter._cap_records(records, 1) == [{"id": 1}]
    assert BaseImporter._cap_records(records, 0) == records


def test_indicators_default_path_caps_records_and_aggregates_objects():
    client = MagicMock()
    client.get_saved_searches.return_value = [{"name": "one"}, {"name": "two"}]
    converter = MagicMock()
    converter.saved_search_to_stix.side_effect = [["obj-1"], ["obj-2"]]
    importer = IndicatorsImporter(_config(), client, converter)

    objects, state = importer.collect({})

    assert objects == ["obj-1"]
    client.get_saved_searches.assert_called_once_with(include_disabled=False)
    converter.saved_search_to_stix.assert_called_once_with(
        {"name": "one"},
        note_type="Search Parameters",
    )
    assert state["objects_count"] == 1
    assert state["records_count"] == 1


def test_indicators_custom_search_path_does_not_apply_default_cap():
    client = MagicMock()
    client.run_search.return_value = [{"name": "one"}, {"name": "two"}]
    converter = MagicMock()
    converter.saved_search_to_stix.side_effect = [["obj-1"], ["obj-2"]]
    importer = IndicatorsImporter(
        _config(indicators_search="index=main", max_records_per_run=1),
        client,
        converter,
    )

    objects, state = importer.collect({})

    assert objects == ["obj-1", "obj-2"]
    client.run_search.assert_called_once_with("index=main", max_records=1)
    assert state["records_count"] == 2


def test_identities_default_path_caps_records_and_aggregates_objects():
    client = MagicMock()
    client.get_assets_identities.return_value = [{"host": "one"}, {"host": "two"}]
    converter = MagicMock()
    converter.asset_identity_to_stix.side_effect = [["obj-1"], ["obj-2"]]
    importer = IdentitiesImporter(_config(), client, converter)

    objects, state = importer.collect({})

    assert objects == ["obj-1"]
    client.get_assets_identities.assert_called_once_with()
    assert state["records_count"] == 1


def test_identities_custom_search_path():
    client = MagicMock()
    client.run_search.return_value = [{"identity": "alice"}]
    converter = MagicMock()
    converter.asset_identity_to_stix.return_value = ["obj-1"]
    importer = IdentitiesImporter(_config(identities_search="index=identity"), client, converter)

    objects, state = importer.collect({})

    assert objects == ["obj-1"]
    client.run_search.assert_called_once_with("index=identity", max_records=1)
    assert state["objects_count"] == 1


def test_incidents_first_run_uses_lookback_for_default_path():
    client = MagicMock()
    client.get_findings.return_value = [{"title": "finding"}]
    converter = MagicMock()
    converter.finding_to_stix.return_value = ["incident", "sighting"]
    importer = IncidentsImporter(_config(), client, converter)

    objects, state = importer.collect({})

    assert objects == ["incident", "sighting"]
    earliest_time = client.get_findings.call_args.kwargs["earliest_time"]
    assert earliest_time == state["last_earliest_time"]
    assert datetime.fromisoformat(earliest_time).tzinfo is not None


def test_incidents_reuses_last_success_for_custom_search():
    client = MagicMock()
    client.run_search.return_value = [{"title": "finding"}]
    converter = MagicMock()
    converter.finding_to_stix.return_value = ["incident"]
    importer = IncidentsImporter(_config(incidents_search="index=notable"), client, converter)
    last_success = "2026-05-31T12:00:00+00:00"

    objects, state = importer.collect({"incidents": {"last_success": last_success}})

    assert objects == ["incident"]
    client.run_search.assert_called_once_with(
        "index=notable",
        earliest_time=last_success,
        max_records=1,
    )
    assert state["last_earliest_time"] == last_success
