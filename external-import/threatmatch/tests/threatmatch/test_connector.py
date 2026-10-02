from datetime import datetime
from unittest.mock import call

import freezegun
import pytest
from pytest_mock import MockerFixture
from threatmatch.config import ConnectorSettings
from threatmatch.connector import Connector
from threatmatch.converter import Converter


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_run(mocked_helper: MockerFixture) -> None:
    connector = Connector(
        helper=mocked_helper,
        config=ConnectorSettings(),
        converter=Converter(
            helper=mocked_helper,
            author_name="ThreatMatch",
            author_description="ThreatMatch Description",
            tlp_level="amber",
            threat_actor_to_intrusion_set=True,
        ),
    )
    connector.run()
    assert connector.helper.connector_logger.info.call_count == 1
    connector.helper.connector_logger.info.assert_has_calls(
        [call("Connector starting...")]
    )

    assert mocked_helper.schedule_process.call_count == 1


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_process(mocked_helper: MockerFixture) -> None:
    connector = Connector(
        helper=mocked_helper,
        config=ConnectorSettings(),
        converter=Converter(
            helper=mocked_helper,
            author_name="ThreatMatch",
            author_description="ThreatMatch Description",
            tlp_level="amber",
            threat_actor_to_intrusion_set=True,
        ),
    )
    connector._process()

    assert connector.helper.connector_logger.error.call_count == 1  # Bad url
    assert (
        "HTTPSConnectionPool(host='test-threatmatch-url', port=443): Max retries exceeded with url: /api/developers-platform/token"
        in connector.helper.connector_logger.error.call_args[0][0]
    )
    assert connector.helper.connector_logger.info.call_count == 2
    connector.helper.connector_logger.info.assert_has_calls(
        [
            call("Running connector..."),
            call("Connector last run: never"),
        ]
    )


@freezegun.freeze_time("2025-04-17T15:24:00Z")
@pytest.mark.usefixtures("mock_config", "mocked_helper")
def test_connector_process_data_last_run(
    mocker: MockerFixture, mocked_helper: MockerFixture
) -> None:
    now = datetime.fromisoformat("2025-04-17T15:24:00Z")
    yesterday = datetime.fromisoformat("2025-04-16T15:24:00Z")

    # Only test _process_data method
    collect_intelligence = mocker.patch.object(Connector, "_collect_intelligence")

    connector = Connector(
        helper=mocked_helper,
        config=ConnectorSettings(),
        converter=Converter(
            helper=mocked_helper,
            author_name="ThreatMatch",
            author_description="ThreatMatch Description",
            tlp_level="amber",
            threat_actor_to_intrusion_set=True,
        ),
    )

    # 1 No last_run in state
    connector._process_data()
    collect_intelligence.assert_called_once_with(None)
    mocked_helper.set_state.assert_called_once_with({"last_run": now.isoformat()})

    # 2 last_run in state as timestamp (retro compatibility)
    mocked_helper.get_state.return_value = {"last_run": yesterday.timestamp()}
    connector._process_data()
    collect_intelligence.assert_called_with(yesterday)
    mocked_helper.set_state.assert_called_with({"last_run": now.isoformat()})

    # 3 last_run in state as ISO format
    mocked_helper.get_state.return_value = {"last_run": yesterday.isoformat()}
    connector._process_data()
    collect_intelligence.assert_called_with(yesterday)
    mocked_helper.set_state.assert_called_with({"last_run": now.isoformat()})


def test_connector_deduplicates_stix_objects_keeping_richer_entity() -> None:
    connector = Connector(
        helper=None,
        config=None,
        converter=None,
    )
    duplicate_id = "malware--01234567-89ab-cdef-0123-456789abcdef"
    rich_object = {
        "id": duplicate_id,
        "type": "malware",
        "name": "Example Malware",
        "description": "Longer description",
        "modified": "2025-01-02T00:00:00Z",
    }
    sparse_object = {
        "id": duplicate_id,
        "type": "malware",
        "name": "Example Malware",
    }
    result = connector._deduplicate_processed_objects([sparse_object, rich_object])
    assert len(result) == 1
    assert result[0] == rich_object


def test_connector_merges_labels_from_duplicate_indicator_sources() -> None:
    # Simulates the same indicator coming from both a profile STIX export
    # (rich context labels) and the TAXII IOC feed (different labels), as
    # described in issue #4906.
    connector = Connector(
        helper=None,
        config=None,
        converter=None,
    )
    duplicate_id = "indicator--01234567-89ab-cdef-0123-456789abcdef"
    profile_object = {
        "id": duplicate_id,
        "type": "indicator",
        "pattern": "[file:hashes.'SHA-256'='abc']",
        "labels": ["Downloader", "United States of America (USA)"],
        "modified": "2025-01-01T00:00:00Z",
    }
    taxii_object = {
        "id": duplicate_id,
        "type": "indicator",
        "pattern": "[file:hashes.'SHA-256'='abc']",
        "labels": ["Ransom demand", "Ransomware"],
        "valid_until": "2026-01-01T00:00:00Z",
        "confidence": 80,
        "modified": "2025-01-02T00:00:00Z",
    }

    result = connector._deduplicate_processed_objects([profile_object, taxii_object])
    assert len(result) == 1
    merged = result[0]
    assert merged["valid_until"] == "2026-01-01T00:00:00Z"
    assert merged["confidence"] == 80
    assert merged["labels"] == [
        "Downloader",
        "United States of America (USA)",
        "Ransom demand",
        "Ransomware",
    ]
