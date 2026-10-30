from datetime import datetime
from unittest.mock import MagicMock, call

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


def test_connector_preserves_markings_from_duplicate_indicator_sources() -> None:
    connector = Connector(helper=None, config=None, converter=None)
    indicator_id = "indicator--11111111-1111-4111-8111-111111111111"
    attack_pattern_id = "attack-pattern--11111111-1111-4111-8111-111111111111"
    first_marking = "marking-definition--11111111-1111-4111-8111-111111111111"
    second_marking = "marking-definition--22222222-2222-4222-8222-222222222222"
    tlp_green = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
    tlp_amber = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    tlp_red = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"

    result = connector._deduplicate_processed_objects(
        [
            {
                "type": "indicator",
                "id": indicator_id,
                "object_marking_refs": [first_marking, tlp_green],
            },
            {
                "type": "indicator",
                "id": indicator_id,
                "object_marking_refs": [second_marking, tlp_amber],
                "name": "Newer",
            },
            {
                "type": "attack-pattern",
                "id": attack_pattern_id,
                "name": "Valid Accounts",
                "object_marking_refs": [tlp_amber],
            },
            {
                "type": "attack-pattern",
                "id": attack_pattern_id,
                "name": "Valid Accounts",
                "object_marking_refs": [tlp_red],
            },
        ]
    )

    by_id = {obj["id"]: obj for obj in result}
    assert by_id[indicator_id]["object_marking_refs"] == [
        first_marking,
        second_marking,
        tlp_amber,
    ]
    assert by_id[attack_pattern_id]["object_marking_refs"] == [
        tlp_red,
    ]


def test_connector_prioritizes_newer_modified_timestamp_when_deduplicating() -> None:
    connector = Connector(helper=None, config=None, converter=None)
    duplicate_id = "indicator--01234567-89ab-cdef-0123-456789abcdef"
    older_richer = {
        "id": duplicate_id,
        "type": "indicator",
        "name": "Stale Name",
        "description": "Older description",
        "confidence": 50,
        "valid_until": "2025-06-01T00:00:00Z",
        "modified": "2025-01-01T00:00:00Z",
    }
    newer_sparser = {
        "id": duplicate_id,
        "type": "indicator",
        "name": "Fresh Name",
        "confidence": 90,
        "modified": "2025-02-01T00:00:00Z",
    }

    result = connector._deduplicate_processed_objects([older_richer, newer_sparser])

    assert len(result) == 1
    assert result[0]["name"] == "Fresh Name"
    assert result[0]["confidence"] == 90
    assert result[0]["modified"] == "2025-02-01T00:00:00Z"
    assert result[0]["description"] == "Older description"
    assert result[0]["valid_until"] == "2025-06-01T00:00:00Z"


def test_connector_adds_observables_only_to_reports_referencing_indicators(
    mocker: MockerFixture,
) -> None:
    helper = MagicMock()
    helper.get_state.return_value = {}
    converter = Converter(
        helper=helper,
        author_name="ThreatMatch",
        author_description="ThreatMatch Description",
        tlp_level="amber",
        threat_actor_to_intrusion_set=False,
    )
    connector = Connector(helper=helper, config=None, converter=converter)
    report_one_id = "report--11111111-1111-4111-8111-111111111111"
    report_two_id = "report--22222222-2222-4222-8222-222222222222"
    sha_indicator_id = "indicator--11111111-1111-4111-8111-111111111111"
    url_indicator_id = "indicator--22222222-2222-4222-8222-222222222222"
    unrelated_indicator_id = "indicator--33333333-3333-4333-8333-333333333333"
    source_marking = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
    sha_pattern = (
        "[file:hashes.'SHA-256'="
        "'55a06694bb96ecc422a7a6c731053b1ef5a35b5f5bac78752ca60b729cf7441f']"
    )
    mocker.patch.object(
        connector,
        "_collect_intelligence",
        return_value=[
            {
                "type": "report",
                "id": report_one_id,
                "name": "Report 1",
                "object_refs": [sha_indicator_id, url_indicator_id],
            },
            {
                "type": "report",
                "id": report_two_id,
                "name": "Report 2",
                "object_refs": [
                    sha_indicator_id,
                    "indicator--99999999-9999-4999-8999-999999999999",
                ],
            },
            {
                "type": "indicator",
                "id": sha_indicator_id,
                "pattern_type": "stix",
                "pattern": sha_pattern,
                "object_marking_refs": [source_marking],
            },
            {
                "type": "indicator",
                "id": url_indicator_id,
                "pattern_type": "stix",
                "pattern": "[url:value='https://example.org/path']",
            },
            {
                "type": "indicator",
                "id": unrelated_indicator_id,
                "pattern_type": "stix",
                "pattern": "[email-addr:value='person@example.org']",
            },
        ],
    )

    connector._process_data()

    items = helper.stix2_create_bundle.call_args.kwargs["items"]
    reports = {
        obj["id"]: obj
        for obj in items
        if isinstance(obj, dict) and obj["type"] == "report"
    }
    observables = {
        obj["type"]: obj
        for obj in items
        if isinstance(obj, dict) and obj["type"] in {"file", "url", "email-addr"}
    }
    assert set(observables) == {"file", "url"}
    assert reports[report_one_id]["object_refs"] == [
        sha_indicator_id,
        url_indicator_id,
        observables["file"]["id"],
        observables["url"]["id"],
    ]
    assert reports[report_two_id]["object_refs"] == [
        sha_indicator_id,
        "indicator--99999999-9999-4999-8999-999999999999",
        observables["file"]["id"],
    ]
    assert observables["file"]["object_marking_refs"] == [source_marking]
    assert observables["file"]["x_opencti_created_by_ref"] == converter.author.id
    assert sum(obj["type"] == "file" for obj in items if isinstance(obj, dict)) == 1
    assert (
        helper.send_stix2_bundle.call_args.kwargs["cleanup_inconsistent_bundle"] is True
    )


def test_connector_merges_markings_for_shared_observable() -> None:
    converter = Converter(
        helper=MagicMock(),
        author_name="ThreatMatch",
        author_description="ThreatMatch Description",
        tlp_level="amber",
        threat_actor_to_intrusion_set=False,
    )
    connector = Connector(helper=None, config=None, converter=converter)
    first = "indicator--11111111-1111-4111-8111-111111111111"
    second = "indicator--22222222-2222-4222-8222-222222222222"
    second_marking = "marking-definition--11111111-1111-4111-8111-111111111111"
    pattern = "[url:value='https://example.org/path']"
    objects = [
        {
            "type": "report",
            "id": "report--11111111-1111-4111-8111-111111111111",
            "object_refs": [first, second],
        },
        {
            "type": "indicator",
            "id": first,
            "pattern_type": "stix",
            "pattern": pattern,
            "object_marking_refs": [converter.tlp_marking.id],
        },
        {
            "type": "indicator",
            "id": second,
            "pattern_type": "stix",
            "pattern": pattern,
            "object_marking_refs": [second_marking],
        },
    ]

    result = connector._add_report_observables(objects)

    assert result[0]["object_refs"] == [first, second, result[-1]["id"]]
    assert len(result) == 4
    assert result[-1]["object_marking_refs"] == [
        converter.tlp_marking.id,
        second_marking,
    ]


def test_connector_reuses_existing_observable() -> None:
    converter = Converter(
        helper=MagicMock(),
        author_name="ThreatMatch",
        author_description="ThreatMatch Description",
        tlp_level="amber",
        threat_actor_to_intrusion_set=False,
    )
    connector = Connector(helper=None, config=None, converter=converter)
    indicator_id = "indicator--11111111-1111-4111-8111-111111111111"
    indicator = {
        "type": "indicator",
        "id": indicator_id,
        "pattern_type": "stix",
        "pattern": "[url:value='https://example.org/path']",
        "object_marking_refs": [converter.tlp_marking.id],
    }
    existing = converter.create_observable(indicator)
    existing["object_marking_refs"] = [
        "marking-definition--11111111-1111-4111-8111-111111111111"
    ]
    objects = [
        {
            "type": "report",
            "id": "report--11111111-1111-4111-8111-111111111111",
            "object_refs": [indicator_id, existing["id"]],
        },
        indicator,
        existing,
    ]

    result = connector._add_report_observables(objects)

    assert len(result) == 3
    assert result[0]["object_refs"] == [indicator_id, existing["id"]]
    assert result[-1]["object_marking_refs"] == [
        "marking-definition--11111111-1111-4111-8111-111111111111",
        converter.tlp_marking.id,
    ]
