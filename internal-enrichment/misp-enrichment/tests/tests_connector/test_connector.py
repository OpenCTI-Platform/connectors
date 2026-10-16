from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, MispEnrichmentConnector
from connector.misp_client import MispMatch
from connectors_sdk.exceptions.error import DataRetrievalError
from pycti import OpenCTIConnectorHelper

IPV4_ID = "ipv4-addr--cb7f3d1e-1a2b-5c3d-9e4f-0a1b2c3d4e5f"
FILE_ID = "file--5a4d3c2b-1a0f-5e9d-8c7b-6a5f4e3d2c1b"
INDICATOR_ID = "indicator--0e9f8a7b-6c5d-4e3f-a2b1-c0d9e8f7a6b5"
TLP_GREEN = {"definition_type": "TLP", "definition": "TLP:GREEN"}
TLP_RED = {"definition_type": "TLP", "definition": "TLP:RED"}


def _settings(**misp: Any) -> ConnectorSettings:
    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "misp": {
                        "url": "https://misp.example.com",
                        "api_key": "test-api-key",
                        **misp,
                    },
                }
            )

    return FakeConnectorSettings()


def _match(event_id: str, value: str, org: str = "CIRCL") -> MispMatch:
    return MispMatch(
        event={
            "id": event_id,
            "info": f"Event {event_id}",
            "date": "2026-03-01",
            "threat_level_id": "2",
            "Orgc": {"name": org},
            "Org": {"name": org},
            "Tag": [{"name": f"event-tag-{event_id}"}],
        },
        attributes=[
            {
                "id": f"{event_id}01",
                "event_id": event_id,
                "category": "Network activity",
                "type": "ip-dst",
                "value": value,
                "Tag": [{"name": f"attribute-tag-{event_id}"}],
            }
        ],
    )


@pytest.fixture
def helper() -> MagicMock:
    helper = MagicMock()
    helper.connect_scope = (
        "ipv4-addr,ipv6-addr,domain-name,url,stixfile,email-addr,indicator"
    )
    helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
    helper.stix2_create_bundle.side_effect = lambda objects: objects
    helper.send_stix2_bundle.return_value = ["bundle"]
    return helper


def _connector(helper: MagicMock, monkeypatch, matches: list[MispMatch], **misp: Any):
    monkeypatch.setattr("connector.misp_client.PyMISP", MagicMock())
    connector = MispEnrichmentConnector(config=_settings(**misp), helper=helper)
    connector.client = MagicMock()
    connector.client.search.return_value = matches
    return connector


def _data(
    stix_entity: dict, entity_type: str, marking=TLP_GREEN, playbook=False
) -> dict:
    other = {"id": "identity--0a1b2c3d-4e5f-5a6b-8c7d-9e0f1a2b3c4d", "type": "identity"}
    data = {
        "enrichment_entity": {"entity_type": entity_type, "objectMarking": [marking]},
        "stix_entity": stix_entity,
        "stix_objects": [stix_entity, other],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


def _ipv4() -> dict:
    return {"id": IPV4_ID, "type": "ipv4-addr", "value": "1.2.3.4"}


def _sent_objects(helper: MagicMock) -> list:
    helper.send_stix2_bundle.assert_called_once()
    assert helper.send_stix2_bundle.call_args.kwargs == {
        "cleanup_inconsistent_bundle": True
    }
    return helper.send_stix2_bundle.call_args.args[0]


def _by_type(objects: list, stix_type: str) -> list:
    return [obj for obj in objects if obj["type"] == stix_type]


def test_observable_is_enriched(helper, monkeypatch):
    connector = _connector(
        helper, monkeypatch, [_match("10", "1.2.3.4"), _match("20", "1.2.3.4")]
    )

    connector.process_message(_data(_ipv4(), "IPv4-Addr"))

    connector.client.search.assert_called_once_with(["1.2.3.4"])
    objects = _sent_objects(helper)
    [entity] = [obj for obj in objects if obj["id"] == IPV4_ID]
    assert [ref["url"] for ref in entity["external_references"]] == [
        "https://misp.example.com/events/view/10",
        "https://misp.example.com/events/view/20",
    ]
    assert entity["labels"] == ["attribute-tag-10", "attribute-tag-20"]
    notes = _by_type(objects, "note")
    assert [note["abstract"] for note in notes] == [
        'MISP match: 1.2.3.4 in "Event 10"',
        'MISP match: 1.2.3.4 in "Event 20"',
    ]
    assert _by_type(objects, "report") == []
    assert len(_by_type(objects, "identity")) == 2  # untouched object + MISP author


@pytest.mark.parametrize(
    "attribute_tags, event_tags, expected",
    [
        pytest.param(False, False, None, id="no_labels"),
        pytest.param(False, True, ["event-tag-10"], id="event_tags_only"),
        pytest.param(True, True, ["attribute-tag-10", "event-tag-10"], id="both"),
    ],
)
def test_labels_follow_configuration(
    helper, monkeypatch, attribute_tags, event_tags, expected
):
    connector = _connector(
        helper,
        monkeypatch,
        [_match("10", "1.2.3.4")],
        import_attribute_tags_as_labels=attribute_tags,
        import_associated_events_tags_as_labels=event_tags,
    )

    connector.process_message(_data(_ipv4(), "IPv4-Addr"))

    [entity] = [obj for obj in _sent_objects(helper) if obj["id"] == IPV4_ID]
    assert entity.get("labels") == expected


def test_reports_are_created_when_import_events_is_enabled(helper, monkeypatch):
    connector = _connector(
        helper, monkeypatch, [_match("10", "1.2.3.4")], import_events=True
    )

    connector.process_message(_data(_ipv4(), "IPv4-Addr"))

    [report] = _by_type(_sent_objects(helper), "report")
    assert report["object_refs"] == [IPV4_ID]


def test_filtered_out_events_produce_nothing(helper, monkeypatch):
    connector = _connector(
        helper,
        monkeypatch,
        [_match("10", "1.2.3.4", org="CIRCL"), _match("20", "1.2.3.4", org="Other")],
        event_filter_creator_orgs="CIRCL",
    )

    connector.process_message(_data(_ipv4(), "IPv4-Addr"))

    objects = _sent_objects(helper)
    [entity] = [obj for obj in objects if obj["id"] == IPV4_ID]
    assert [ref["source_name"] for ref in entity["external_references"]] == [
        "MISP Event #10"
    ]
    assert entity["labels"] == ["attribute-tag-10"]
    assert len(_by_type(objects, "note")) == 1


def test_file_looks_up_every_hash(helper, monkeypatch):
    connector = _connector(
        helper, monkeypatch, [_match("10", "d41d8cd98f00b204e9800998ecf8427e")]
    )
    stix_file = {
        "id": FILE_ID,
        "type": "file",
        "hashes": {"MD5": "d41d8cd98f00b204e9800998ecf8427e", "SHA-256": "e3b0c442"},
    }

    connector.process_message(_data(stix_file, "StixFile"))

    connector.client.search.assert_called_once_with(
        ["e3b0c442", "d41d8cd98f00b204e9800998ecf8427e"]
    )
    [note] = _by_type(_sent_objects(helper), "note")
    assert (
        note["abstract"] == 'MISP match: d41d8cd98f00b204e9800998ecf8427e in "Event 10"'
    )


def test_indicator_keeps_the_enrichment_of_every_pattern_value(helper, monkeypatch):
    connector = _connector(
        helper, monkeypatch, [_match("10", "1.2.3.4"), _match("20", "evil.com")]
    )
    indicator = {
        "id": INDICATOR_ID,
        "type": "indicator",
        "pattern_type": "stix",
        "pattern": "[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'evil.com']",
    }

    connector.process_message(_data(indicator, "Indicator"))

    connector.client.search.assert_called_once_with(["1.2.3.4", "evil.com"])
    objects = _sent_objects(helper)
    [entity] = [obj for obj in objects if obj["id"] == INDICATOR_ID]
    assert len(entity["external_references"]) == 2
    assert entity["labels"] == ["attribute-tag-10", "attribute-tag-20"]
    assert [note["abstract"] for note in _by_type(objects, "note")] == [
        'MISP match: 1.2.3.4 in "Event 10"',
        'MISP match: evil.com in "Event 20"',
    ]


def test_non_stix_indicator_is_skipped(helper, monkeypatch):
    connector = _connector(helper, monkeypatch, [])
    indicator = {
        "id": INDICATOR_ID,
        "type": "indicator",
        "pattern_type": "yara",
        "pattern": "rule a { condition: true }",
    }

    message = connector.process_message(_data(indicator, "Indicator"))

    assert message == "No value to look up in MISP, skipping"
    connector.client.search.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize("playbook", [False, True])
def test_no_match(helper, monkeypatch, playbook):
    connector = _connector(helper, monkeypatch, [])
    data = _data(_ipv4(), "IPv4-Addr", playbook=playbook)

    message = connector.process_message(data)

    assert message == "No MISP event found"
    if playbook:
        assert _sent_objects(helper) == data["stix_objects"]
    else:
        helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize("playbook", [False, True])
def test_tlp_above_max_is_not_sent_to_misp(helper, monkeypatch, playbook):
    connector = _connector(helper, monkeypatch, [_match("10", "1.2.3.4")])
    data = _data(_ipv4(), "IPv4-Addr", marking=TLP_RED, playbook=playbook)

    if playbook:
        connector.process_message(data)
        assert _sent_objects(helper) == data["stix_objects"]
    else:
        with pytest.raises(ValueError, match="greater than MAX TLP"):
            connector.process_message(data)
        helper.send_stix2_bundle.assert_not_called()
    connector.client.search.assert_not_called()


def test_out_of_scope_entity_in_playbook_is_sent_back_unchanged(helper, monkeypatch):
    connector = _connector(helper, monkeypatch, [])
    data = _data({"id": "malware--x", "type": "malware"}, "Malware", playbook=True)

    connector.process_message(data)

    assert _sent_objects(helper) == data["stix_objects"]


def test_out_of_scope_entity_raises(helper, monkeypatch):
    connector = _connector(helper, monkeypatch, [])

    with pytest.raises(ValueError, match="Malware is not a supported entity type"):
        connector.process_message(
            _data({"id": "malware--x", "type": "malware"}, "Malware")
        )


def test_misp_error_fails_the_enrichment(helper, monkeypatch):
    connector = _connector(helper, monkeypatch, [])
    connector.client.search.side_effect = DataRetrievalError("MISP down")

    with pytest.raises(DataRetrievalError):
        connector.process_message(_data(_ipv4(), "IPv4-Addr"))
    helper.send_stix2_bundle.assert_not_called()
