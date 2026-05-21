from typing import Any
from unittest.mock import MagicMock

from pure_signal_scout.connector import PureSignalScoutConnector
from pure_signal_scout.settings import ConnectorSettings


class StubConnectorSettings(ConnectorSettings):
    """
    Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
    It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
    """

    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {
                    "url": "http://localhost:8080",
                    "token": "test-token",
                },
                "connector": {},
                "pure_signal_scout": {
                    "api_url": "https://taxii.cymru.com/api/scout",
                    "api_token": "SecretStr",
                    "max_tlp": "TLP:AMBER",
                },
            }
        )


class FakeHelper:
    def __init__(self, max_tlp_ok: bool = True):
        self.connector_logger = MagicMock()
        self.connect_id = "connector-id"
        self.connect_name = "Test Connector"
        self.connect_scope = "IPv4-Addr"
        self._max_tlp_ok = max_tlp_ok
        self.stix2_create_bundle = MagicMock(return_value="serialized-bundle")
        self.send_stix2_bundle = MagicMock()

    def check_max_tlp(self, tlp, max_tlp):
        return self._max_tlp_ok

    def listen(self, callback):
        self._callback = callback


def _find_by_id(objects, object_id):
    for obj in objects:
        if obj.get("id") == object_id:
            return obj
    return None


def test_process_stix_data_filters_and_rewrites():
    # Given
    settings = StubConnectorSettings()
    helper = FakeHelper()
    connector = PureSignalScoutConnector(config=settings, helper=helper)

    data = {
        "objects": [
            {"type": "network-traffic", "id": "network-traffic--1"},
            {"type": "domain-name", "id": "domain-name--bad", "value": "bad_domain"},
            {
                "type": "domain-name",
                "id": "domain-name--good",
                "value": "example.com",
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "source_ref": "indicator--1",
                "target_ref": "ipv4-addr--1",
                "relationship_type": "indicates",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "source_ref": "domain-name--bad",
                "target_ref": "indicator--1",
                "relationship_type": "related-to",
            },
            {
                "type": "relationship",
                "id": "relationship--3",
                "source_ref": "network-traffic--1",
                "target_ref": "ipv4-addr--1",
                "relationship_type": "uses",
            },
            {
                "type": "relationship",
                "id": "relationship--4",
                "source_ref": "domain-name--good",
                "target_ref": "domain-name--good",
                "relationship_type": "uses",
            },
            {
                "type": "relationship",
                "id": "relationship--5",
                "source_ref": "ipv4-addr--1",
                "target_ref": "identity--1",
                "relationship_type": "owned-by",
            },
            {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.1.1.1"},
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '1.1.1.1']",
                "name": "test-indicator",
            },
        ]
    }

    # When
    filtered = connector.process_stix_data(data)
    filtered_ids = {obj["id"] for obj in filtered}

    # Then
    assert "network-traffic--1" not in filtered_ids
    assert "domain-name--bad" not in filtered_ids
    assert "relationship--2" not in filtered_ids
    assert "relationship--3" not in filtered_ids
    assert "relationship--4" not in filtered_ids
    assert "relationship--1" in filtered_ids
    assert "relationship--5" in filtered_ids

    relationship_1 = _find_by_id(filtered, "relationship--1")
    assert relationship_1["relationship_type"] == "based-on"

    relationship_5 = _find_by_id(filtered, "relationship--5")
    assert relationship_5["relationship_type"] == "related-to"

    author_id = connector.team_cymru_identity["id"]
    for obj in filtered:
        if obj.get("id") == author_id:
            continue
        assert obj["created_by_ref"] == author_id


def test_process_message_unsupported_type_returns_message():
    # Given
    settings = StubConnectorSettings()
    helper = FakeHelper()
    connector = PureSignalScoutConnector(config=settings, helper=helper)
    connector.client.get_entity = MagicMock()

    # When
    result = connector.process_message(
        {
            "enrichment_entity": {
                "standard_id": "observable--1",
                "entity_type": "File",
                "value": "sample.exe",
                "objectMarking": [],
            }
        }
    )

    # Then
    assert result == "Unsupported observable type"
    connector.client.get_entity.assert_not_called()


def test_process_message_sends_bundle_when_data_is_available():
    # Given
    settings = StubConnectorSettings()
    helper = FakeHelper()
    connector = PureSignalScoutConnector(config=settings, helper=helper)
    connector.client.get_entity = MagicMock(
        return_value={"objects": [{"type": "indicator", "id": "indicator--1"}]}
    )
    connector.process_stix_data = MagicMock(
        return_value=[{"type": "indicator", "id": "indicator--1"}]
    )

    # When
    result = connector.process_message(
        {
            "enrichment_entity": {
                "standard_id": "observable--2",
                "entity_type": "IPv4-Addr",
                "value": "1.1.1.1",
                "objectMarking": [],
            }
        }
    )

    # Then
    assert result == "Data fetched successfully and ingestion process has started"
    helper.stix2_create_bundle.assert_called_once_with(
        [{"type": "indicator", "id": "indicator--1"}]
    )
    helper.send_stix2_bundle.assert_called_once()
    send_kwargs = helper.send_stix2_bundle.call_args.kwargs
    assert send_kwargs["bundle"] == "serialized-bundle"
    assert send_kwargs["update"] is True
    assert send_kwargs["cleanup_inconsistent_bundle"] is True
