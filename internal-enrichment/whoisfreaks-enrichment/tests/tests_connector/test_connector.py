"""Tests for the enrichment flow: scope, TLP, playbooks, bundle assembly, errors."""

import copy
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector import ConnectorSettings, WhoisFreaksConnector
from connectors_sdk.exceptions.error import DataRetrievalError
from mock_responses import MOCK_WHOIS_FULL
from whoisfreaks_client.models import WhoisRecord

DOMAIN_ID = "domain-name--cb5a2f2e-6b3a-5d8a-9a8c-5f2a4e1f9c11"
_TLP_ORDER = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


class StubConnectorSettings(ConnectorSettings):
    @classmethod
    def _load_config_dict(cls, _, handler) -> dict[str, Any]:
        return handler(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {"id": "connector-id", "max_tlp": "amber"},
                "whoisfreaks": {"api_key": "test-api-key"},
            }
        )


@pytest.fixture
def connector():
    helper = MagicMock()
    helper.connect_scope = "Domain-Name"  # as pycti keeps it
    helper.check_max_tlp.side_effect = lambda tlp, max_tlp: _TLP_ORDER.index(
        tlp
    ) <= _TLP_ORDER.index(max_tlp)
    helper.stix2_create_bundle.side_effect = lambda objects: {"objects": objects}
    helper.send_stix2_bundle.return_value = ["bundle"]
    connector = WhoisFreaksConnector(config=StubConnectorSettings(), helper=helper)
    connector.client = MagicMock()
    connector.client.lookup.return_value = WhoisRecord.from_response(
        copy.deepcopy(MOCK_WHOIS_FULL)
    )
    return connector


def _message(entity_id=DOMAIN_ID, tlp=None, event_type="enrichment"):
    stix_entity = {
        "type": entity_id.split("--")[0],
        "id": entity_id,
        "value": "example.com",
    }
    markings = [{"definition_type": "TLP", "definition": tlp}] if tlp else []
    data = {
        "entity_id": entity_id,
        "enrichment_entity": {"id": entity_id, "objectMarking": markings},
        "stix_entity": stix_entity,
        "stix_objects": [stix_entity],
    }
    if event_type:
        data["event_type"] = event_type
    return data


def _sent_objects(connector):
    return connector.helper.stix2_create_bundle.call_args.args[0]


def test_enrichment_sends_the_original_bundle_and_the_new_objects(connector):
    data = _message()

    result = connector.process_message(data)

    connector.client.lookup.assert_called_once_with("example.com")
    sent = _sent_objects(connector)
    assert sent[0] is data["stix_entity"]  # the enriched observable comes first
    assert {"identity", "domain-name", "email-addr", "note", "relationship"} <= {
        o["type"] for o in sent
    }
    assert result.startswith("Sent 1 bundle(s)")


def test_mutated_observable_replaces_its_stale_copy_in_the_bundle(connector):
    """The JSON-delivered message deserializes `stix_entity` and `stix_objects`
    separately, so the connector must send the mutated entity, not its stale copy."""
    data = _message()
    stale = dict(data["stix_entity"])  # a separate object with the same id
    data["stix_objects"] = [stale]

    connector.process_message(data)

    sent = _sent_objects(connector)
    observable = next(o for o in sent if o["id"] == data["stix_entity"]["id"])
    assert observable is data["stix_entity"]  # the mutated one, carrying the labels
    assert stale not in sent
    assert "extensions" in observable  # labels / external reference were applied


def test_out_of_scope_playbook_gets_its_bundle_back(connector):
    data = _message("ipv4-addr--8b9d3c1e-6f2a-5b4c-9d8e-7f6a5b4c3d2e", event_type=None)

    connector.process_message(data)

    connector.client.lookup.assert_not_called()
    assert _sent_objects(connector) == data["stix_objects"]


def test_out_of_scope_manual_enrichment_does_nothing(connector):
    connector.process_message(
        _message("ipv4-addr--8b9d3c1e-6f2a-5b4c-9d8e-7f6a5b4c3d2e")
    )

    connector.client.lookup.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()


def test_tlp_above_the_maximum_is_never_sent_to_the_api(connector):
    """An expected case: the work ends normally with a message, not an error."""
    result = connector.process_message(_message(tlp="TLP:RED"))

    assert "above the maximum TLP:AMBER" in result
    connector.client.lookup.assert_not_called()
    connector.helper.check_max_tlp.assert_called_with("TLP:RED", "TLP:AMBER")
    connector.helper.send_stix2_bundle.assert_not_called()


def test_tlp_above_the_maximum_in_a_playbook_returns_the_bundle(connector):
    data = _message(tlp="TLP:RED", event_type=None)

    connector.process_message(data)

    connector.client.lookup.assert_not_called()
    assert _sent_objects(connector) == data["stix_objects"]


def test_tlp_within_the_maximum_is_enriched(connector):
    connector.process_message(_message(tlp="TLP:GREEN"))

    connector.client.lookup.assert_called_once()


def test_playbook_error_returns_the_bundle_and_still_fails(connector):
    connector.client.lookup.side_effect = DataRetrievalError("API down")
    data = _message(event_type=None)

    with pytest.raises(DataRetrievalError):
        connector.process_message(data)

    assert _sent_objects(connector) == data["stix_objects"]


def test_manual_enrichment_error_fails_without_sending(connector):
    connector.client.lookup.side_effect = DataRetrievalError("API down")

    with pytest.raises(DataRetrievalError):
        connector.process_message(_message())

    connector.helper.send_stix2_bundle.assert_not_called()
