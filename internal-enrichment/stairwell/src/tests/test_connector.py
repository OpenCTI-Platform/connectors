from unittest.mock import MagicMock

import pytest
from connector.connector import StairwellConnector
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


@pytest.fixture
def env(monkeypatch):
    for key, value in {
        "OPENCTI_URL": "http://opencti:8080",
        "OPENCTI_TOKEN": "token",
        "CONNECTOR_ID": "11111111-1111-4111-8111-111111111111",
        "CONNECTOR_SCOPE": "StixFile,Domain-Name,IPv4-Addr,IPv6-Addr,Autonomous-System",
        "STAIRWELL_API_TOKEN": "sw-token",
    }.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def _connector():
    helper = MagicMock()
    # The real static check, so a wrong max-TLP format fails as it would live.
    helper.check_max_tlp = OpenCTIConnectorHelper.check_max_tlp
    connector = StairwellConnector(config=ConnectorSettings(), helper=helper)
    connector.client._session = MagicMock()
    return connector, helper


def _message(*tlps):
    observable = {
        "id": "x",
        "standard_id": "file--1",
        "entity_type": "StixFile",
        "hashes": [{"algorithm": "SHA-256", "hash": "a" * 64}],
        "objectMarking": [
            {"definition_type": "TLP", "definition": tlp} for tlp in tlps
        ],
    }
    # Shape of an enrichment message from pycti: the entity is included.
    data = {
        "entity_id": "x",
        "stix_entity": {"id": "file--1"},
        "enrichment_entity": observable,
    }
    return data, observable


def test_defaults_are_amber_max_tlp_and_no_sightings(env):
    settings = ConnectorSettings()
    assert settings.stairwell.max_tlp_level == "amber"
    assert settings.stairwell.sightings_limit == 0
    connector, _ = _connector()
    assert connector.dispatcher.max_tlp == "TLP:AMBER"
    assert connector.dispatcher.file.sightings_limit == 0


@pytest.mark.parametrize(
    "configured", ["clear", "white", "green", "amber", "amber+strict", "red"]
)
def test_every_configurable_max_tlp_works_with_pycti(env, configured):
    env.setenv("STAIRWELL_MAX_TLP_LEVEL", configured)
    connector, helper = _connector()
    data, _ = _message("TLP:CLEAR")
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    assert connector.process_message(data) == "enriched"


def test_observable_above_max_tlp_is_never_sent_to_stairwell(env):
    connector, helper = _connector()
    data, _ = _message("TLP:GREEN", "TLP:RED")
    with pytest.raises(ValueError, match="max TLP"):
        connector.process_message(data)
    connector.client._session.get.assert_not_called()
    helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize(
    "configured, observable_tlp, allowed",
    [
        ("green", "TLP:AMBER", False),
        ("green", "TLP:GREEN", True),
        ("red", "TLP:RED", True),
        ("amber+strict", "TLP:AMBER+STRICT", True),
        ("amber", "TLP:AMBER+STRICT", False),
    ],
)
def test_configured_max_tlp_reaches_the_gate(env, configured, observable_tlp, allowed):
    env.setenv("STAIRWELL_MAX_TLP_LEVEL", configured)
    connector, helper = _connector()
    data, _ = _message(observable_tlp)
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    if allowed:
        assert connector.process_message(data) == "enriched"
    else:
        with pytest.raises(ValueError, match="max TLP"):
            connector.process_message(data)
        connector.dispatcher.file.enrich.assert_not_called()


def test_uses_the_entity_pycti_already_resolved(env):
    connector, helper = _connector()
    data, _ = _message("TLP:GREEN")
    connector.dispatcher.file.enrich = MagicMock(return_value="enriched")
    assert connector.process_message(data) == "enriched"
    connector.dispatcher.file.enrich.assert_called_once_with(data["enrichment_entity"])
    helper.api.stix_cyber_observable.read.assert_not_called()


def _out_of_scope_message(playbook):
    entity = {"id": "x", "entity_type": "Report", "objectMarking": []}
    data = {
        "entity_id": "report--1",
        "stix_entity": {"id": "report--1", "type": "report"},
        "enrichment_entity": entity,
        "stix_objects": [{"id": "report--1", "type": "report"}],
    }
    if not playbook:
        data["event_type"] = "INTERNAL_ENRICHMENT"
    return data


def test_playbook_entity_out_of_scope_gets_its_bundle_back_unchanged(env):
    connector, helper = _connector()
    helper.stix2_create_bundle.side_effect = lambda objs: {"objects": objs}
    connector.process_message(_out_of_scope_message(playbook=True))
    helper.stix2_create_bundle.assert_called_once_with(
        [{"id": "report--1", "type": "report"}]
    )
    helper.send_stix2_bundle.assert_called_once_with(
        {"objects": [{"id": "report--1", "type": "report"}]}
    )
    connector.client._session.get.assert_not_called()


def test_manual_enrichment_out_of_scope_is_an_error(env):
    connector, helper = _connector()
    with pytest.raises(ValueError, match="not a supported entity type"):
        connector.process_message(_out_of_scope_message(playbook=False))
    helper.send_stix2_bundle.assert_not_called()
