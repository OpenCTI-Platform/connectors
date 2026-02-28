import json
from typing import Any

import pytest
from connectors_sdk import ConfigValidationError
from external_import_connector import ConnectorHuntIo
from external_import_connector.constants import ExternalReferences
from external_import_connector.settings import ConfigLoader
from pycti import OpenCTIConnectorHelper

NUMS_OF_CREATED_STIX_OBJECTS = 7
NUMS_OF_CREATED_RELATIONSHIPS = 4
NUMS_OF_CREATED_MARKINGS = 1
NUMS_OF_CREATED_IDENTITIES = 1


def list_has_key_value(dicts, key, value) -> bool:
    return any(isinstance(d, dict) and key in d and d[key] == value for d in dicts)


def find_dict_by_key_value(dicts: list[dict], key: str, value: Any) -> dict | None:
    for d in dicts:
        if isinstance(d, dict) and key in d and d[key] == value:
            return d
    return None


def test_should_run_connector(correct_config, api_response_mock):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ConnectorHuntIo(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    nums_of_entities = (
        (NUMS_OF_CREATED_STIX_OBJECTS * len(api_response_mock))
        + NUMS_OF_CREATED_MARKINGS
        + NUMS_OF_CREATED_IDENTITIES
    )
    nums_of_relationships = NUMS_OF_CREATED_RELATIONSHIPS * len(api_response_mock)

    for item in api_response_mock:
        assert list_has_key_value(sent_bundle["objects"], "value", item.ip)
        assert list_has_key_value(sent_bundle["objects"], "value", item.hostname)
        assert list_has_key_value(sent_bundle["objects"], "dst_port", item.port)
        assert list_has_key_value(sent_bundle["objects"], "name", item.scan_uri)
        assert list_has_key_value(sent_bundle["objects"], "name", item.malware.name)

    assert len(sent_bundle["objects"]) == nums_of_entities + nums_of_relationships


def test_should_fail_if_config_is_invalid():
    with pytest.raises(ConfigValidationError) as e:
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())
        ConnectorHuntIo(config=config, helper=helper)
    assert str(e.value) == "Error validating configuration."


def test_should_warn_if_deprecated_config_is_used(deprecated_config):
    with pytest.deprecated_call():
        config = ConfigLoader()
        helper = OpenCTIConnectorHelper(config=config.to_helper_config())
        ConnectorHuntIo(config=config, helper=helper)


def test_should_send_identity(correct_config, api_response_mock):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ConnectorHuntIo(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    identity = find_dict_by_key_value(sent_bundle["objects"], "type", "identity")

    assert identity

    identity_id = identity["id"]

    count = 0
    for item in sent_bundle["objects"]:
        if item["type"] in ["ipv4-addr", "domain-name", "network-traffic"]:
            count += 1
            assert item["x_opencti_created_by_ref"] == identity_id
        elif item["type"] in [
            "indicator",
            "infrastructure",
            "relationship",
            "malware",
            "observed-data",
        ]:
            count += 1
            assert item["created_by_ref"] == identity_id

    assert count == len(sent_bundle["objects"]) - (
        NUMS_OF_CREATED_MARKINGS + NUMS_OF_CREATED_IDENTITIES
    )


def test_should_add_external_references_to_organization_only(
    correct_config, api_response_mock
):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ConnectorHuntIo(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    identity = find_dict_by_key_value(sent_bundle["objects"], "type", "identity")

    assert (
        identity["external_references"][0]["description"]
        == ExternalReferences.DESCRIPTION
    )
    assert (
        identity["external_references"][0]["source_name"]
        == ExternalReferences.SOURCE_NAME
    )
    assert identity["external_references"][0]["url"] == ExternalReferences.URL

    for item in sent_bundle["objects"]:
        if item["type"] in ["ipv4-addr", "domain-name", "network-traffic"]:
            assert not item.get("x_opencti_external_references", None)
        elif item["type"] in [
            "indicator",
            "infrastructure",
            "relationship",
            "malware",
            "observed-data",
        ]:
            assert not item.get("external_references", None)


def test_should_send_tpl_markings(correct_config, api_response_mock):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ConnectorHuntIo(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    marking_definition = find_dict_by_key_value(
        sent_bundle["objects"], "type", "marking-definition"
    )

    assert marking_definition

    marking_definition_id = marking_definition["id"]

    count = 0
    for item in sent_bundle["objects"]:
        if item["type"] not in ["identity", "marking-definition"]:
            count += 1
            assert marking_definition_id in item["object_marking_refs"]

    assert count == len(sent_bundle["objects"]) - (
        NUMS_OF_CREATED_MARKINGS + NUMS_OF_CREATED_IDENTITIES
    )


def test_should_not_initiate_work_if_payload_is_empty(
    correct_config, empty_api_response_mock
):
    config = ConfigLoader()
    helper = OpenCTIConnectorHelper(config=config.to_helper_config())
    connector = ConnectorHuntIo(config=config, helper=helper)

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    assert sent_bundle == {}
    assert connector.helper.api.work.initiate_work.call_count == 0
    assert connector.helper.api.work.to_processed.call_count == 0
