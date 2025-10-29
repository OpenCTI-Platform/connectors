import json
from typing import Any

import pytest
from connectors_sdk import ConfigValidationError
from external_import_connector import ConnectorHuntIo


def has_key_value(dicts, key, value) -> bool:
    return any(isinstance(d, dict) and key in d and d[key] == value for d in dicts)


def find_dict_by_key_value(dicts: list[dict], key: str, value: Any) -> dict | None:
    for d in dicts:
        if isinstance(d, dict) and key in d and d[key] == value:
            return d
    return None


def test_should_run_connector(correct_config, api_response_mock):
    connector = ConnectorHuntIo()

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    nums_of_entities = 7 * len(api_response_mock) + 1  # Entities + Identity
    nums_of_relationships = 4 * len(api_response_mock)

    for item in api_response_mock:
        assert has_key_value(sent_bundle["objects"], "value", item.ip)
        assert has_key_value(sent_bundle["objects"], "value", item.hostname)
        assert has_key_value(sent_bundle["objects"], "dst_port", item.port)
        assert has_key_value(sent_bundle["objects"], "name", item.scan_uri)
        assert has_key_value(sent_bundle["objects"], "name", item.malware.name)

    assert len(sent_bundle["objects"]) == nums_of_entities + nums_of_relationships


def test_should_fail_if_config_is_invalid():
    with pytest.raises(ConfigValidationError) as e:
        ConnectorHuntIo()
    assert str(e.value) == "Error validating configuration."


def test_should_warn_if_deprecated_config_is_used(deprecated_config):
    with pytest.deprecated_call():
        ConnectorHuntIo()


def test_should_send_identity(correct_config, api_response_mock):
    connector = ConnectorHuntIo()

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

    assert count == len(sent_bundle["objects"]) - 1
