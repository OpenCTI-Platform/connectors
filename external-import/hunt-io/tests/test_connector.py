import json

import pytest
from connectors_sdk import ConfigValidationError
from external_import_connector import ConnectorHuntIo


def test_should_run_connector(correct_config, api_response_mock):
    connector = ConnectorHuntIo()

    sent_bundle = {}

    def capture_sent_bundle(bundle: str, **_):
        nonlocal sent_bundle
        sent_bundle = json.loads(bundle)

    def has_key_value(dicts, key, value) -> bool:
        return any(isinstance(d, dict) and key in d and d[key] == value for d in dicts)

    connector.helper.send_stix2_bundle = capture_sent_bundle
    connector.process_message()

    nums_of_relationships = 4

    for item in api_response_mock:
        assert has_key_value(sent_bundle["objects"], "value", item.ip)
        assert has_key_value(sent_bundle["objects"], "value", item.hostname)
        assert has_key_value(sent_bundle["objects"], "dst_port", item.port)
        assert has_key_value(sent_bundle["objects"], "name", item.scan_uri)
        assert has_key_value(sent_bundle["objects"], "name", item.malware.name)

    assert len(sent_bundle["objects"]) == (7 + nums_of_relationships) * len(
        api_response_mock
    )


def test_should_fail_if_config_is_invalid():
    with pytest.raises(ConfigValidationError) as e:
        ConnectorHuntIo()
    assert str(e.value) == "Error validating configuration."


def test_should_warn_if_deprecated_config_is_used(deprecated_config):
    with pytest.deprecated_call():
        ConnectorHuntIo()
