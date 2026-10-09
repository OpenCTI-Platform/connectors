from unittest.mock import MagicMock, patch

import pytest
from connector import JoeSandboxConnector

ARTIFACT_MARKED_RED = {
    "entity_type": "Artifact",
    "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
}


def _make_connector(max_tlp: str) -> JoeSandboxConnector:
    """Build a connector without running `__init__`, with a mocked helper and config."""
    connector = object.__new__(JoeSandboxConnector)
    connector.helper = MagicMock()
    connector.config = MagicMock()
    connector.config.connector.max_tlp = max_tlp
    return connector


def test_process_message_should_skip_entity_above_max_tlp():
    # Given: A connector capped at TLP:AMBER and an artifact marked TLP:RED
    connector = _make_connector("TLP:AMBER")
    data = {
        "event_type": "INTERNAL_ENRICHMENT",
        "enrichment_entity": ARTIFACT_MARKED_RED,
        "stix_objects": [],
    }

    # When: The enrichment message is processed
    with patch.object(JoeSandboxConnector, "_process_observable") as process:
        result = connector._process_message(data)

    # Then: Nothing is submitted to Joe Sandbox and no bundle is sent
    process.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    assert result == "Skipping enrichment: entity TLP is above the max TLP"


def test_process_message_should_send_bundle_back_when_skipping_in_playbook():
    # Given: A playbook message (no event_type) for an artifact above the max TLP
    connector = _make_connector("TLP:AMBER")
    stix_objects = [{"id": "artifact--1", "type": "artifact"}]
    data = {"enrichment_entity": ARTIFACT_MARKED_RED, "stix_objects": stix_objects}

    # When: The enrichment message is processed
    with patch.object(JoeSandboxConnector, "_process_observable") as process:
        connector._process_message(data)

    # Then: The original objects are sent back unchanged so the playbook goes on
    process.assert_not_called()
    connector.helper.stix2_create_bundle.assert_called_once_with(stix_objects)
    connector.helper.send_stix2_bundle.assert_called_once()


@pytest.mark.parametrize("object_marking", [[], ARTIFACT_MARKED_RED["objectMarking"]])
def test_process_message_should_enrich_entity_within_max_tlp(object_marking):
    # Given: A connector capped at TLP:RED and an artifact unmarked or marked TLP:RED
    connector = _make_connector("TLP:RED")
    observable = {**ARTIFACT_MARKED_RED, "objectMarking": object_marking}
    data = {"enrichment_entity": observable, "stix_objects": []}

    # When: The enrichment message is processed
    with patch.object(
        JoeSandboxConnector, "_process_observable", return_value="Done"
    ) as process:
        result = connector._process_message(data)

    # Then: The observable is submitted to Joe Sandbox
    process.assert_called_once_with(observable)
    assert result == "Done"
