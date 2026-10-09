from unittest.mock import MagicMock, patch

import pytest
from lib import DnsTwistConnector

DOMAIN_MARKED_RED = {
    "entity_type": "Domain-Name",
    "value": "example.com",
    "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
}


def _make_connector(max_tlp: str) -> DnsTwistConnector:
    """Build a connector without running `__init__`, with a mocked helper and config."""
    connector = object.__new__(DnsTwistConnector)
    connector.helper = MagicMock()
    connector.helper.api.stix_cyber_observable.read.return_value = DOMAIN_MARKED_RED
    connector.config = MagicMock()
    connector.config.connector.max_tlp = max_tlp
    return connector


def test_process_message_should_skip_entity_above_max_tlp():
    # Given: A connector capped at TLP:AMBER and a domain marked TLP:RED
    connector = _make_connector("TLP:AMBER")

    # When: The enrichment message is processed
    with patch.object(DnsTwistConnector, "dns_twist_enrichment") as enrichment:
        result = connector.process_message({"entity_id": "domain-name--1"})

    # Then: DNSTwist is never run
    enrichment.assert_not_called()
    assert result == "Skipping enrichment: entity TLP is above the max TLP"


@pytest.mark.parametrize("object_marking", [[], DOMAIN_MARKED_RED["objectMarking"]])
def test_process_message_should_enrich_entity_within_max_tlp(object_marking):
    # Given: A connector capped at TLP:RED and a domain unmarked or marked TLP:RED
    connector = _make_connector("TLP:RED")
    connector.helper.api.stix_cyber_observable.read.return_value = {
        **DOMAIN_MARKED_RED,
        "objectMarking": object_marking,
    }

    # When: The enrichment message is processed
    with patch.object(
        DnsTwistConnector, "dns_twist_enrichment", return_value="Success"
    ) as enrichment:
        result = connector.process_message({"entity_id": "domain-name--1"})

    # Then: DNSTwist is run
    enrichment.assert_called_once()
    assert result == "Success"
