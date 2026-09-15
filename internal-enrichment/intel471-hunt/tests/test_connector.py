"""Message-handling tests: TLP gating, playbook passthrough, marking propagation."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from pycti import OpenCTIConnectorHelper
from src.connector import HunterEnrichmentConnector

TLP_RED = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"


@pytest.fixture
def connector(monkeypatch) -> HunterEnrichmentConnector:
    """A connector with the network client and cache stubbed out."""
    conn = HunterEnrichmentConnector.__new__(HunterEnrichmentConnector)
    conn.config = MagicMock()
    conn.config.hunter.max_tlp = "TLP:AMBER"
    conn.helper = MagicMock()
    conn.helper.send_stix2_bundle.return_value = ["bundle"]
    # Use the real serializer so bundle construction is genuinely exercised.
    conn.helper.stix2_create_bundle = OpenCTIConnectorHelper.stix2_create_bundle
    conn.client = MagicMock()
    conn.cache = MagicMock()
    conn.cache.is_fresh.return_value = False
    conn.author = MagicMock(id="identity--author")
    conn.hunter_ui_base_url = None
    return conn


def _message(**overrides: Any) -> dict[str, Any]:
    data = {
        "stix_objects": [{"id": "indicator--original", "type": "indicator"}],
        "stix_entity": {"id": "intrusion-set--x"},
        "enrichment_entity": {
            "entity_type": "Intrusion-Set",
            "name": "TeamPCP",
            "standard_id": "intrusion-set--x",
        },
        "event_type": "",  # empty == playbook run
    }
    data.update(overrides)
    return data


def test_out_of_scope_entity_returns_original_bundle(connector):
    data = _message(enrichment_entity={"entity_type": "Artifact", "name": "x"})

    result = connector.process_message(data)

    assert "not in scope" in result
    # The original bundle is handed back so the playbook can continue.
    connector.helper.send_stix2_bundle.assert_called_once()


def test_manual_enrichment_does_not_resend_original_bundle(connector):
    data = _message(
        enrichment_entity={"entity_type": "Artifact", "name": "x"},
        event_type="update",  # manual enrichment, not a playbook step
    )

    connector.process_message(data)

    connector.helper.send_stix2_bundle.assert_not_called()


def test_tlp_above_max_is_refused(connector):
    data = _message(
        enrichment_entity={
            "entity_type": "Intrusion-Set",
            "name": "TeamPCP",
            "standard_id": "intrusion-set--x",
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
        }
    )

    result = connector.process_message(data)

    assert "Error" in result and "TLP" in result
    connector.client.query.assert_not_called()


def test_tlp_within_max_is_processed(connector):
    connector.client.query.return_value = []
    data = _message(
        enrichment_entity={
            "entity_type": "Intrusion-Set",
            "name": "TeamPCP",
            "standard_id": "intrusion-set--x",
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:GREEN"}],
        }
    )

    result = connector.process_message(data)

    assert "no hunts" in result
    connector.client.query.assert_called()


def test_no_hunts_returns_original_bundle(connector):
    connector.client.query.return_value = []

    result = connector.process_message(_message())

    assert "no hunts" in result
    connector.helper.send_stix2_bundle.assert_called_once()


def test_missing_stix_objects_key_is_tolerated(connector):
    connector.client.query.return_value = []
    data = _message()
    del data["stix_objects"]

    result = connector.process_message(data)

    assert "no hunts" in result


def test_entity_markings_are_propagated(connector, response_payload, monkeypatch):
    connector.client.query.return_value = response_payload["results"][:1]
    captured: dict[str, Any] = {}

    from src import stix_builder

    original = stix_builder.build_bundle

    def spy(*args, **kwargs):
        captured["markings"] = kwargs.get("markings")
        return original(*args, **kwargs)

    monkeypatch.setattr(stix_builder, "build_bundle", spy)

    connector.process_message(
        _message(
            stix_entity={"id": "intrusion-set--x", "object_marking_refs": [TLP_RED]}
        )
    )

    assert captured["markings"] == [TLP_RED]
