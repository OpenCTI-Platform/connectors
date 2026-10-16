# pragma: no cover
# type: ignore
import pytest
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)

ENTITY_ID = "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4"


def _make_data(object_marking=None) -> dict:
    stix_entity = {"type": "ipv4-addr", "id": ENTITY_ID, "value": "1.2.3.4"}
    return {
        "event_type": "INTERNAL_ENRICHMENT",
        "entity_id": ENTITY_ID,
        "entity_type": "IPv4-Addr",
        "enrichment_entity": {
            "entity_type": "IPv4-Addr",
            "objectMarking": object_marking,
        },
        "stix_entity": stix_entity,
        "stix_objects": [dict(stix_entity)],
    }


class TestEnrichmentMessage:
    def test_from_data(self):
        data = _make_data()

        message = EnrichmentMessage.from_data(data, is_playbook=False)

        assert message.entity_id == ENTITY_ID
        assert message.enrichment_entity is data["enrichment_entity"]
        assert message.stix_entity is data["stix_entity"]
        assert message.stix_objects is data["stix_objects"]
        assert message.is_playbook is False

    def test_from_data_raises_on_missing_field(self):
        data = _make_data()
        del data["enrichment_entity"]

        with pytest.raises(KeyError):
            EnrichmentMessage.from_data(data, is_playbook=False)

    def test_is_read_only(self):
        message = EnrichmentMessage.from_data(_make_data(), is_playbook=False)

        with pytest.raises(AttributeError):
            message.is_playbook = True

    def test_entity_type_comes_from_enrichment_entity(self):
        # In a playbook, data["entity_type"] is missing
        data = _make_data()
        del data["entity_type"]

        message = EnrichmentMessage.from_data(data, is_playbook=True)

        assert message.entity_type == "IPv4-Addr"

    def test_tlp_levels(self):
        data = _make_data(
            object_marking=[
                {"definition_type": "TLP", "definition": "TLP:GREEN"},
                {"definition_type": "PAP", "definition": "PAP:RED"},
                {"definition_type": "TLP", "definition": "TLP:AMBER"},
            ]
        )

        message = EnrichmentMessage.from_data(data, is_playbook=False)

        assert message.tlp_levels == ["TLP:GREEN", "TLP:AMBER"]

    @pytest.mark.parametrize("object_marking", [None, []])
    def test_tlp_levels_without_markings(self, object_marking):
        message = EnrichmentMessage.from_data(
            _make_data(object_marking=object_marking), is_playbook=False
        )

        assert message.tlp_levels == []

    def test_entity_copy_is_a_deep_copy(self):
        data = _make_data()
        data["stix_entity"]["labels"] = ["original"]
        message = EnrichmentMessage.from_data(data, is_playbook=False)

        entity = message.entity_copy()
        entity["labels"].append("new")
        entity["x_opencti_score"] = 80

        assert entity == {
            **data["stix_entity"],
            "labels": ["original", "new"],
            "x_opencti_score": 80,
        }
        assert data["stix_entity"]["labels"] == ["original"]
        assert "x_opencti_score" not in data["stix_entity"]
