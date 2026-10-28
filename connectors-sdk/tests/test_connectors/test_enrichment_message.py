# pragma: no cover
# type: ignore
import pytest
from connectors_sdk.connectors.internal_enrichment.enrichment_message import (
    EnrichmentMessage,
)
from pydantic import ValidationError

ENTITY_ID = "ipv4-addr--0198f97b-e65d-5025-87e5-58bc39d4bdb4"
OCTI_ID = "0b7e1c5a-3f2d-4e6a-9b8c-1d2e3f4a5b6c"


def _make_data(object_marking=None) -> dict:
    stix_entity = {"type": "ipv4-addr", "id": ENTITY_ID, "value": "1.2.3.4"}
    return {
        "event_type": "INTERNAL_ENRICHMENT",
        "entity_id": ENTITY_ID,
        "entity_type": "IPv4-Addr",
        "enrichment_entity": {
            "id": OCTI_ID,
            "entity_type": "IPv4-Addr",
            "objectMarking": object_marking,
        },
        "stix_entity": stix_entity,
        "stix_objects": [dict(stix_entity)],
        "from_playbook": False,
    }


class TestEnrichmentMessage:
    def test_model_validate(self):
        data = _make_data()

        message = EnrichmentMessage.model_validate(data)

        assert message.enrichment_entity.id == OCTI_ID
        assert message.enrichment_entity.entity_type == "IPv4-Addr"
        assert message.stix_entity.id == ENTITY_ID
        assert message.stix_entity.type == "ipv4-addr"
        assert message.stix_entity.model_dump() == data["stix_entity"]
        assert message.stix_objects == data["stix_objects"]
        assert message.from_playbook is False

    def test_validation_copies_the_objects_received(self):
        data = _make_data()

        message = EnrichmentMessage.model_validate(data)

        assert message.stix_entity is not data["stix_entity"]
        assert message.stix_objects is not data["stix_objects"]

    @pytest.mark.parametrize(
        "missing_field", ["enrichment_entity", "stix_entity", "stix_objects"]
    )
    def test_raises_on_missing_field(self, missing_field):
        data = _make_data()
        del data[missing_field]

        with pytest.raises(ValidationError):
            EnrichmentMessage.model_validate(data)

    @pytest.mark.parametrize(
        "entity, missing_key",
        [
            ("enrichment_entity", "id"),
            ("enrichment_entity", "entity_type"),
            ("stix_entity", "id"),
            ("stix_entity", "type"),
        ],
    )
    def test_raises_when_the_entity_misses_an_id_or_a_type(self, entity, missing_key):
        data = _make_data()
        del data[entity][missing_key]

        with pytest.raises(ValidationError):
            EnrichmentMessage.model_validate(data)

    def test_ignores_unknown_fields(self):
        data = {**_make_data(), "configuration": {"key": "value"}}

        message = EnrichmentMessage.model_validate(data)

        assert not hasattr(message, "configuration")

    def test_is_read_only(self):
        message = EnrichmentMessage.model_validate(_make_data())

        with pytest.raises(ValidationError):
            message.from_playbook = True

    def test_ignores_the_ids_and_types_at_the_top_level_of_the_message(self):
        data = {**_make_data(), "entity_id": "other--id", "entity_type": "Other"}

        message = EnrichmentMessage.model_validate(data)

        assert message.enrichment_entity.entity_type == "IPv4-Addr"
        assert message.stix_entity.id == ENTITY_ID

    def test_tlp_levels(self):
        data = _make_data(
            object_marking=[
                {"definition_type": "TLP", "definition": "TLP:GREEN"},
                {"definition_type": "PAP", "definition": "PAP:RED"},
                {"definition_type": "TLP", "definition": "TLP:AMBER"},
            ]
        )

        message = EnrichmentMessage.model_validate(data)

        assert message.enrichment_entity.tlp_levels == ["TLP:GREEN", "TLP:AMBER"]

    @pytest.mark.parametrize("object_marking", [None, []])
    def test_tlp_levels_without_markings(self, object_marking):
        message = EnrichmentMessage.model_validate(
            _make_data(object_marking=object_marking)
        )

        assert message.enrichment_entity.tlp_levels == []

    @pytest.mark.parametrize("from_playbook", [False, True])
    def test_to_log_metadata(self, from_playbook):
        message = EnrichmentMessage.model_validate(
            {**_make_data(), "from_playbook": from_playbook}
        )

        assert message.to_log_metadata() == {
            "octi_id": OCTI_ID,
            "octi_entity_type": "IPv4-Addr",
            "from_playbook": from_playbook,
        }

    def test_undeclared_fields_can_be_read_as_attributes(self):
        data = _make_data()
        data["enrichment_entity"]["parent_types"] = ["Stix-Cyber-Observable"]

        message = EnrichmentMessage.model_validate(data)

        assert message.stix_entity.value == "1.2.3.4"
        assert message.enrichment_entity.parent_types == ["Stix-Cyber-Observable"]
