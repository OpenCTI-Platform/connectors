# pragma: no cover
# type: ignore
from connectors_sdk.connectors.internal_enrichment.enriched_entity import (
    OPENCTI_SCO_EXTENSION_ID,
    OPENCTI_SDO_EXTENSION_ID,
    EnrichedEntity,
    merge_enriched_entity,
    replace_refs,
)

ENTITY_ID = "ipv4-addr--00010af8-5d2e-5198-a256-8fdf39bc3e41"
REF_A = {"source_name": "a", "url": "https://a.example"}
REF_B = {"source_name": "b", "url": "https://b.example"}


def _manual_entity() -> dict:
    """An IPv4 as pycti exports it in manual/auto mode: OpenCTI attributes at the top level."""
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": ENTITY_ID,
        "value": "1.2.3.4",
        "x_opencti_score": 10,
        "x_opencti_labels": ["existing"],
        "x_opencti_external_references": [REF_A],
        "x_opencti_created_by_ref": "identity--original-author",
        "object_marking_refs": ["marking-definition--original"],
    }


def _playbook_entity() -> dict:
    """The same IPv4 as the platform sends it to a playbook: attributes in the extension."""
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": ENTITY_ID,
        "value": "1.2.3.4",
        "object_marking_refs": ["marking-definition--original"],
        "extensions": {
            OPENCTI_SCO_EXTENSION_ID: {
                "extension_type": "property-extension",
                "score": 10,
                "labels": ["existing"],
                "external_references": [REF_A],
                "created_by_ref": "identity--original-author",
            }
        },
    }


def _sdk_enriched(**fields) -> dict:
    """An enriched IPv4 as an SDK observable model serializes it."""
    return {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": ENTITY_ID,
        "value": "1.2.3.4",
        "defanged": False,
        "x_opencti_created_by_ref": "identity--source-author",
        **fields,
    }


class TestEnrichedEntity:
    def test_enriched_entity_should_hold_the_object(self):
        enriched = EnrichedEntity({"id": ENTITY_ID})

        assert enriched.entity == {"id": ENTITY_ID}


class TestMergeManualEntity:
    def test_should_add_labels_external_references_and_markings_at_the_top_level(self):
        entity = _manual_entity()

        merge_enriched_entity(
            entity,
            _sdk_enriched(
                x_opencti_labels=["existing", "new"],
                x_opencti_external_references=[REF_B],
                object_marking_refs=["marking-definition--source"],
            ),
        )

        assert entity["x_opencti_labels"] == ["existing", "new"]
        assert entity["x_opencti_external_references"] == [REF_A, REF_B]
        assert entity["object_marking_refs"] == [
            "marking-definition--original",
            "marking-definition--source",
        ]
        assert "extensions" not in entity

    def test_should_replace_the_score_and_the_description(self):
        entity = _manual_entity()
        entity["x_opencti_description"] = "old"

        merge_enriched_entity(
            entity, _sdk_enriched(x_opencti_score=80, x_opencti_description="new")
        )

        assert entity["x_opencti_score"] == 80
        assert entity["x_opencti_description"] == "new"

    def test_should_keep_the_identity_and_the_author_of_the_entity(self):
        entity = _manual_entity()

        merge_enriched_entity(entity, _sdk_enriched(id="ipv4-addr--other"))

        assert entity["id"] == ENTITY_ID
        assert entity["x_opencti_created_by_ref"] == "identity--original-author"

    def test_should_keep_attributes_the_enriched_entity_does_not_provide(self):
        entity = _manual_entity()

        merge_enriched_entity(entity, _sdk_enriched(x_opencti_labels=[]))

        assert entity == {**_manual_entity(), "defanged": False}


class TestMergePlaybookEntity:
    def test_should_write_sdk_top_level_attributes_into_the_extension(self):
        entity = _playbook_entity()

        merge_enriched_entity(
            entity,
            _sdk_enriched(
                x_opencti_score=80,
                x_opencti_labels=["new"],
                x_opencti_external_references=[REF_B],
            ),
        )

        extension = entity["extensions"][OPENCTI_SCO_EXTENSION_ID]
        assert extension["score"] == 80
        assert extension["labels"] == ["existing", "new"]
        assert extension["external_references"] == [REF_A, REF_B]
        assert "x_opencti_labels" not in entity
        assert "x_opencti_score" not in entity

    def test_should_write_a_missing_attribute_into_the_extension(self):
        entity = _playbook_entity()

        merge_enriched_entity(entity, _sdk_enriched(x_opencti_description="new"))

        assert entity["extensions"][OPENCTI_SCO_EXTENSION_ID]["description"] == "new"
        assert "x_opencti_description" not in entity

    def test_should_keep_top_level_markings_when_the_entity_has_an_extension(self):
        entity = _playbook_entity()
        del entity["object_marking_refs"]

        merge_enriched_entity(
            entity, _sdk_enriched(object_marking_refs=["marking-definition--source"])
        )

        assert entity["object_marking_refs"] == ["marking-definition--source"]

    def test_should_read_an_enriched_entity_given_in_the_extension_shape(self):
        entity = _manual_entity()
        enriched = _playbook_entity()
        enriched["extensions"][OPENCTI_SCO_EXTENSION_ID]["labels"] = ["new"]
        enriched["extensions"][OPENCTI_SCO_EXTENSION_ID]["score"] = 70

        merge_enriched_entity(entity, enriched)

        assert entity["x_opencti_labels"] == ["existing", "new"]
        assert entity["x_opencti_score"] == 70


class TestMergeLocations:
    def test_should_update_every_location_holding_the_attribute(self):
        entity = {
            "type": "indicator",
            "id": "indicator--1",
            "labels": ["top"],
            "extensions": {OPENCTI_SDO_EXTENSION_ID: {"labels": ["extension"]}},
        }

        merge_enriched_entity(entity, {"id": "indicator--1", "labels": ["new"]})

        assert entity["labels"] == ["top", "new"]
        assert entity["extensions"][OPENCTI_SDO_EXTENSION_ID]["labels"] == [
            "extension",
            "new",
        ]

    def test_should_write_where_the_enriched_entity_holds_it_without_extension(
        self,
    ):
        entity = {"type": "indicator", "id": "indicator--1", "description": None}

        merge_enriched_entity(
            entity, {"id": "indicator--1", "labels": ["new"], "description": "d"}
        )

        assert entity["labels"] == ["new"]
        assert entity["description"] == "d"

    def test_should_write_at_the_top_level_when_only_the_enriched_entity_has_one(
        self,
    ):
        entity = {"type": "ipv4-addr", "id": ENTITY_ID}
        enriched = {
            "id": ENTITY_ID,
            "extensions": {OPENCTI_SCO_EXTENSION_ID: {"labels": ["new"]}},
        }

        merge_enriched_entity(entity, enriched)

        assert entity == {
            "type": "ipv4-addr",
            "id": ENTITY_ID,
            "x_opencti_labels": ["new"],
        }


class TestMergeOtherProperties:
    def test_should_add_missing_hashes_without_replacing_existing_ones(self):
        entity = {"type": "file", "id": "file--1", "hashes": {"MD5": "original"}}

        merge_enriched_entity(
            entity, {"id": "file--2", "hashes": {"MD5": "other", "SHA-256": "new"}}
        )

        assert entity["hashes"] == {"MD5": "original", "SHA-256": "new"}

    def test_should_add_hashes_to_an_entity_without_hashes(self):
        entity = {"type": "file", "id": "file--1"}

        merge_enriched_entity(entity, {"id": "file--2", "hashes": {"SHA-256": "new"}})

        assert entity["hashes"] == {"SHA-256": "new"}

    def test_should_add_missing_properties_without_overwriting_existing_ones(self):
        entity = {
            "type": "indicator",
            "id": "indicator--1",
            "valid_from": "2020-01-01T00:00:00Z",
        }

        merge_enriched_entity(
            entity,
            {
                "id": "indicator--1",
                "valid_from": "2026-10-22T00:00:00Z",
                "x_mitre_platforms": ["windows"],
            },
        )

        assert entity["valid_from"] == "2020-01-01T00:00:00Z"
        assert entity["x_mitre_platforms"] == ["windows"]

    def test_should_not_share_mutable_values_with_the_enriched_entity(self):
        entity = {"type": "indicator", "id": "indicator--1"}
        enriched = {
            "id": "indicator--1",
            "labels": [],
            "kill_chain_phases": [{"phase_name": "x"}],
        }
        enriched["labels"].append("new")

        merge_enriched_entity(entity, enriched)
        enriched["labels"].append("later")
        enriched["kill_chain_phases"][0]["phase_name"] = "changed"

        assert entity["labels"] == ["new"]
        assert entity["kill_chain_phases"] == [{"phase_name": "x"}]


class TestReplaceRefs:
    def test_should_replace_single_and_list_references(self):
        stix_object = {
            "id": "relationship--1",
            "source_ref": "file--old",
            "target_ref": "malware--1",
            "object_refs": ["file--old", "note--1"],
            "labels": ["file--old"],
        }

        replace_refs(stix_object, "file--old", "file--entity")

        assert stix_object == {
            "id": "relationship--1",
            "source_ref": "file--entity",
            "target_ref": "malware--1",
            "object_refs": ["file--entity", "note--1"],
            "labels": ["file--old"],
        }
