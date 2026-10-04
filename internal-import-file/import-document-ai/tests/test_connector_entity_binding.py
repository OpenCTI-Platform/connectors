"""``Connector.process_message`` binds the extracted entities to existing ones.

The extracted bundle goes through ``curationResolve`` before any container or
relationship captures its ids: what OpenCTI receives names the existing
entities, under their standard ids, with the document's spellings as aliases.
"""

import json
from io import BytesIO
from unittest.mock import Mock

import pycti
import pytest
import stix2
from import_doc_ai import connector as connector_module
from import_doc_ai.connector import Connector
from import_doc_ai.entity_binding import curation_resolve_query
from import_doc_ai.util import OpenCTIFileObject

APT29_ID = pycti.IntrusionSet.generate_id("APT29")
UNITED_STATES_ID = pycti.Location.generate_id("United States", "Country")
SCHEMA_ERROR = ValueError(
    {
        "name": "GRAPHQL_VALIDATION_FAILED",
        "error_message": 'Cannot query field "curationResolve" on type "Query".',
    }
)
COZY_BEAR = stix2.IntrusionSet(
    id=pycti.IntrusionSet.generate_id("Cozy Bear"), name="Cozy Bear"
)
WELLMESS = stix2.Malware(
    id=pycti.Malware.generate_id("WellMess"), name="WellMess", is_family=True
)
USA = stix2.Location(
    id=pycti.Location.generate_id("USA", "Country"), name="USA", country="US"
)
IP = stix2.IPv4Address(value="192.0.2.10")
USES = stix2.Relationship(
    id=pycti.StixCoreRelationship.generate_id("uses", COZY_BEAR["id"], WELLMESS["id"]),
    relationship_type="uses",
    source_ref=COZY_BEAR["id"],
    target_ref=WELLMESS["id"],
)
TARGETS = stix2.Relationship(
    id=pycti.StixCoreRelationship.generate_id("targets", COZY_BEAR["id"], USA["id"]),
    relationship_type="targets",
    source_ref=COZY_BEAR["id"],
    target_ref=USA["id"],
)
EXTRACTED_IDS = {COZY_BEAR["id"], USA["id"]}


def extraction(with_report: bool = False) -> stix2.Bundle:
    objects = [COZY_BEAR, WELLMESS, USA, IP, USES, TARGETS]
    if with_report:
        objects.append(
            stix2.Report(
                id=pycti.Report.generate_id("Extracted report", "2026-01-01T00:00:00Z"),
                name="Extracted report",
                published="2026-01-01T00:00:00Z",
                report_types=["threat-report"],
                object_refs=[obj["id"] for obj in objects],
            )
        )
    return stix2.Bundle(objects=objects, allow_custom=True)


class Platform:
    """Answer curationResolve like an OpenCTI knowing APT29 and the United States."""

    def __init__(self, error: Exception | None = None):
        self.error = error
        self.calls = []
        self.requests = 0

    def query(self, query: str, variables: dict) -> dict:
        size = len(variables) // 2
        assert query == curation_resolve_query(size)
        names = [
            (variables[f"type{index}"], variables[f"name{index}"])
            for index in range(size)
        ]
        self.calls.extend(names)
        self.requests += 1
        if self.error is not None:
            raise self.error
        answers = {
            ("Intrusion-Set", "Cozy Bear"): {
                "entity_id": "1d2e8f30-0f6b-4bd6-9d0e-0d6b8b8a2f01",
                "standard_id": APT29_ID,
                "entity_type": "Intrusion-Set",
                "name": "APT29",
                "match_type": "taxonomy",
                "score": 0.95,
                "matched_value": "APT29",
            },
            ("Country", "USA"): {
                "entity_id": "5b7a7c8e-2e4c-4b8a-a7a2-6f3f4f2b9c02",
                "standard_id": UNITED_STATES_ID,
                "entity_type": "Country",
                "name": "United States",
                "match_type": "alias",
                "score": 1.0,
                "matched_value": "United States of America",
            },
        }
        return {
            "data": {
                f"resolve{index}": answers.get(name) for index, name in enumerate(names)
            }
        }


def build_connector(
    monkeypatch: pytest.MonkeyPatch,
    bundle: stix2.Bundle,
    platform: Platform,
    resolve_existing_entities: bool = True,
    triggering_entity: Mock | None = None,
) -> tuple[Connector, Mock]:
    helper = Mock()
    helper.api.query.return_value = {"data": {"settings": {"id": "instance-id"}}}
    helper.api_impersonate.query.side_effect = platform.query
    helper.applicant_id = "88ec0c6a-13ce-5e39-b486-354fe4a7084f"
    helper.draft_id = ""
    helper.get_only_contextual.return_value = False
    config = Mock()
    config.import_document_ai.include_relationships = False
    config.import_document_ai.create_indicator = False
    config.import_document_ai.resolve_existing_entities = resolve_existing_entities
    config.import_document_ai.api_base_url = "http://127.0.0.1:1"
    config.import_document_ai.api_key = "unused"
    monkeypatch.setattr(
        connector_module,
        "download_import_file",
        Mock(
            return_value=OpenCTIFileObject(
                path="import/global/report.pdf",
                buffered_data=BytesIO(b"%PDF-1.4 entity binding"),
                mime_type="application/pdf",
                id="import/global/report.pdf",
            )
        ),
    )
    monkeypatch.setattr(
        connector_module, "get_triggering_entity", Mock(return_value=triggering_entity)
    )
    monkeypatch.setattr(
        connector_module,
        "fetch_octi_attack_pattern_by_mitre_id",
        Mock(return_value=None),
    )
    connector = Connector(config=config, helper=helper)
    connector.import_doc_ia_client.get_bundle = Mock(return_value=bundle)
    return connector, helper


def build_triggering_entity(stix_object: stix2.v21._STIXBase21) -> Mock:
    triggering_entity = Mock()
    triggering_entity.id = stix_object["id"]
    triggering_entity.author_id = None
    triggering_entity.object_marking_refs = [stix2.TLP_GREEN["id"]]
    triggering_entity.get_stix = Mock(return_value=stix_object)
    return triggering_entity


def sent_objects(helper: Mock) -> dict[str, dict]:
    bundle = json.loads(helper.send_stix2_bundle.call_args.kwargs["bundle"])
    return {obj["id"]: obj for obj in bundle["objects"]}


def sent(call) -> dict:
    """The send options and the objects of a sent bundle (its id is random)."""
    return {**call.kwargs, "bundle": json.loads(call.kwargs["bundle"])["objects"]}


def test_global_import_sends_the_existing_entities_the_document_names(
    monkeypatch: pytest.MonkeyPatch,
):
    # Given a document naming APT29 "Cozy Bear" and the United States "USA"
    platform = Platform()
    connector, helper = build_connector(monkeypatch, extraction(), platform)

    # When importing it without context
    connector.process_message(data={})

    # Then OpenCTI receives APT29 and the United States, under their standard
    # ids and names, with the spellings of the document as aliases
    objects = sent_objects(helper)
    assert objects[APT29_ID]["name"] == "APT29"
    assert objects[APT29_ID]["aliases"] == ["Cozy Bear"]
    assert objects[UNITED_STATES_ID]["name"] == "United States"
    assert objects[UNITED_STATES_ID]["x_opencti_aliases"] == ["USA"]
    assert objects[UNITED_STATES_ID]["x_opencti_location_type"] == "Country"
    assert objects[WELLMESS["id"]] == json.loads(WELLMESS.serialize())
    # And the relationships and the report created for the file point to them
    assert objects[USES["id"]]["source_ref"] == APT29_ID
    assert objects[TARGETS["id"]]["source_ref"] == APT29_ID
    assert objects[TARGETS["id"]]["target_ref"] == UNITED_STATES_ID
    [created_report] = [obj for obj in objects.values() if obj["type"] == "report"]
    assert set(created_report["object_refs"]) == set(objects) - {created_report["id"]}
    serialized = json.dumps(objects)
    assert not [
        extracted_id for extracted_id in EXTRACTED_IDS if extracted_id in serialized
    ]
    assert sorted(platform.calls) == [
        ("Country", "USA"),
        ("Intrusion-Set", "Cozy Bear"),
        ("Malware", "WellMess"),
    ]
    helper.connector_logger.info.assert_any_call(
        "Resolved the extracted entities against OpenCTI",
        {
            "bound": 2,
            "aliases_added": 2,
            "lookups": 3,
            "requests": 1,
            "cache_hits": 0,
            "failed_lookups": 0,
            "rejected_resolutions": 0,
            "unresolved_names": 0,
            "merged_duplicates": 0,
            "dropped_relationships": 0,
        },
    )
    helper.connector_logger.debug.assert_any_call(
        "Bound an extracted entity to an existing OpenCTI entity",
        {
            "type": "Intrusion-Set",
            "extracted_name": "Cozy Bear",
            "bound_name": "APT29",
            "bound_id": APT29_ID,
            "match_type": "taxonomy",
            "score": 0.95,
            "alias_added": True,
        },
    )


def test_contextual_import_into_a_container_references_the_existing_entities(
    monkeypatch: pytest.MonkeyPatch,
):
    container = stix2.Report(
        id=pycti.Report.generate_id("Triggering report", "2026-01-01T00:00:00Z"),
        name="Triggering report",
        published="2026-01-01T00:00:00Z",
        report_types=["threat-report"],
        object_refs=[IP["id"]],
    )
    connector, helper = build_connector(
        monkeypatch,
        extraction(),
        Platform(),
        triggering_entity=build_triggering_entity(container),
    )

    connector.process_message(data={})

    objects = sent_objects(helper)
    container_refs = set(objects[container["id"]]["object_refs"])
    assert {APT29_ID, UNITED_STATES_ID, WELLMESS["id"]} <= container_refs
    assert not EXTRACTED_IDS & container_refs


def test_contextual_import_into_the_named_entity_relates_nothing_to_itself(
    monkeypatch: pytest.MonkeyPatch,
):
    # Given an import triggered from APT29, whose document calls it Cozy Bear
    apt29 = stix2.IntrusionSet(id=APT29_ID, name="APT29")
    connector, helper = build_connector(
        monkeypatch,
        extraction(),
        Platform(),
        triggering_entity=build_triggering_entity(apt29),
    )

    connector.process_message(data={})

    # Then the other extracted objects are related to APT29, and APT29 is not
    # related to itself
    related_to = [
        obj
        for obj in sent_objects(helper).values()
        if obj.get("relationship_type") == "related-to"
    ]
    assert {obj["target_ref"] for obj in related_to} == {APT29_ID}
    assert APT29_ID not in {obj["source_ref"] for obj in related_to}
    assert {UNITED_STATES_ID, WELLMESS["id"], IP["id"]} <= {
        obj["source_ref"] for obj in related_to
    }


def test_disabled_binding_sends_the_entities_as_extracted(
    monkeypatch: pytest.MonkeyPatch,
):
    platform = Platform()
    connector, helper = build_connector(
        monkeypatch,
        extraction(with_report=True),
        platform,
        resolve_existing_entities=False,
    )

    connector.process_message(data={})

    objects = sent_objects(helper)
    assert EXTRACTED_IDS <= set(objects)
    assert not {APT29_ID, UNITED_STATES_ID} & set(objects)
    assert platform.calls == []
    helper.api_impersonate.query.assert_not_called()


def test_import_against_a_platform_without_curation_resolve_is_unchanged(
    monkeypatch: pytest.MonkeyPatch,
):
    # Given the bundle a connector without binding sends
    extracted = extraction(with_report=True)
    connector, helper = build_connector(
        monkeypatch, extracted, Platform(), resolve_existing_entities=False
    )
    connector.process_message(data={})
    expected = sent(helper.send_stix2_bundle.call_args)

    # When importing the same document against a platform without
    # curationResolve, twice
    platform = Platform(error=SCHEMA_ERROR)
    connector, helper = build_connector(monkeypatch, extracted, platform)
    connector.process_message(data={})
    connector.process_message(data={})

    # Then OpenCTI receives the very same objects, the platform is asked once,
    # and the fallback is logged once
    first_call, second_call = helper.send_stix2_bundle.call_args_list
    assert sent(first_call) == expected
    assert sent(second_call) == expected
    assert platform.requests == 1
    fallback_logs = [
        call
        for call in helper.connector_logger.info.call_args_list
        if call.args[0].startswith("OpenCTI does not expose the curationResolve query")
    ]
    assert len(fallback_logs) == 1
    helper.connector_logger.warning.assert_not_called()


def test_an_unexpected_binding_error_does_not_fail_the_import(
    monkeypatch: pytest.MonkeyPatch,
):
    # Given a binder failing in an unexpected way
    extracted = extraction(with_report=True)
    connector, helper = build_connector(
        monkeypatch, extracted, Platform(), resolve_existing_entities=False
    )
    connector.process_message(data={})
    expected = sent(helper.send_stix2_bundle.call_args)
    connector, helper = build_connector(monkeypatch, extracted, Platform())
    connector.existing_entity_binder.bind = Mock(side_effect=RuntimeError("boom"))

    # When importing a document
    connector.process_message(data={})

    # Then the document is imported as extracted, and the error logged
    assert sent(helper.send_stix2_bundle.call_args) == expected
    helper.connector_logger.error.assert_called_once_with(
        "Could not bind the extracted entities to the existing ones, "
        "importing them as extracted",
        {"error": "RuntimeError: boom"},
    )
