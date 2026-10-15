"""Contracts of the bundle ``Connector.process_message`` hands to OpenCTI.

- the location / indicator-flag rewrite is linear and produces exactly the
  bundle the former one-rebuild-per-object loops produced;
- the connector signs nothing: an author comes from the extraction (or the
  triggering entity's own record) and is never added nor overridden;
- ``send_stix2_bundle`` is called without ``cleanup_inconsistent_bundle``,
  because the pycti cleanup would strip the platform references a contextual
  import relies on (pinned against the real pycti splitter).
"""

import json
import time
from io import BytesIO
from unittest.mock import Mock

import pycti
import pytest
import stix2
from import_doc_ai import connector as connector_module
from import_doc_ai.connector import Connector
from import_doc_ai.util import (
    OpenCTIFileObject,
    replace_in_bundle,
    replace_objects_in_bundle,
    update_custom_properties,
    update_object_refs,
)
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter

AUTHOR = stix2.Identity(
    id=pycti.Identity.generate_id("Document Author Org", "organization"),
    name="Document Author Org",
    identity_class="organization",
)
CUSTOM_MARKING_ID = pycti.MarkingDefinition.generate_id("statement", "Internal only")


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
def build_extraction(
    observable_count: int, location_count: int, author: stix2.Identity | None = None
) -> stix2.Bundle:
    """Build a deterministic extraction: observables, locations, relationships, report."""
    created_by = {"created_by_ref": author["id"]} if author else {}
    intrusion_set = stix2.IntrusionSet(
        id=pycti.IntrusionSet.generate_id("Extracted Intrusion Set"),
        name="Extracted Intrusion Set",
        **created_by,
    )
    observables = [
        stix2.IPv4Address(value=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}")
        for i in range(observable_count)
    ]
    locations = []
    for i in range(location_count):
        location_fields = (
            {"country": "FR", "city": f"City {i}"} if i % 2 else {"region": "europe"}
        )
        locations.append(
            stix2.Location(
                id=pycti.Location.generate_id(f"Location {i}", "City"),
                name=f"Location {i}",
                **location_fields,
            )
        )
    relationships = [
        stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                "related-to", observable["id"], intrusion_set["id"]
            ),
            relationship_type="related-to",
            source_ref=observable["id"],
            target_ref=intrusion_set["id"],
            **created_by,
        )
        for observable in observables[:50]
    ]
    objects = [intrusion_set, *observables, *locations, *relationships]
    if author:
        objects.insert(0, author)
    report = stix2.Report(
        id=pycti.Report.generate_id("Extracted report", "2026-01-01T00:00:00Z"),
        name="Extracted report",
        published="2026-01-01T00:00:00Z",
        report_types=["threat-report"],
        object_refs=[obj["id"] for obj in objects],
        **created_by,
    )
    return stix2.Bundle(objects=[*objects, report], allow_custom=True)


def build_connector(
    monkeypatch: pytest.MonkeyPatch,
    extraction: stix2.Bundle,
    create_indicator: bool = False,
    triggering_entity: Mock | None = None,
) -> tuple[Connector, Mock]:
    helper = Mock()
    helper.api.query.return_value = {"data": {"settings": {"id": "instance-id"}}}
    helper.get_only_contextual.return_value = False
    config = Mock()
    config.import_document_ai.include_relationships = False
    config.import_document_ai.create_indicator = create_indicator
    config.import_document_ai.api_base_url = "http://127.0.0.1:1"
    config.import_document_ai.api_key = "unused"
    imported_file = OpenCTIFileObject(
        path="import/global/report.pdf",
        buffered_data=BytesIO(b"%PDF-1.4 bundle contracts"),
        mime_type="application/pdf",
        id="import/global/report.pdf",
    )
    monkeypatch.setattr(
        connector_module, "download_import_file", Mock(return_value=imported_file)
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
    connector.import_doc_ia_client.get_bundle = Mock(return_value=extraction)
    return connector, helper


def build_triggering_entity(
    stix_object: stix2.v21._STIXBase21, marking_ids: list[str]
) -> Mock:
    triggering_entity = Mock()
    triggering_entity.id = stix_object["id"]
    triggering_entity.author_id = stix_object.get("created_by_ref")
    triggering_entity.object_marking_refs = marking_ids
    triggering_entity.get_stix = Mock(return_value=stix_object)
    return triggering_entity


def sent_bundle(helper: Mock) -> dict:
    helper.send_stix2_bundle.assert_called_once()
    return json.loads(helper.send_stix2_bundle.call_args.kwargs["bundle"])


def sequential_replace_objects_in_bundle(bundle, new_objects_by_id):
    """The former behaviour: one full bundle rebuild per replaced object."""
    for object_id, new_object in new_objects_by_id.items():
        bundle = replace_in_bundle(bundle, object_id, new_object)
    return bundle


def count_bundle_rebuilds(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    counter = [0]
    original_init = stix2.Bundle.__init__

    def counting_init(self, *args, **kwargs):
        counter[0] += 1
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(stix2.Bundle, "__init__", counting_init)
    return counter


def split(bundle: dict, cleanup_inconsistent_bundle: bool) -> dict[str, dict]:
    """What pycti hands to the workers: the split objects, keyed by id."""
    _, _, bundles = OpenCTIStix2Splitter().split_bundle_with_expectations(
        bundle=json.dumps(bundle),
        cleanup_inconsistent_bundle=cleanup_inconsistent_bundle,
    )
    objects = {}
    for split_bundle in bundles:
        for obj in json.loads(split_bundle)["objects"]:
            obj.pop("nb_deps", None)
            objects[obj["id"]] = obj
    return objects


# --------------------------------------------------------------------------- #
# Linear rebuild, identical output
# --------------------------------------------------------------------------- #
def test_replace_objects_in_bundle_matches_one_replace_per_object():
    extraction = build_extraction(observable_count=30, location_count=10)
    duplicated = stix2.Bundle(
        objects=[*extraction["objects"], extraction["objects"][3]], allow_custom=True
    )
    replacements = {
        obj["id"]: update_custom_properties({"x_marker": True}, obj)
        for obj in duplicated["objects"][1:40]
    }

    single_pass = replace_objects_in_bundle(duplicated, replacements)
    one_per_object = sequential_replace_objects_in_bundle(duplicated, replacements)

    assert [obj.serialize() for obj in single_pass["objects"]] == [
        obj.serialize() for obj in one_per_object["objects"]
    ]


@pytest.mark.parametrize("create_indicator", [False, True])
def test_large_extraction_is_sent_exactly_as_with_the_per_object_rebuild(
    monkeypatch: pytest.MonkeyPatch, create_indicator: bool
):
    extraction = build_extraction(observable_count=200, location_count=40)
    # Defanged spellings, one of them a duplicate once refanged: the refang
    # step runs first and its output is what both rebuilds process.
    defanged = [
        stix2.DomainName(value="evil[.]example[.]com"),
        stix2.DomainName(value="evil.example.com"),
        stix2.IPv4Address(value="10[.]200[.]0[.]1"),
    ]
    extraction = stix2.Bundle(
        objects=[*extraction["objects"][:-1], *defanged, extraction["objects"][-1]],
        allow_custom=True,
    )

    connector, helper = build_connector(monkeypatch, extraction, create_indicator)
    connector.process_message(data={})
    linear = sent_bundle(helper)
    sent_values = {obj.get("value") for obj in linear["objects"]}
    assert {"evil.example.com", "10.200.0.1"} <= sent_values
    assert not {"evil[.]example[.]com", "10[.]200[.]0[.]1"} & sent_values

    monkeypatch.setattr(
        connector_module,
        "replace_objects_in_bundle",
        sequential_replace_objects_in_bundle,
    )
    connector, helper = build_connector(monkeypatch, extraction, create_indicator)
    connector.process_message(data={})
    per_object = sent_bundle(helper)

    assert linear["objects"] == per_object["objects"]
    observables = [obj for obj in linear["objects"] if obj["type"] == "ipv4-addr"]
    locations = [obj for obj in linear["objects"] if obj["type"] == "location"]
    assert len(observables) == 201
    assert all(
        obj.get("x_opencti_create_indicator") is (True if create_indicator else None)
        for obj in observables
    )
    assert {obj["x_opencti_location_type"] for obj in locations} == {
        "Country",
        "Region",
    }


def test_bundle_rebuilds_do_not_grow_with_the_extraction_size(
    monkeypatch: pytest.MonkeyPatch,
):
    rebuilds = count_bundle_rebuilds(monkeypatch)
    counts = {}
    for size in (20, 200):
        extraction = build_extraction(observable_count=size, location_count=size // 5)
        connector, _ = build_connector(monkeypatch, extraction, create_indicator=True)
        rebuilds[0] = 0
        connector.process_message(data={})
        counts[size] = rebuilds[0]

    assert counts[20] == counts[200]

    monkeypatch.setattr(
        connector_module,
        "replace_objects_in_bundle",
        sequential_replace_objects_in_bundle,
    )
    extraction = build_extraction(observable_count=200, location_count=40)
    connector, _ = build_connector(monkeypatch, extraction, create_indicator=True)
    rebuilds[0] = 0
    connector.process_message(data={})
    assert rebuilds[0] >= 240  # the former loops rebuilt once per object


def test_large_extraction_is_processed_within_a_linear_time_budget(
    monkeypatch: pytest.MonkeyPatch,
):
    extraction = build_extraction(observable_count=3000, location_count=300)
    connector, helper = build_connector(monkeypatch, extraction, create_indicator=True)

    started = time.perf_counter()
    connector.process_message(data={})
    elapsed = time.perf_counter() - started

    assert len(sent_bundle(helper)["objects"]) == 3000 + 300 + 50 + 2
    assert elapsed < 60, f"3,300 objects took {elapsed:.1f}s"


# --------------------------------------------------------------------------- #
# Author: never added, never overridden
# --------------------------------------------------------------------------- #
def test_global_import_adds_no_author(monkeypatch: pytest.MonkeyPatch):
    extraction = build_extraction(observable_count=5, location_count=2)
    connector, helper = build_connector(monkeypatch, extraction, create_indicator=True)

    connector.process_message(data={})

    for obj in sent_bundle(helper)["objects"]:
        assert "created_by_ref" not in obj, obj["id"]
        assert "x_opencti_created_by_ref" not in obj, obj["id"]


def test_extraction_author_is_kept_as_extracted(monkeypatch: pytest.MonkeyPatch):
    extraction = build_extraction(observable_count=5, location_count=2, author=AUTHOR)
    extracted_authors = {
        obj["id"]: obj.get("created_by_ref") for obj in extraction["objects"]
    }
    connector, helper = build_connector(monkeypatch, extraction, create_indicator=True)

    connector.process_message(data={})

    sent_objects = sent_bundle(helper)["objects"]
    assert {obj["id"]: obj.get("created_by_ref") for obj in sent_objects} == (
        extracted_authors
    )
    assert AUTHOR["id"] in {obj["id"] for obj in sent_objects}


def test_triggering_container_keeps_its_own_author_and_lends_it_to_nobody(
    monkeypatch: pytest.MonkeyPatch,
):
    container_author_id = pycti.Identity.generate_id("Container Author", "organization")
    container = stix2.Report(
        id=pycti.Report.generate_id("Triggering report", "2026-01-01T00:00:00Z"),
        name="Triggering report",
        published="2026-01-01T00:00:00Z",
        report_types=["threat-report"],
        object_refs=[AUTHOR["id"]],
        created_by_ref=container_author_id,
    )
    extraction = build_extraction(observable_count=5, location_count=2)
    connector, helper = build_connector(
        monkeypatch,
        extraction,
        triggering_entity=build_triggering_entity(container, [stix2.TLP_GREEN["id"]]),
    )

    connector.process_message(data={})

    sent_objects = {obj["id"]: obj for obj in sent_bundle(helper)["objects"]}
    assert sent_objects[container["id"]]["created_by_ref"] == container_author_id
    assert [
        object_id
        for object_id, obj in sent_objects.items()
        if object_id != container["id"]
        and container_author_id
        in (obj.get("created_by_ref"), obj.get("x_opencti_created_by_ref"))
    ] == []


# --------------------------------------------------------------------------- #
# cleanup_inconsistent_bundle, measured on the real pycti splitter
# --------------------------------------------------------------------------- #
def test_cleanup_changes_nothing_on_a_consistent_bundle(
    monkeypatch: pytest.MonkeyPatch,
):
    extraction = build_extraction(observable_count=20, location_count=4, author=AUTHOR)
    connector, helper = build_connector(monkeypatch, extraction)
    connector.process_message(data={})
    bundle = sent_bundle(helper)

    assert split(bundle, cleanup_inconsistent_bundle=True) == split(
        bundle, cleanup_inconsistent_bundle=False
    )


def test_cleanup_drops_only_the_dangling_references_of_an_inconsistent_bundle(
    monkeypatch: pytest.MonkeyPatch,
):
    missing_id = pycti.Malware.generate_id("Never extracted")
    extraction = build_extraction(observable_count=20, location_count=4)
    dangling_relationship = stix2.Relationship(
        id=pycti.StixCoreRelationship.generate_id(
            "related-to", extraction["objects"][1]["id"], missing_id
        ),
        relationship_type="related-to",
        source_ref=extraction["objects"][1]["id"],
        target_ref=missing_id,
    )
    report = extraction["objects"][-1]
    inconsistent_report = update_object_refs(
        report, [missing_id, dangling_relationship["id"]], extend=True
    )
    extraction = stix2.Bundle(
        objects=[
            *extraction["objects"][:-1],
            dangling_relationship,
            inconsistent_report,
        ],
        allow_custom=True,
    )
    connector, helper = build_connector(monkeypatch, extraction)
    connector.process_message(data={})
    bundle = sent_bundle(helper)

    kept = split(bundle, cleanup_inconsistent_bundle=False)
    cleaned = split(bundle, cleanup_inconsistent_bundle=True)

    # Without the cleanup the platform receives the dangling relationship
    # (rejected there: missing target) and the dangling report reference
    # (ignored there after its retries).
    assert dangling_relationship["id"] in kept
    assert missing_id in kept[report["id"]]["object_refs"]
    # With it, only those are gone.
    assert dangling_relationship["id"] not in cleaned
    assert missing_id not in cleaned[report["id"]]["object_refs"]
    kept.pop(dangling_relationship["id"])
    kept[report["id"]]["object_refs"].remove(missing_id)
    assert cleaned == kept


def test_cleanup_would_strip_the_platform_references_of_a_contextual_import(
    monkeypatch: pytest.MonkeyPatch,
):
    marking_ids = [stix2.TLP_AMBER["id"], CUSTOM_MARKING_ID]
    intrusion_set = stix2.IntrusionSet(
        id=pycti.IntrusionSet.generate_id("Triggering Intrusion Set"),
        name="Triggering Intrusion Set",
        object_marking_refs=marking_ids,
    )
    extraction = build_extraction(observable_count=10, location_count=2)
    connector, helper = build_connector(
        monkeypatch,
        extraction,
        triggering_entity=build_triggering_entity(intrusion_set, marking_ids),
    )

    connector.process_message(data={})

    assert (
        "cleanup_inconsistent_bundle" not in helper.send_stix2_bundle.call_args.kwargs
    )
    bundle = sent_bundle(helper)
    imported_ids = {obj["id"] for obj in extraction["objects"]}
    related_to_ids = {
        obj["id"]
        for obj in bundle["objects"]
        if obj["type"] == "relationship" and obj["target_ref"] == intrusion_set["id"]
    }
    assert related_to_ids

    # What the connector sends today reaches the workers intact: the imported
    # objects carry the triggering entity's markings and are related to it.
    sent = split(bundle, cleanup_inconsistent_bundle=False)
    assert related_to_ids <= set(sent)
    for object_id in imported_ids:
        assert set(marking_ids) <= set(sent[object_id]["object_marking_refs"])

    # The cleanup would drop every marking (the marking definitions live in the
    # platform, not in the bundle) and every related-to relationship (the
    # triggering entity is not in the bundle either).
    cleaned = split(bundle, cleanup_inconsistent_bundle=True)
    assert not related_to_ids & set(cleaned)
    for object_id in imported_ids:
        assert not cleaned[object_id].get("object_marking_refs"), object_id
