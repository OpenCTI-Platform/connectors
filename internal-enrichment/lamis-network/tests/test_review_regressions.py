"""Regression coverage for PR review 5331691970."""

import json
import uuid
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest
import stix2
from lamis_network.builder import LamisNetworkBuilder
from lamis_network.connector import LamisNetworkConnector
from pycti import Identity as PyctiIdentity
from pycti import Incident as PyctiIncident
from pycti import Indicator as PyctiIndicator
from pycti.utils.opencti_stix2_splitter import OpenCTIStix2Splitter


@pytest.fixture
def connector():
    helper = MagicMock()
    helper.api.indicator.read.return_value = None
    helper.api.stix_core_relationship.list.return_value = []
    helper.stix2_create_bundle.side_effect = lambda objects: stix2.Bundle(
        objects=objects, allow_custom=True
    ).serialize()
    connector = LamisNetworkConnector(helper=helper)
    connector.client = MagicMock()
    connector.client.get_ip_reputation.return_value = {"fraud_score": 20}
    return connector


@pytest.fixture
def event():
    observable_id = f"ipv4-addr--{uuid.uuid4()}"
    stix_entity = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": observable_id,
        "value": "198.51.100.10",
    }
    return {
        "enrichment_entity": {
            "id": observable_id,
            "standard_id": observable_id,
            "entity_type": "IPv4-Addr",
            "value": stix_entity["value"],
        },
        "stix_entity": stix_entity,
        "stix_objects": [deepcopy(stix_entity)],
    }


@pytest.mark.parametrize("marking_type", [None, "", "UNKNOWN", False, 7])
@pytest.mark.parametrize("source", ["event", "platform"])
def test_malformed_marking_blocks_external_query(
    connector, event, marking_type, source
):
    ref = (
        stix2.TLP_RED.id if source == "event" else f"marking-definition--{uuid.uuid4()}"
    )
    marking = {
        "standard_id": ref,
        "definition_type": marking_type,
        "definition": "TLP:RED",
    }
    event["enrichment_entity"]["object_marking_refs"] = [ref]
    event["stix_entity"]["object_marking_refs"] = [ref]
    if source == "event":
        event["enrichment_entity"]["objectMarking"] = [marking]
    else:
        connector.helper.api.marking_definition.read.return_value = marking
    assert "skipped" in connector._process_message(event)
    connector.client.get_ip_reputation.assert_not_called()
    connector.helper.send_stix2_bundle.assert_called_once()


@pytest.mark.parametrize("marking_type", ["PAP", "statement", "TLP"])
def test_known_red_id_cannot_be_overridden(connector, event, marking_type):
    event["enrichment_entity"]["objectMarking"] = [
        {
            "standard_id": stix2.TLP_RED.id,
            "definition_type": marking_type,
            "definition": "TLP:CLEAR",
        }
    ]
    assert "skipped" in connector._process_message(event)
    connector.client.get_ip_reputation.assert_not_called()


@pytest.mark.parametrize("marking_type", ["PAP", "statement"])
def test_explicit_non_tlp_marking_is_allowed(connector, event, marking_type):
    ref = f"marking-definition--{uuid.uuid4()}"
    marking = {
        "standard_id": ref,
        "definition_type": marking_type,
        "definition": "AMBER",
    }
    event["enrichment_entity"]["objectMarking"] = [marking]
    event["stix_entity"]["object_marking_refs"] = [ref]
    connector.helper.api.marking_definition.read.return_value = marking
    assert "Sent STIX bundle" in connector._process_message(event)
    connector.client.get_ip_reputation.assert_called_once()


@pytest.mark.parametrize(
    "failure",
    [
        "observable",
        "ip",
        "family",
        "stix_entity",
        "stix_id",
        "stix_value",
        "stix_markings",
        "client",
        "builder",
    ],
)
def test_errors_forward_original_bundle_before_propagation(connector, event, failure):
    original = deepcopy(event["stix_objects"])
    if failure == "observable":
        event.pop("enrichment_entity")
    elif failure == "ip":
        event["enrichment_entity"]["value"] = "invalid"
    elif failure == "family":
        event["enrichment_entity"]["entity_type"] = "IPv6-Addr"
    elif failure == "stix_entity":
        event.pop("stix_entity")
    elif failure == "stix_id":
        event["stix_entity"]["id"] = f"ipv4-addr--{uuid.uuid4()}"
    elif failure == "stix_value":
        event["stix_entity"]["value"] = "198.51.100.11"
    elif failure == "stix_markings":
        event["stix_entity"]["object_marking_refs"] = "invalid"
    elif failure == "client":
        connector.client.get_ip_reputation.side_effect = RuntimeError("client failed")
    with patch.object(LamisNetworkBuilder, "enrich_observable") as enrich:
        if failure == "builder":
            enrich.side_effect = RuntimeError("builder failed")
        with pytest.raises((ValueError, RuntimeError)):
            connector._process_message(event)
    connector.helper.send_stix2_bundle.assert_called_once()
    args, kwargs = connector.helper.send_stix2_bundle.call_args
    assert json.loads(args[0])["objects"] == original
    assert event["stix_objects"] == original
    assert kwargs["cleanup_inconsistent_bundle"] is True
    if failure not in {"client", "builder"}:
        connector.client.get_ip_reputation.assert_not_called()


@pytest.mark.parametrize("path", ["skip", "invalid_response", "error", "success"])
def test_referenced_authors_and_markings_survive_real_sdk_cleanup(
    connector, event, path
):
    author = stix2.Identity(
        id=PyctiIdentity.generate_id("Analyst", "organization"),
        name="Analyst",
        identity_class="organization",
    )
    custom_marking = f"marking-definition--{uuid.uuid4()}"
    incident = stix2.Incident(
        id=PyctiIncident.generate_id("Existing incident", "2024-01-01T00:00:00Z"),
        created="2024-01-01T00:00:00Z",
        name="Existing incident",
        created_by_ref=author.id,
        object_marking_refs=[custom_marking, stix2.TLP_GREEN.id],
    )
    event["stix_objects"].append(json.loads(incident.serialize()))
    original = deepcopy(event["stix_objects"])
    connector.helper.api.stix2.get_stix_bundle_or_object_from_entity_id.return_value = {
        "objects": [json.loads(author.serialize())]
    }
    connector.helper.api.marking_definition.read.return_value = {
        "definition_type": "statement",
        "definition": "Internal use only",
    }
    if path == "skip":
        event["stix_entity"]["object_marking_refs"] = [stix2.TLP_RED.id]
    elif path == "invalid_response":
        connector.client.get_ip_reputation.return_value = None
    elif path == "error":
        event.pop("enrichment_entity")
    if path == "error":
        with pytest.raises(ValueError):
            connector._process_message(event)
    else:
        connector._process_message(event)
    args, kwargs = connector.helper.send_stix2_bundle.call_args
    assert kwargs["cleanup_inconsistent_bundle"] is True
    _, incompatible, chunks = OpenCTIStix2Splitter().split_bundle_with_expectations(
        args[0], cleanup_inconsistent_bundle=True
    )
    assert not incompatible
    cleaned = {
        obj["id"]: obj for chunk in chunks for obj in json.loads(chunk)["objects"]
    }
    assert cleaned[incident.id]["created_by_ref"] == author.id
    assert cleaned[incident.id]["object_marking_refs"] == [
        custom_marking,
        stix2.TLP_GREEN.id,
    ]
    assert custom_marking in cleaned and author.id in cleaned
    assert event["stix_objects"] == original


@pytest.mark.parametrize("source", ["dict", "stix", "platform", "observable"])
def test_retirement_preserves_metadata_and_later_label_reconciliation(
    connector, event, source
):
    ip = event["stix_entity"]["value"]
    indicator_id = PyctiIndicator.generate_id(f"[ipv4-addr:value = '{ip}']")
    indicator = {
        "type": "indicator",
        "id": indicator_id,
        "spec_version": "2.1",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        "created_by_ref": connector.author.id,
        "name": ip,
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
        "labels": ["analyst-label", "vpn", "suspicious"],
        "external_references": [
            {"source_name": "Analyst", "url": "https://example.org/report"}
        ],
        "x_lamis_network_labels": ["vpn", "suspicious"],
        "object_marking_refs": [stix2.TLP_GREEN.id],
    }
    original = deepcopy(indicator)
    if source == "dict":
        event["stix_objects"].append(indicator)
    elif source == "stix":
        event["stix_objects"].append(stix2.parse(indicator, allow_custom=True))
    else:
        indicator["standard_id"] = indicator_id
        indicator["objectLabel"] = [
            {"value": label} for label in indicator.pop("labels")
        ]
        indicator["externalReferences"] = [
            {"sourceName": "Analyst", "url": "https://example.org/report"}
        ]
        indicator.pop("external_references")
        if source == "platform":
            connector.helper.api.indicator.read.return_value = indicator
        else:
            event["enrichment_entity"]["indicators"] = [indicator]
    builder = LamisNetworkBuilder(
        helper=connector.helper,
        author=connector.author,
        observable=event["enrichment_entity"],
        stix_objects=event["stix_objects"],
    )
    builder.revoke_indicator(ip, "IPv4-Addr")
    retired = next(obj for obj in builder.bundle if obj["id"] == indicator_id)
    assert list(retired["labels"]) == original["labels"]
    assert list(retired["x_lamis_network_labels"]) == original["x_lamis_network_labels"]
    assert [dict(ref) for ref in retired["external_references"]] == original[
        "external_references"
    ]
    assert stix2.TLP_GREEN.id in retired["object_marking_refs"]
    assert retired["valid_until"] > retired["valid_from"]
    connector.helper.api.indicator.read.return_value = None
    builder.create_indicator(
        ip,
        "IPv4-Addr",
        90,
        ["suspicious"],
        "Risk increased",
        evaluated_flags={"suspicious": True, "vpn": False},
    )
    active = next(obj for obj in builder.bundle if obj["id"] == indicator_id)
    assert list(active["labels"]) == ["analyst-label", "suspicious"]
    assert list(active["x_lamis_network_labels"]) == ["suspicious"]
    assert "valid_until" not in active


@pytest.mark.parametrize(
    "source", ["dict", "stix", "platform", "observable", "multiple"]
)
def test_reenrichment_preserves_other_external_references(connector, event, source):
    ip = event["stix_entity"]["value"]
    indicator_id = PyctiIndicator.generate_id(f"[ipv4-addr:value = '{ip}']")
    analyst_ref = {
        "source_name": "Analyst",
        "url": "https://example.org/report",
        "external_id": "CASE-42",
    }
    old_lamis_ref = {
        "source_name": "Lamis Network",
        "url": "https://lamisnetwork.com",
        "description": "Lamis Network IP risk evaluation (Score: 80/100)",
    }
    indicator = {
        "type": "indicator",
        "id": indicator_id,
        "spec_version": "2.1",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        "created_by_ref": connector.author.id,
        "name": ip,
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "valid_from": "2024-01-01T00:00:00Z",
        "external_references": [analyst_ref, old_lamis_ref],
    }
    if source in {"dict", "multiple"}:
        event["stix_objects"].append(deepcopy(indicator))
    if source == "stix":
        event["stix_objects"].append(stix2.parse(indicator, allow_custom=True))
    if source in {"platform", "observable", "multiple"}:
        platform_indicator = deepcopy(indicator)
        platform_indicator["standard_id"] = indicator_id
        platform_references = []
        for ref in indicator["external_references"]:
            platform_ref = {"sourceName": ref["source_name"], "url": ref["url"]}
            if "external_id" in ref:
                platform_ref["externalId"] = ref["external_id"]
            if "description" in ref:
                platform_ref["description"] = ref["description"]
            platform_references.append(platform_ref)
        platform_indicator["externalReferences"] = platform_references
        platform_indicator.pop("external_references")
        if source in {"platform", "multiple"}:
            connector.helper.api.indicator.read.return_value = platform_indicator
        else:
            event["enrichment_entity"]["indicators"] = [platform_indicator]

    builder = LamisNetworkBuilder(
        helper=connector.helper,
        author=connector.author,
        observable=event["enrichment_entity"],
        stix_objects=event["stix_objects"],
    )
    builder.create_indicator(ip, "IPv4-Addr", 90, ["suspicious"], "Risk increased")
    updated = next(obj for obj in builder.bundle if obj["id"] == indicator_id)
    references = [dict(ref) for ref in updated["external_references"]]
    assert analyst_ref in references
    assert references.count(analyst_ref) == 1
    lamis_refs = [ref for ref in references if ref["source_name"] == "Lamis Network"]
    assert len(lamis_refs) == 1
    assert "Score: 90/100" in lamis_refs[0]["description"]
