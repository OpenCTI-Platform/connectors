"""Regression tests for the follow-up deep Aikido review."""

import json
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock

import pytest
from connectors_sdk.exceptions.error import DataRetrievalError, UseCaseError
from pycti import MarkingDefinition, OpenCTIConnectorHelper
from src.services.utils.cve_extractor import extract_cve_ids
from tests.conftest import make_vulnerability
from tests.tests_connector.test_aikido_regressions import payload
from tests.tests_connector.test_cve_connector import _make_enrichment_connector


@pytest.mark.parametrize("representation", ["graphql", "stix"])
@pytest.mark.parametrize("distinct_clear_id", [False, True])
def test_clear_marking_supports_pycti_canonical_ids(
    monkeypatch, representation, distinct_clear_id
):
    original_generate_id = MarkingDefinition.generate_id
    alternate_id = "marking-definition--11111111-2222-4333-8444-555555555555"

    def generate_id(kind, definition):
        if distinct_clear_id and kind == "TLP" and definition == "TLP:CLEAR":
            return alternate_id
        return original_generate_id(kind, definition)

    monkeypatch.setattr(MarkingDefinition, "generate_id", staticmethod(generate_id))
    clear_id = generate_id("TLP", "TLP:CLEAR")
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        return_value=make_vulnerability("CVE-2024-3400")
    )
    data = payload()
    data["event_type"] = "INTERNAL_ENRICHMENT"
    if representation == "graphql":
        data["enrichment_entity"]["objectMarking"] = [
            {
                "standard_id": clear_id,
                "definition_type": "TLP",
                "definition": "TLP:CLEAR",
            }
        ]
    else:
        data["stix_entity"]["object_marking_refs"] = [clear_id]
    assert "Enriched 1 CVE" in connector.process_message(data)
    objects = json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
        "objects"
    ]
    marking = next(obj for obj in objects if obj["id"] == clear_id)
    assert marking["x_opencti_definition_type"] == "TLP"
    assert marking["x_opencti_definition"] == "TLP:CLEAR"
    for obj in objects:
        if obj["type"] in {"vulnerability", "report", "relationship"}:
            assert clear_id in obj["object_marking_refs"]
    connector.helper.check_max_tlp.assert_any_call("TLP:CLEAR", "TLP:AMBER")


@pytest.mark.parametrize(
    "text,expected",
    [
        ("CVE-2024-12345678", ["CVE-2024-12345678"]),
        ("CVE[-]2024[-]1234567890123456", ["CVE-2024-1234567890123456"]),
        ("cve_2024_12345678 CVE-2024-12345678", ["CVE-2024-12345678"]),
        ("CVE-2024-123 CVE-2024-12345678abc", []),
    ],
)
def test_cve_suffix_has_no_seven_digit_limit(text, expected):
    assert extract_cve_ids(text) == expected


def test_long_cve_is_looked_up_and_can_create_a_placeholder():
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        return_value=None
    )
    data = payload()
    data["stix_entity"]["name"] = "CVE-2024-12345678"
    assert "Enriched 1 CVE" in connector.process_message(data)
    connector.converter.client_api.get_vulnerability_by_id.assert_awaited_once_with(
        "CVE-2024-12345678", raise_on_error=True
    )
    objects = json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
        "objects"
    ]
    assert any(
        obj.get("name") == "CVE-2024-12345678" and obj["type"] == "vulnerability"
        for obj in objects
    )


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("Invalid API key"),
        TimeoutError("NVD timeout"),
        TypeError("Invalid NVD response"),
    ],
)
def test_direct_lookup_failure_propagates_to_worker(error):
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=error
    )
    connector.converter._placeholder_vulnerability_to_stix2 = MagicMock()
    data = payload()
    data["event_type"] = "INTERNAL_ENRICHMENT"
    with pytest.raises(ExceptionGroup) as caught:
        connector.process_message(data)
    failure = caught.value.exceptions[0]
    assert isinstance(failure, DataRetrievalError)
    assert failure.__cause__ is error
    connector.converter.client_api.get_vulnerability_by_id.assert_awaited_once_with(
        "CVE-2024-3400", raise_on_error=True
    )
    connector.converter._placeholder_vulnerability_to_stix2.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()
    connector.converter.client_api.close.assert_awaited_once()
    connector.converter.cpe_match_client.close.assert_awaited_once()


def test_playbook_initial_lookup_failure_returns_original_bundle():
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=TimeoutError("NVD timeout")
    )
    data = payload()
    original = deepcopy(data)
    status = connector.process_message(data)
    assert "Error while enriching" in status
    assert "NVD lookup failed" in status
    assert "Enriched 0" not in status
    assert (
        json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
            "objects"
        ]
        == original["stix_objects"]
    )
    assert data == original


def test_direct_later_chunk_failure_does_not_overwrite_prior_success():
    connector = _make_enrichment_connector()

    async def lookup(cve_id, **kwargs):
        if cve_id == "CVE-2024-3405":
            raise TimeoutError("NVD timeout on second chunk")
        return make_vulnerability(cve_id)

    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=lookup
    )
    data = payload()
    data["event_type"] = "INTERNAL_ENRICHMENT"
    data["stix_entity"]["name"] = " ".join(f"CVE-2024-{i}" for i in range(3400, 3406))
    with pytest.raises(ExceptionGroup):
        connector.process_message(data)
    connector.helper.send_stix2_bundle.assert_called_once()
    objects = json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
        "objects"
    ]
    assert sum(obj["type"] == "vulnerability" for obj in objects) == 5


def test_direct_conversion_failure_is_not_acknowledged_as_success():
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        return_value={"cve": {"id": "CVE-2024-3400"}}
    )
    data = payload()
    data["event_type"] = "INTERNAL_ENRICHMENT"
    with pytest.raises(ExceptionGroup) as caught:
        connector.process_message(data)
    assert isinstance(caught.value.exceptions[0], UseCaseError)
    connector.helper.send_stix2_bundle.assert_not_called()


def test_sdk_strict_marking_still_enforces_disclosure_limit():
    connector = _make_enrichment_connector(max_tlp="TLP:AMBER")
    connector.helper.check_max_tlp.side_effect = OpenCTIConnectorHelper.check_max_tlp
    data = payload()
    data["stix_entity"]["object_marking_refs"] = [
        MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT")
    ]
    data["event_type"] = "INTERNAL_ENRICHMENT"
    assert "exceeds max TLP" in connector.process_message(data)
    connector.converter.client_api.get_vulnerability_by_id.assert_not_called()
    connector.helper.send_stix2_bundle.assert_not_called()


def test_direct_partial_lookup_failure_does_not_send_a_successful_chunk():
    connector = _make_enrichment_connector()

    async def lookup(cve_id, **kwargs):
        if cve_id == "CVE-2024-3401":
            raise TimeoutError("NVD timeout")
        return make_vulnerability(cve_id)

    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=lookup
    )
    data = payload()
    data["event_type"] = "INTERNAL_ENRICHMENT"
    data["stix_entity"]["name"] = "CVE-2024-3400 CVE-2024-3401"
    with pytest.raises(ExceptionGroup):
        connector.process_message(data)
    connector.helper.send_stix2_bundle.assert_not_called()


@pytest.mark.parametrize("failure_stage", ["lookup", "send"])
def test_later_chunk_failure_preserves_last_successful_playbook_bundle(failure_stage):
    connector = _make_enrichment_connector()

    async def lookup(cve_id, **kwargs):
        if failure_stage == "lookup" and cve_id == "CVE-2024-3405":
            raise TimeoutError("NVD timeout on second chunk")
        return make_vulnerability(cve_id)

    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=lookup
    )
    if failure_stage == "send":
        connector.helper.send_stix2_bundle.side_effect = [
            ["bundle-1"],
            RuntimeError("Second send failed"),
            ["fallback"],
        ]
    data = payload()
    data["stix_entity"]["name"] = " ".join(f"CVE-2024-{i}" for i in range(3400, 3406))
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": "TLP:GREEN"}
    ]
    original = deepcopy(data)
    assert "Error while enriching" in connector.process_message(data)
    calls = connector.helper.send_stix2_bundle.call_args_list
    assert len(calls) == (2 if failure_stage == "lookup" else 3)
    successful = json.loads(calls[0].kwargs["bundle"])["objects"]
    fallback = json.loads(calls[-1].kwargs["bundle"])["objects"]
    assert fallback == successful
    vulnerabilities = {obj["id"] for obj in fallback if obj["type"] == "vulnerability"}
    assert len(vulnerabilities) == 5
    report = next(obj for obj in fallback if obj["type"] == "report")
    assert vulnerabilities <= set(report["object_refs"])
    assert any(obj["type"] == "marking-definition" for obj in fallback)
    assert data == original
