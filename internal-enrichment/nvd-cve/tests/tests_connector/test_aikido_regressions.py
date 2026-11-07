"""Regression coverage for the Aikido findings on PR #8242."""

import json
import os
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock

import pytest
from pycti import OpenCTIStix2Splitter
from src.models.configs.config_loader import ConfigLoader
from src.services.client.cpe_match import CPEMatchClient
from src.services.utils.constants import (
    CVES_PER_CHUNK,
    MAX_CPE_PAGES_PER_CVE,
    MAX_CPES_PER_CVE,
    MAX_CVES_PER_ENTITY,
)
from tests.conftest import make_cpe_name, make_vulnerability
from tests.tests_connector.test_cve_connector import _make_enrichment_connector

GREEN = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"


def payload():
    entity = {
        "id": "report--11111111-2222-4333-8444-555555555555",
        "type": "report",
        "name": "CVE-2024-3400",
    }
    return {
        "stix_entity": entity,
        "stix_objects": [entity],
        "enrichment_entity": {"entity_type": "Report"},
    }


@pytest.mark.parametrize(
    "stix_type,graphql_type",
    [
        ("indicator", "Report"),
        ("report", "Indicator"),
        ("", "Report"),
        ("report", ""),
    ],
)
def test_scope_requires_both_representations(stix_type, graphql_type):
    connector = _make_enrichment_connector()
    data = payload()
    data["stix_entity"]["type"] = stix_type
    data["enrichment_entity"]["entity_type"] = graphql_type
    original = deepcopy(data)
    assert "outside configured connector scope" in connector.process_message(data)
    connector.converter.client_api.get_vulnerability_by_id.assert_not_called()
    assert (
        json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
            "objects"
        ]
        == original["stix_objects"]
    )
    assert data == original


def test_graphql_only_markings_cover_every_generated_object():
    connector = _make_enrichment_connector(import_software=True)
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        return_value=make_vulnerability("CVE-2024-3400")
    )
    connector.converter.cpe_match_client.get_cpes_for_cve = AsyncMock(
        return_value=[make_cpe_name()]
    )
    data = payload()
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "TLP", "definition": "TLP:GREEN"}
    ]
    assert "Enriched 1 CVE" in connector.process_message(data)
    objects = json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
        "objects"
    ]
    assert any(o["id"] == GREEN and o["type"] == "marking-definition" for o in objects)
    for obj in objects:
        if obj["type"] in {"vulnerability", "software", "relationship", "report"}:
            assert GREEN in obj["object_marking_refs"]
    assert "object_marking_refs" not in data["stix_entity"]


@pytest.mark.parametrize(
    "graphql_markings,stix_refs",
    [
        ([{"id": "unresolved"}], []),
        ([], ["marking-definition--11111111-2222-4333-8444-555555555555"]),
        ([{"definition_type": "TLP", "definition": "TLP:UNKNOWN"}], []),
    ],
)
def test_unresolved_markings_refuse_lookup_and_preserve_original(
    graphql_markings, stix_refs
):
    connector = _make_enrichment_connector()
    data = payload()
    data["enrichment_entity"]["objectMarking"] = graphql_markings
    data["stix_entity"]["object_marking_refs"] = stix_refs
    original = deepcopy(data)
    assert "Error while enriching" in connector.process_message(data)
    connector.converter.client_api.get_vulnerability_by_id.assert_not_called()
    assert (
        json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
            "objects"
        ]
        == original["stix_objects"]
    )
    assert data == original


def test_config_precedence(monkeypatch, tmp_path):
    from src.models.configs import config_loader

    for key in list(os.environ):
        if key.startswith(("OPENCTI_", "CONNECTOR_", "CVE_")):
            monkeypatch.delenv(key)
    monkeypatch.setattr(
        config_loader,
        "__file__",
        str(tmp_path / "models" / "configs" / "config_loader.py"),
    )
    (tmp_path / "config.yml").write_text(
        "opencti:\n  url: https://yaml.example\n  token: yaml-token\n"
        "connector:\n  name: yaml-name\n"
        "cve:\n  import_software: true\n",
        encoding="utf-8",
    )
    (tmp_path / ".env").write_text(
        "OPENCTI_URL=https://dotenv.example\nOPENCTI_TOKEN=dotenv-token\n",
        encoding="utf-8",
    )
    config = ConfigLoader()
    assert str(config.opencti.url) == "https://dotenv.example/"
    assert config.opencti.token.get_secret_value() == "dotenv-token"
    monkeypatch.setenv("OPENCTI_URL", "https://runtime.example")
    monkeypatch.setenv("OPENCTI_TOKEN", "runtime-token")
    monkeypatch.setenv("CONNECTOR_NAME", "runtime-name")
    monkeypatch.setenv("CVE_IMPORT_SOFTWARE", "false")
    config = ConfigLoader()
    assert str(config.opencti.url) == "https://runtime.example/"
    assert config.opencti.token.get_secret_value() == "runtime-token"
    assert config.connector.name == "runtime-name"
    assert config.cve.import_software is False
    assert "runtime-token" not in config.model_dump_json()
    explicit = ConfigLoader(
        opencti={"url": "https://explicit.example", "token": "explicit-token"}
    )
    assert explicit.opencti.token.get_secret_value() == "explicit-token"
    (tmp_path / ".env").unlink()
    monkeypatch.delenv("OPENCTI_URL")
    monkeypatch.delenv("OPENCTI_TOKEN")
    assert ConfigLoader().opencti.token.get_secret_value() == "yaml-token"


@pytest.mark.parametrize("unique", [True, False])
async def test_cpe_pagination_has_name_and_page_limits(unique):
    client = CPEMatchClient.__new__(CPEMatchClient)
    client.helper = MagicMock()
    matches = (
        [
            {"cpeName": make_cpe_name(product=f"p{i}")}
            for i in range(MAX_CPES_PER_CVE + 50)
        ]
        if unique
        else []
    )
    client.get_complete_collection = AsyncMock(
        return_value={
            "totalResults": 100000,
            "resultsPerPage": 100,
            "matchStrings": [{"matchString": {"matches": matches}}],
        }
    )
    names = await client.get_cpes_for_cve("CVE-2024-3400")
    assert len(names) == (MAX_CPES_PER_CVE if unique else 0)
    assert client.get_complete_collection.await_count == (
        1 if unique else MAX_CPE_PAGES_PER_CVE
    )


def test_high_fanout_is_processed_and_sent_in_bounded_chunks():
    connector = _make_enrichment_connector(import_software=True)
    connector.config.cve.max_cves_per_entity = MAX_CVES_PER_ENTITY * 2
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=lambda cid, **kw: make_vulnerability(cid)
    )
    connector.converter.cpe_match_client.get_cpes_for_cve = AsyncMock(
        return_value=[
            make_cpe_name(product=f"p{i}") for i in range(MAX_CPES_PER_CVE + 50)
        ]
    )
    data = payload()
    data["stix_entity"]["name"] = " ".join(
        f"CVE-2024-{i:04d}" for i in range(MAX_CVES_PER_ENTITY + 1)
    )
    assert f"Enriched {MAX_CVES_PER_ENTITY} CVE" in connector.process_message(data)
    assert (
        connector.converter.client_api.get_vulnerability_by_id.await_count
        == MAX_CVES_PER_ENTITY
    )
    assert (
        connector.helper.send_stix2_bundle.call_count
        == MAX_CVES_PER_ENTITY // CVES_PER_CHUNK
    )
    for call in connector.helper.send_stix2_bundle.call_args_list:
        objects = json.loads(call.kwargs["bundle"])["objects"]
        assert sum(o["type"] == "vulnerability" for o in objects) <= CVES_PER_CHUNK
        assert (
            sum(o["type"] == "software" for o in objects)
            <= CVES_PER_CHUNK * MAX_CPES_PER_CVE
        )
        assert len(objects) <= CVES_PER_CHUNK * (2 * MAX_CPES_PER_CVE + 2) + 2
        ids = {o["id"] for o in objects}
        for obj in objects:
            if obj["type"] == "relationship":
                assert {obj["source_ref"], obj["target_ref"]} <= ids


def test_chunk_splitting_preserves_existing_and_previous_vulnerability_refs():
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=lambda cid, **kw: make_vulnerability(cid)
    )
    data = payload()
    data["stix_entity"]["name"] = " ".join(
        f"CVE-2024-{i:04d}" for i in range(CVES_PER_CHUNK + 1)
    )
    original_ref = "indicator--11111111-2222-4333-8444-555555555555"
    data["stix_entity"]["object_refs"] = [original_ref]
    assert f"Enriched {CVES_PER_CHUNK + 1} CVE" in connector.process_message(data)
    vulnerability_ids = set()
    for call in connector.helper.send_stix2_bundle.call_args_list:
        bundle = json.loads(call.kwargs["bundle"])
        vulnerability_ids.update(
            o["id"] for o in bundle["objects"] if o["type"] == "vulnerability"
        )
        _, _, chunks = OpenCTIStix2Splitter().split_bundle_with_expectations(
            call.kwargs["bundle"],
            cleanup_inconsistent_bundle=call.kwargs["cleanup_inconsistent_bundle"],
        )
        report = next(
            o
            for chunk in chunks
            for o in json.loads(chunk)["objects"]
            if o["type"] == "report"
        )
        assert {original_ref} | vulnerability_ids <= set(report["object_refs"])


def test_stix_and_graphql_markings_are_combined():
    connector = _make_enrichment_connector()
    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        return_value=make_vulnerability("CVE-2024-3400")
    )
    data = payload()
    data["stix_entity"]["object_marking_refs"] = [GREEN]
    data["enrichment_entity"]["objectMarking"] = [
        {"definition_type": "statement", "definition": "Internal distribution only"}
    ]
    assert "Enriched 1 CVE" in connector.process_message(data)
    objects = json.loads(connector.helper.send_stix2_bundle.call_args.kwargs["bundle"])[
        "objects"
    ]
    definitions = {o["id"] for o in objects if o["type"] == "marking-definition"}
    assert len(definitions) == 2
    for obj in objects:
        if obj["type"] in {"vulnerability", "report", "relationship"}:
            assert set(obj["object_marking_refs"]) == definitions
