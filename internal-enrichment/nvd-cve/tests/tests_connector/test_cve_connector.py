"""Tests for CVEConnector internal enrichment message processing and CVE extraction."""

import json
from unittest.mock import AsyncMock, MagicMock

from src.connector.cve_connector import CVEConnector
from src.services.converter.vulnerability_to_stix2 import CVEConverter
from src.services.utils.cve_extractor import extract_cve_ids, extract_cves_from_entity
from tests.conftest import make_cpe_name, make_vulnerability


def _make_enrichment_connector(
    *,
    max_tlp: str = "TLP:AMBER",
    create_relationships: bool = True,
    create_unmatched_cve: bool = True,
    import_software: bool = False,
) -> CVEConnector:
    connector = object.__new__(CVEConnector)
    connector.max_tlp = max_tlp

    mock_config = MagicMock()
    mock_config.connector.max_tlp = max_tlp
    mock_config.connector.scope = ["Report", "Vulnerability", "Case-Incident", "Note"]
    mock_config.cve.create_relationships = create_relationships
    mock_config.cve.create_unmatched_cve = create_unmatched_cve
    mock_config.cve.import_software = import_software
    mock_config.cve.max_cves_per_entity = 100
    connector.config = mock_config

    mock_helper = MagicMock()
    mock_helper.connector_logger = MagicMock()
    mock_helper.check_max_tlp.side_effect = lambda tlp, max_t: (
        False if tlp == "TLP:RED" and max_t != "TLP:RED" else True
    )
    mock_helper.stix2_create_bundle.side_effect = lambda objs: json.dumps(
        {"type": "bundle", "objects": objs}
    )
    mock_helper.send_stix2_bundle.return_value = ["bundle-1"]
    connector.helper = mock_helper

    converter = object.__new__(CVEConverter)
    converter.helper = mock_helper
    converter.import_software = import_software
    converter.cpe_max_concurrency = 4
    converter.cve_max_concurrency = 8
    converter.cpe_history_interval = None
    converter.create_unmatched_cve = create_unmatched_cve
    converter.author = CVEConverter._create_author()
    converter._rate_limiter = MagicMock()
    converter.client_api = MagicMock()
    converter.client_api.close = AsyncMock()
    converter.cpe_match_client = MagicMock()
    converter.cpe_match_client.close = AsyncMock()

    connector.converter = converter
    return connector


def test_extract_cve_ids_matches_standard_and_defanged_cves():
    text = (
        "Critical advisories for CVE-2024-3400, cve-2021-44228, "
        "and defanged CVE[-]2023[-]12345 or CVE_2022_0001. "
        "Duplicate CVE-2024-3400 should only appear once. "
        "Invalid CVE-2024-123 (too short) should be ignored."
    )
    extracted = extract_cve_ids(text)
    assert extracted == [
        "CVE-2024-3400",
        "CVE-2021-44228",
        "CVE-2023-12345",
        "CVE-2022-0001",
    ]


def test_extract_cves_from_entity_combines_name_description_and_content():
    stix_entity = {
        "type": "report",
        "name": "Advisory for CVE-2024-1111",
        "description": "Exploitation of CVE-2024-2222 observed in the wild.",
        "x_opencti_content": "<p>Patch CVE-2024-3333 and CVE-2024-1111 immediately.</p>",
    }
    enrichment_entity = {
        "content": "Additional note mentioning CVE-2024-4444.",
    }

    extracted = extract_cves_from_entity(stix_entity, enrichment_entity)
    assert extracted == [
        "CVE-2024-1111",
        "CVE-2024-2222",
        "CVE-2024-3333",
        "CVE-2024-4444",
    ]


def test_process_message_enriches_report_container_with_nvd_data():
    connector = _make_enrichment_connector(import_software=True)

    # Mock NVD responses for CVE-2024-3400 (found) and CVE-2024-9999 (unmatched -> placeholder)
    async def fake_get_vuln_by_id(cve_id: str, *, raise_on_error: bool = False):
        if cve_id == "CVE-2024-3400":
            return make_vulnerability("CVE-2024-3400")
        return None

    async def fake_get_cpes(cve_id: str, request_params=None):
        return [make_cpe_name("paloaltonetworks", "pan-os", "11.1")]

    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        side_effect=fake_get_vuln_by_id
    )
    connector.converter.cpe_match_client.get_cpes_for_cve = AsyncMock(
        side_effect=fake_get_cpes
    )

    report_stix = {
        "id": "report--11111111-2222-3333-4444-555555555555",
        "type": "report",
        "name": "Threat Report on CVE-2024-3400",
        "description": "Also tracks emerging CVE-2024-9999.",
        "object_refs": ["indicator--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"],
    }
    data = {
        "entity_id": report_stix["id"],
        "stix_entity": report_stix,
        "stix_objects": [report_stix],
        "enrichment_entity": {
            "entity_type": "Report",
            "parent_types": [
                "Basic-Object",
                "Stix-Object",
                "Stix-Domain-Object",
                "Container",
            ],
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:GREEN"}],
        },
    }

    status = connector.process_message(data)
    assert "Enriched 2 CVE(s)" in status

    # Verify bundle sent
    assert connector.helper.send_stix2_bundle.call_count == 1
    sent_bundle_raw = connector.helper.send_stix2_bundle.call_args.kwargs["bundle"]
    sent_bundle = json.loads(sent_bundle_raw)
    objects = sent_bundle["objects"]

    vulns = [o for o in objects if o["type"] == "vulnerability"]
    assert len(vulns) == 2

    vuln_by_name = {v["name"]: v for v in vulns}
    assert vuln_by_name["CVE-2024-3400"]["x_opencti_base_score"] == 7.5
    assert (
        vuln_by_name["CVE-2024-3400"]["description"] == "Description of CVE-2024-3400"
    )
    assert "confidence" not in vuln_by_name["CVE-2024-9999"]

    # Verify software and 'has' relationship + 2 'related-to' container relationships
    software = [o for o in objects if o["type"] == "software"]
    assert len(software) == 1

    rels = [o for o in objects if o["type"] == "relationship"]
    has_rels = [r for r in rels if r["relationship_type"] == "has"]
    related_rels = [r for r in rels if r["relationship_type"] == "related-to"]
    assert len(has_rels) == 1
    assert len(related_rels) == 2

    # Verify report's object_refs includes both vulnerabilities, software, and relationships
    reports = [o for o in objects if o["type"] == "report"]
    assert len(reports) == 1
    report_refs = set(reports[0]["object_refs"])
    for v in vulns:
        assert v["id"] in report_refs
    assert software[0]["id"] in report_refs


def test_process_message_enriches_vulnerability_entity_directly():
    connector = _make_enrichment_connector()

    connector.converter.client_api.get_vulnerability_by_id = AsyncMock(
        return_value=make_vulnerability("CVE-2024-3400")
    )

    vuln_stix = {
        "id": "vulnerability--11111111-2222-3333-4444-555555555555",
        "type": "vulnerability",
        "name": "CVE-2024-3400",
    }
    data = {
        "entity_id": vuln_stix["id"],
        "stix_entity": vuln_stix,
        "stix_objects": [vuln_stix],
        "enrichment_entity": {
            "entity_type": "Vulnerability",
            "parent_types": ["Basic-Object", "Stix-Object", "Stix-Domain-Object"],
            "objectMarking": [],
        },
    }

    status = connector.process_message(data)
    assert "Enriched 1 CVE(s)" in status

    sent_bundle_raw = connector.helper.send_stix2_bundle.call_args.kwargs["bundle"]
    sent_bundle = json.loads(sent_bundle_raw)
    objects = sent_bundle["objects"]

    vulns = [o for o in objects if o["type"] == "vulnerability"]
    assert any(v.get("x_opencti_base_score") == 7.5 for v in vulns)
    # Direct vulnerability enrichment should not create self-relationships
    rels = [o for o in objects if o["type"] == "relationship"]
    assert len(rels) == 0


def test_process_message_skips_when_tlp_exceeds_max_tlp():
    connector = _make_enrichment_connector(max_tlp="TLP:AMBER")

    report_stix = {
        "id": "report--11111111-2222-3333-4444-555555555555",
        "type": "report",
        "name": "Red Report on CVE-2024-3400",
    }
    data = {
        "entity_id": report_stix["id"],
        "stix_entity": report_stix,
        "stix_objects": [report_stix],
        "enrichment_entity": {
            "entity_type": "Report",
            "objectMarking": [{"definition_type": "TLP", "definition": "TLP:RED"}],
        },
    }

    status = connector.process_message(data)
    assert "exceeds max TLP" in status
    connector.converter.client_api.get_vulnerability_by_id.assert_not_called()
    # Original bundle is still forwarded for playbook continuity
    assert connector.helper.send_stix2_bundle.call_count == 1
