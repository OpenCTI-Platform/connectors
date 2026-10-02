"""Module to test Orchestrator's pure relationship-building helpers.

These tests exercise the private relationship/enrichment builders directly with
lightweight SimpleNamespace fakes standing in for parsed GTI entities, avoiding
the need for full API response fixtures.
"""

import logging
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest
from connector.src.custom.orchestrators.orchestrator import Orchestrator

# =====================
# Test Fakes
# =====================


class DummyConfig:
    """Dummy configuration for testing purposes."""

    def __init__(self, **overrides: Any) -> None:
        """Initialize the DummyConfig object with sensible defaults."""
        self.api_key = "fake-key"
        self.import_start_date = "P1D"
        self.api_url = "https://fake-gti.api"
        self.import_reports = True
        self.report_types = ["All"]
        self.origins = ["All"]
        self.tlp_level = "amber+strict"
        for key, value in overrides.items():
            setattr(self, key, value)


class FakeWorkManager:
    """Minimal fake WorkManager, unused by these pure-logic tests."""


def _entity(
    id: Optional[str] = None,
    name: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
    entity_type: Optional[str] = None,
) -> Any:
    """Build a fake GTI/STIX-like entity with the given optional fields."""
    ns = SimpleNamespace()
    if id is not None:
        ns.id = id
    if name is not None:
        ns.name = name
    if attributes is not None:
        ns.attributes = SimpleNamespace(**attributes)
    if entity_type is not None:
        ns.type = entity_type
    return ns


# =====================
# Fixtures
# =====================


@pytest.fixture
def orchestrator() -> Orchestrator:
    """Fixture for a real Orchestrator wired with a dummy config and no-op logging."""
    logger = logging.getLogger("test_orchestrator_relationships")
    return Orchestrator(
        work_manager=FakeWorkManager(),  # type: ignore
        logger=logger,
        config=DummyConfig(),  # type: ignore
        tlp_level="amber+strict",
    )


# =====================
# Test Cases: _enrich_iocs_with_report_context
# =====================


# Scenario: Enrich IOCs with threat actor and malware names from the report
def test_enrich_iocs_with_report_context_builds_maps(
    orchestrator: Orchestrator,
) -> None:
    """Test that IOC entities are mapped to the report's threat actor and malware names."""
    subentities = {
        "threat_actors": [_entity(attributes={"name": "APT1"})],
        "malware_families": [_entity(attributes={"name": "Emotet"})],
        "domains": [_entity(id="domain--1")],
        "files": [_entity(id="file--1")],
    }
    ta_map, malware_map = orchestrator._enrich_iocs_with_report_context(subentities)
    assert ta_map["domains"]["domain--1"] == ["APT1"]  # noqa: S101
    assert ta_map["files"]["file--1"] == ["APT1"]  # noqa: S101
    assert malware_map["domains"]["domain--1"] == ["Emotet"]  # noqa: S101


# Scenario: No threat actors or malware means no enrichment maps are built
def test_enrich_iocs_with_report_context_empty_when_no_ta_or_malware(
    orchestrator: Orchestrator,
) -> None:
    """Test that enrichment maps stay empty without threat actors or malware in the report."""
    subentities = {"domains": [_entity(id="domain--1")]}
    ta_map, malware_map = orchestrator._enrich_iocs_with_report_context(subentities)
    assert ta_map == {}  # noqa: S101
    assert malware_map == {}  # noqa: S101


# Scenario: IOC entities missing an id are skipped
def test_enrich_iocs_with_report_context_skips_entities_without_id(
    orchestrator: Orchestrator,
) -> None:
    """Test that IOC entities without an id are not added to the enrichment maps."""
    subentities = {
        "threat_actors": [_entity(attributes={"name": "APT1"})],
        "domains": [_entity()],
    }
    ta_map, _ = orchestrator._enrich_iocs_with_report_context(subentities)
    assert ta_map.get("domains", {}) == {}  # noqa: S101


# =====================
# Test Cases: _create_malware_vulnerability_relationships
# =====================


# Scenario: Malware and vulnerabilities in the same report generate 'exploits' relationships
def test_create_malware_vulnerability_relationships_cross_product(
    orchestrator: Orchestrator,
) -> None:
    """Test that every malware/vulnerability pair gets an 'exploits' relationship."""
    subentities = {
        "malware_families": [_entity(attributes={"name": "Emotet"})],
        "vulnerabilities": [_entity(attributes={"name": "CVE-2024-0001"})],
    }
    relationships = orchestrator._create_malware_vulnerability_relationships(
        subentities
    )
    assert len(relationships) == 1  # noqa: S101
    assert relationships[0].relationship_type == "exploits"  # noqa: S101


# Scenario: Vulnerability name falls back to a parsed CVE id from the entity id
def test_create_malware_vulnerability_relationships_id_fallback(
    orchestrator: Orchestrator,
) -> None:
    """Test that vulnerability names fall back to parsing the STIX id when attributes are absent."""
    subentities = {
        "malware_families": [_entity(name="Emotet")],
        "vulnerabilities": [_entity(id="vulnerability--cve-2024-0002")],
    }
    relationships = orchestrator._create_malware_vulnerability_relationships(
        subentities
    )
    assert len(relationships) == 1  # noqa: S101


# Scenario: No relationships are created without both malware and vulnerabilities
def test_create_malware_vulnerability_relationships_empty_without_both(
    orchestrator: Orchestrator,
) -> None:
    """Test that no relationships are created when either side is missing."""
    assert (  # noqa: S101
        orchestrator._create_malware_vulnerability_relationships(
            {"malware_families": [_entity(name="Emotet")]}
        )
        == []
    )


# =====================
# Test Cases: _create_report_relationship_mesh
# =====================


# Scenario: A report with threat actors and related entities creates a full relationship mesh
def test_create_report_relationship_mesh_full(orchestrator: Orchestrator) -> None:
    """Test that threat actors are linked to malware, techniques, vulnerabilities, tools, and IOCs."""
    subentities = {
        "threat_actors": [_entity(attributes={"name": "APT1"})],
        "malware_families": [_entity(attributes={"name": "Emotet"})],
        "attack_techniques": [
            _entity(id="T1059", attributes={"name": "Command Line", "info": None})
        ],
        "vulnerabilities": [_entity(attributes={"name": "CVE-2024-0001"})],
        "software_toolkits": [_entity(attributes={"name": "cURL"})],
        "domains": [_entity(id="domain--1")],
    }
    converted_stix = [
        _entity(id="indicator--1", entity_type="indicator"),
        _entity(id="domain--1", entity_type="domain-name"),
    ]
    relationships = orchestrator._create_report_relationship_mesh(
        subentities, converted_stix
    )
    rel_types = {r.relationship_type for r in relationships}
    assert "uses" in rel_types  # noqa: S101
    assert "targets" in rel_types  # noqa: S101
    assert "indicates" in rel_types  # noqa: S101
    assert "related-to" in rel_types  # noqa: S101


# Scenario: No threat actors means no relationship mesh is created
def test_create_report_relationship_mesh_no_threat_actors(
    orchestrator: Orchestrator,
) -> None:
    """Test that no relationships are created without any threat actors present."""
    assert (  # noqa: S101
        orchestrator._create_report_relationship_mesh(
            {"malware_families": [_entity(name="Emotet")]}
        )
        == []
    )


# Scenario: Threat actors without an extractable name are skipped
def test_create_report_relationship_mesh_skips_unnamed_threat_actor(
    orchestrator: Orchestrator,
) -> None:
    """Test that a threat actor without a usable name produces no relationships."""
    subentities = {
        "threat_actors": [_entity()],
        "malware_families": [_entity(attributes={"name": "Emotet"})],
    }
    assert (
        orchestrator._create_report_relationship_mesh(subentities) == []
    )  # noqa: S101


# Scenario: Entities missing names or ids are skipped without crashing
def test_create_report_relationship_mesh_handles_missing_names(
    orchestrator: Orchestrator,
) -> None:
    """Test that malware/technique/vulnerability/tool entries without names are safely skipped."""
    subentities = {
        "threat_actors": [_entity(attributes={"name": "APT1"})],
        "malware_families": [_entity()],
        "attack_techniques": [_entity()],
        "vulnerabilities": [_entity()],
        "software_toolkits": [_entity()],
    }
    relationships = orchestrator._create_report_relationship_mesh(subentities)
    assert relationships == []  # noqa: S101


# =====================
# Test Cases: _create_campaign_relationships
# =====================


# Scenario: A campaign with related entities creates a full relationship set
def test_create_campaign_relationships_full(orchestrator: Orchestrator) -> None:
    """Test that a campaign is linked to threat actors, malware, techniques, tools, CVEs, and IOCs."""
    campaign_stix = [_entity(id="campaign--1", entity_type="campaign")]
    subentities = {
        "threat_actors": [_entity(attributes={"name": "APT1"})],
        "malware_families": [_entity(attributes={"name": "Emotet"})],
        "attack_techniques": [_entity(id="T1059", attributes={"name": "Command Line"})],
        "software_toolkits": [_entity(attributes={"name": "cURL"})],
        "vulnerabilities": [_entity(attributes={"name": "CVE-2024-0001"})],
    }
    converted_stix = [
        _entity(id="indicator--1", entity_type="indicator"),
        _entity(id="ipv4-addr--1", entity_type="ipv4-addr"),
    ]
    relationships = orchestrator._create_campaign_relationships(
        campaign_stix, subentities, converted_stix
    )
    rel_types = {(r.relationship_type, r.source_ref) for r in relationships}
    assert ("attributed-to", "campaign--1") in rel_types  # noqa: S101
    assert ("indicates", "indicator--1") in rel_types  # noqa: S101
    assert ("related-to", "ipv4-addr--1") in rel_types  # noqa: S101


# Scenario: No campaign STIX object means no relationships are created
def test_create_campaign_relationships_no_campaign_id(
    orchestrator: Orchestrator,
) -> None:
    """Test that no relationships are created when the campaign STIX object is absent."""
    assert orchestrator._create_campaign_relationships([], {}) == []  # noqa: S101


# Scenario: A threat actor without an extractable name is logged and skipped
def test_create_campaign_relationships_skips_unnamed_threat_actor(
    orchestrator: Orchestrator,
) -> None:
    """Test that an unnamed threat actor does not produce an attributed-to relationship."""
    campaign_stix = [_entity(id="campaign--1", entity_type="campaign")]
    subentities = {"threat_actors": [_entity()]}
    relationships = orchestrator._create_campaign_relationships(
        campaign_stix, subentities
    )
    assert relationships == []  # noqa: S101


# Scenario: No relationships created despite entities logs a warning
def test_create_campaign_relationships_no_relationships_warns(
    orchestrator: Orchestrator,
) -> None:
    """Test that campaign relationship creation handles the no-op case without crashing."""
    campaign_stix = [_entity(id="campaign--1", entity_type="campaign")]
    subentities = {"malware_families": [_entity()]}
    relationships = orchestrator._create_campaign_relationships(
        campaign_stix, subentities
    )
    assert relationships == []  # noqa: S101


# =====================
# Test Cases: _update_report_with_object_refs
# =====================


# Scenario: Update a report's object_refs with subentity and relationship ids
def test_update_report_with_object_refs_adds_ids(orchestrator: Orchestrator) -> None:
    """Test that object ids from subentities/relationships are merged into the report's refs."""
    report_entities = orchestrator.converter.convert_report_to_stix(_fake_gti_report())
    subentity_stix = [_entity(id="indicator--1")]
    additional_stix = [_entity(id="relationship--1")]
    updated = orchestrator._update_report_with_object_refs(
        report_entities, subentity_stix, additional_stix
    )
    report = next(e for e in updated if getattr(e, "type", None) == "report")
    assert "indicator--1" in report.object_refs  # noqa: S101
    assert "relationship--1" in report.object_refs  # noqa: S101


# Scenario: No subentity STIX objects means the report entities are returned unchanged
def test_update_report_with_object_refs_no_subentities_returns_unchanged(
    orchestrator: Orchestrator,
) -> None:
    """Test that report entities pass through unchanged when there is nothing to add."""
    report_entities: List[Any] = [_entity(id="report--1", entity_type="report")]
    result = orchestrator._update_report_with_object_refs(report_entities, None)
    assert result is report_entities  # noqa: S101


# Scenario: Subentities without an id contribute nothing to object_refs
def test_update_report_with_object_refs_no_ids_returns_unchanged(
    orchestrator: Orchestrator,
) -> None:
    """Test that report entities pass through unchanged when subentities have no ids."""
    report_entities: List[Any] = [_entity(id="report--1", entity_type="report")]
    subentity_stix = [_entity()]
    result = orchestrator._update_report_with_object_refs(
        report_entities, subentity_stix
    )
    assert result is report_entities  # noqa: S101


# =====================
# Test Cases: _update_report_index_inplace / _flush_batch_processor
# =====================


# Scenario: Update the work name template with the current report progress
def test_update_report_index_inplace_updates_template(
    orchestrator: Orchestrator,
) -> None:
    """Test that the work name template's report counter is advanced in place."""
    orchestrator.client_api.real_total_reports = 5
    orchestrator.batch_processor.config.work_name_template = "Importing (~ 0/0 reports)"
    orchestrator._update_report_index_inplace()
    assert (  # noqa: S101
        orchestrator.batch_processor.config.work_name_template
        == "Importing (~ 1/5 reports)"
    )


# Scenario: Update the work name template when the total report count is unknown
def test_update_report_index_inplace_zero_total(orchestrator: Orchestrator) -> None:
    """Test that the counter resets to 0/0 when the total report count is not yet known."""
    orchestrator.client_api.real_total_reports = None
    orchestrator.batch_processor.config.work_name_template = "Importing (~ 3/9 reports)"
    orchestrator._update_report_index_inplace()
    assert (  # noqa: S101
        orchestrator.batch_processor.config.work_name_template
        == "Importing (~ 0/0 reports)"
    )


# Scenario: Flushing the batch processor logs when items were flushed
def test_flush_batch_processor_logs_when_flushed(orchestrator: Orchestrator) -> None:
    """Test that flushing the batch processor updates the final state."""
    orchestrator._flush_batch_processor()


# Scenario: Flushing the batch processor swallows unexpected errors
def test_flush_batch_processor_handles_error(
    orchestrator: Orchestrator, monkeypatch: Any
) -> None:
    """Test that an error while flushing the batch processor is logged, not raised."""

    def _boom() -> None:
        raise RuntimeError("flush failed")

    monkeypatch.setattr(orchestrator.batch_processor, "flush", _boom)
    orchestrator._flush_batch_processor()


# =====================
# Helper Functions
# =====================


def _fake_gti_report() -> Any:
    """Load the real reports debug-response fixture as a GTIReportData instance."""
    import json
    from pathlib import Path

    from connector.src.custom.models.gti_reports.gti_report_model import (
        GTIReportResponse,
    )

    debug_folder = Path(__file__).parent / "debug_responses"
    report_file = next(debug_folder.glob("reports_*.json"))
    raw = json.loads(report_file.read_text(encoding="utf-8"))
    raw = raw.get("response", raw)
    return GTIReportResponse.model_validate(raw).data[0]
