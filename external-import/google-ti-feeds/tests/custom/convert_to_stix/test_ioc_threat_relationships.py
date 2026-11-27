"""Tests for the IOC to threat co-occurrence relationships of reports and campaigns."""

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from connector.src.custom.convert_to_stix.convert_to_stix_base import (
    ioc_threat_relationship_types,
)
from connector.src.custom.convert_to_stix.report.convert_to_stix_report import (
    ConvertToSTIXReport,
)
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)

INTRUSION_SET_ID = "intrusion-set--00000000-0000-4000-8000-000000000001"
MALWARE_ID = "malware--00000000-0000-4000-8000-000000000002"
CAMPAIGN_ID = "campaign--00000000-0000-4000-8000-000000000003"
INDICATOR_ID = "indicator--00000000-0000-4000-8000-000000000004"
DOMAIN_ID = "domain-name--00000000-0000-4000-8000-000000000005"
TOOL_ID = "tool--00000000-0000-4000-8000-000000000006"


def _obj(stix_type: str, stix_id: str) -> Any:
    return SimpleNamespace(type=stix_type, id=stix_id)


@pytest.fixture
def converter() -> ConvertToSTIXReport:
    """Return a report converter."""
    return ConvertToSTIXReport(
        config=MagicMock(), logger=logging.getLogger(__name__), tlp_level="white"
    )


@pytest.fixture
def report_subentities() -> list[Any]:
    """Return converted sub-entities of a report."""
    return [
        _obj("intrusion-set", INTRUSION_SET_ID),
        _obj("malware", MALWARE_ID),
        _obj("campaign", CAMPAIGN_ID),
        _obj("tool", TOOL_ID),
        _obj("indicator", INDICATOR_ID),
        _obj("domain-name", DOMAIN_ID),
        _obj("relationship", "relationship--1"),
    ]


def test_iocs_are_linked_to_every_threat(
    converter: ConvertToSTIXReport, report_subentities: list[Any]
) -> None:
    """Indicators indicate and observables relate to each threat."""
    # Given the converted sub-entities of a report
    # When IOC to threat relationships are created
    relationships = converter.create_co_occurrence_relationships(
        report_subentities,
        ioc_threat_relationship_types(("intrusion-set", "malware", "campaign")),
    )
    # Then each IOC is linked to each threat with the matching type
    links = {(r.source_ref, r.relationship_type, r.target_ref) for r in relationships}
    assert links == {  # noqa: S101
        (INDICATOR_ID, "indicates", INTRUSION_SET_ID),
        (INDICATOR_ID, "indicates", MALWARE_ID),
        (INDICATOR_ID, "indicates", CAMPAIGN_ID),
        (DOMAIN_ID, "related-to", INTRUSION_SET_ID),
        (DOMAIN_ID, "related-to", MALWARE_ID),
        (DOMAIN_ID, "related-to", CAMPAIGN_ID),
    }
    assert len(relationships) == 6  # noqa: S101


def test_relationships_carry_author_and_marking(
    converter: ConvertToSTIXReport, report_subentities: list[Any]
) -> None:
    """Relationships are authored by GTI, marked, and have deterministic IDs."""
    # Given the converted sub-entities of a report
    # When IOC to threat relationships are created twice
    first = converter.create_co_occurrence_relationships(
        report_subentities, ioc_threat_relationship_types(("malware",))
    )
    second = converter.create_co_occurrence_relationships(
        report_subentities, ioc_threat_relationship_types(("malware",))
    )
    # Then they reference the author and marking and keep the same IDs
    for relationship in first:
        assert relationship.created_by_ref == converter.organization.id  # noqa: S101
        assert relationship.object_marking_refs == [  # noqa: S101
            converter.tlp_marking.id
        ]
    assert [r.id for r in first] == [r.id for r in second]  # noqa: S101


def test_no_relationship_without_threat(converter: ConvertToSTIXReport) -> None:
    """IOCs alone produce no relationship."""
    # Given a report with IOCs and no threat
    stix_objects = [_obj("indicator", INDICATOR_ID), _obj("domain-name", DOMAIN_ID)]
    # When IOC to threat relationships are created
    relationships = converter.create_co_occurrence_relationships(
        stix_objects, ioc_threat_relationship_types(("intrusion-set", "malware"))
    )
    # Then none is created
    assert relationships == []  # noqa: S101


def test_report_orchestrator_adds_relationships_to_report(
    report_subentities: list[Any],
) -> None:
    """The relationships are added to the report object_refs."""
    # Given a report orchestrator and a converted report
    orchestrator = OrchestratorReport(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=MagicMock(
            ioc_link_to_threats=True, intrusion_set_link_to_capabilities=False
        ),
        tlp_level="white",
    )
    report = SimpleNamespace(type="report", id="report--1", object_refs=[])
    # When co-occurring entities are linked
    relationships = orchestrator._link_co_occurring_entities(
        [report], report_subentities
    )
    # Then the report references every relationship
    assert report.object_refs == [r.id for r in relationships]  # noqa: S101
    assert len(relationships) == 6  # noqa: S101


def test_report_orchestrator_without_enabled_links(
    report_subentities: list[Any],
) -> None:
    """No relationship is created when every link option is disabled."""
    # Given a report orchestrator with the link options disabled
    orchestrator = OrchestratorReport(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=MagicMock(
            ioc_link_to_threats=False, intrusion_set_link_to_capabilities=False
        ),
        tlp_level="white",
    )
    report = SimpleNamespace(type="report", id="report--1", object_refs=[])
    # When co-occurring entities are linked
    relationships = orchestrator._link_co_occurring_entities(
        [report], report_subentities
    )
    # Then nothing is created
    assert relationships == []  # noqa: S101
    assert report.object_refs == []  # noqa: S101
