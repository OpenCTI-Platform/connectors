"""Test module for GTI_REPORT_LINK_TO_MENTIONED_THREATS on the report orchestrator."""

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from connector.src.custom.mappers import relationship_reasons
from connector.src.custom.orchestrators.report.orchestrator_report import (
    OrchestratorReport,
)

LISTED_ACTOR = "threat-actor--11111111-1111-5111-8111-111111111111"
LINKED_ACTOR = "threat-actor--2930cc24-2abe-59a4-80f4-8a6dec724e65"
LINKED_MALWARE = "malware--4da11b43-e57e-5206-b255-5d8fb388178c"
GUI = "https://www.virustotal.com/gui/collection/"


def _orchestrator(enabled: bool, subentity_types: list[str]) -> OrchestratorReport:
    orchestrator = OrchestratorReport(
        work_manager=MagicMock(),
        logger=logging.getLogger(__name__),
        config=MagicMock(
            report_link_to_mentioned_threats=enabled,
            report_subentities=subentity_types,
        ),
        tlp_level="white",
    )
    orchestrator.client_api = MagicMock()
    orchestrator.client_api.fetch_linked_threats = AsyncMock(
        return_value={
            "threat_actors": [SimpleNamespace(id=LINKED_ACTOR)],
            "malware_families": [SimpleNamespace(id=LINKED_MALWARE)],
        }
    )
    return orchestrator


def _report(analyst_comment: str) -> Any:
    return SimpleNamespace(
        id="report--26-10105329",
        attributes=SimpleNamespace(
            content=f'<a href="{GUI}{LINKED_MALWARE}">X</a>',
            executive_summary=None,
            analyst_comment=analyst_comment,
        ),
    )


def _threat(stix_type: str, stix_id: str, gti_id: str, name: str) -> Any:
    return SimpleNamespace(
        type=stix_type,
        id=stix_id,
        name=name,
        external_references=[SimpleNamespace(url=f"{GUI}{gti_id}")],
    )


@pytest.mark.asyncio
async def test_linked_threats_are_added_to_the_subentities() -> None:
    """Threats linked in the text and not listed by GTI are fetched and added."""
    # Given a report linking a listed actor, another actor and a malware family
    orchestrator = _orchestrator(True, ["threat_actors", "malware_families", "files"])
    report = _report(f"[A]({GUI}{LISTED_ACTOR}) and [B]({GUI}{LINKED_ACTOR})")
    subentities: dict[str, list[Any]] = {
        "threat_actors": [SimpleNamespace(id=LISTED_ACTOR)]
    }

    # When the linked sub-entities are added
    added = await orchestrator._add_linked_subentities(report, subentities)

    # Then only the threats GTI does not list are fetched, for the threat types
    orchestrator.client_api.fetch_linked_threats.assert_awaited_once_with(
        [LINKED_MALWARE, LINKED_ACTOR], ["threat_actors", "malware_families"]
    )
    assert added == {LINKED_ACTOR, LINKED_MALWARE}  # noqa: S101
    assert [t.id for t in subentities["threat_actors"]] == [  # noqa: S101
        LISTED_ACTOR,
        LINKED_ACTOR,
    ]
    assert [t.id for t in subentities["malware_families"]] == [  # noqa: S101
        LINKED_MALWARE
    ]


@pytest.mark.asyncio
async def test_linked_threats_disabled() -> None:
    """Nothing is fetched when GTI_REPORT_LINK_TO_MENTIONED_THREATS is disabled."""
    orchestrator = _orchestrator(False, ["threat_actors"])
    subentities: dict[str, list[Any]] = {}
    added = await orchestrator._add_linked_subentities(
        _report(f"{GUI}{LINKED_ACTOR}"), subentities
    )
    assert added == set()  # noqa: S101
    assert subentities == {}  # noqa: S101
    orchestrator.client_api.fetch_linked_threats.assert_not_awaited()


@pytest.mark.asyncio
async def test_linked_threats_without_threat_subentity_types() -> None:
    """Nothing is fetched when report_subentities has no threat type."""
    orchestrator = _orchestrator(True, ["files", "domains"])
    added = await orchestrator._add_linked_subentities(
        _report(f"{GUI}{LINKED_ACTOR}"), {}
    )
    assert added == set()  # noqa: S101
    orchestrator.client_api.fetch_linked_threats.assert_not_awaited()


@pytest.mark.parametrize("descriptions_enabled", [False, True])
def test_report_is_related_to_the_linked_threats(descriptions_enabled: bool) -> None:
    """The report gets an always described 'related-to' to each linked threat only."""
    # Given a converted report, a linked threat and a threat GTI lists
    relationship_reasons.set_relationship_descriptions(descriptions_enabled)
    orchestrator = _orchestrator(True, ["threat_actors"])
    report = SimpleNamespace(
        type="report", id="report--1", name="ShinyHunters rebranding", object_refs=[]
    )
    linked = _threat("intrusion-set", "intrusion-set--1", LINKED_ACTOR, "UNC6240")
    listed = _threat("intrusion-set", "intrusion-set--2", LISTED_ACTOR, "Listed")

    # When the report is linked to the threats added from its text
    relationships = orchestrator._link_linked_entities(
        [report], [linked, listed], {LINKED_ACTOR}
    )
    relationship_reasons.set_relationship_descriptions(False)

    # Then a single described related-to targets the linked threat
    assert [  # noqa: S101
        (r.source_ref, r.relationship_type, r.target_ref) for r in relationships
    ] == [("report--1", "related-to", "intrusion-set--1")]
    assert relationships[0].description == (  # noqa: S101
        "Inferred by the connector, not stated by GTI: the report 'ShinyHunters "
        "rebranding' links to the intrusion set 'UNC6240' in its text, but GTI does "
        "not list it among the related objects of the report."
    )
    # And the report does not reference it: a relationship from the report that
    # the report references is a cycle the OpenCTI bundle import drops
    assert report.object_refs == []  # noqa: S101
