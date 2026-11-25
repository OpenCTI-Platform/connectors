from unittest.mock import MagicMock

import stix2
from BeaconBeagle import BeaconBeagle, _build_observable_link, _observable_ref
from pycti import AttackPattern, Identity, StixCoreRelationship, Tool

TOOL_ID = Tool.generate_id("CobaltStrike")
AP_ID = AttackPattern.generate_id(
    "Standard Application Layer Protocol", x_mitre_id="T1071"
)
IDENTITY_ID = Identity.generate_id("BeaconBeagle", "organization")
MARKING = stix2.TLP_WHITE.id
START_TIME = "2026-11-05T10:00:00.000Z"
IPV4 = stix2.IPv4Address(value="198.51.100.7")


def _link(observable, target_id):
    return _build_observable_link(
        observable,
        target_id,
        IDENTITY_ID,
        START_TIME,
        MARKING,
        "Was used by CobaltStrike. (Link ObsTool)",
    )


def test_tool_link_has_the_observable_as_source():
    relation = _link(IPV4, TOOL_ID)

    assert relation.relationship_type == "related-to"
    assert relation.source_ref == IPV4.id
    assert relation.target_ref == TOOL_ID


def test_attack_pattern_link_has_the_observable_as_source():
    relation = _link(IPV4, AP_ID)

    assert relation.source_ref == IPV4.id
    assert relation.target_ref == AP_ID


def test_link_id_follows_the_observable_to_tool_direction():
    relation = _link(IPV4, TOOL_ID)

    assert relation.id == StixCoreRelationship.generate_id(
        "related-to", IPV4.id, TOOL_ID, start_time=START_TIME
    )
    assert relation.id != StixCoreRelationship.generate_id(
        "related-to", TOOL_ID, IPV4.id, start_time=START_TIME
    )


def test_observable_read_from_opencti_uses_its_standard_id():
    observable = {
        "id": "a1b2c3d4-0000-4000-8000-000000000000",
        "standard_id": IPV4.id,
        "value": "198.51.100.7",
    }

    assert _observable_ref(observable) == IPV4.id
    relation = _link(observable, TOOL_ID)
    assert relation.source_ref == IPV4.id
    assert relation.target_ref == TOOL_ID


def test_link_keeps_author_marking_and_start_time():
    relation = _link(IPV4, TOOL_ID)

    assert relation.created_by_ref == IDENTITY_ID
    assert relation.object_marking_refs == [MARKING]
    assert relation.start_time == stix2.utils.parse_into_datetime(START_TIME)


def _connector(tool_id=TOOL_ID, ap_id=AP_ID):
    connector = BeaconBeagle.__new__(BeaconBeagle)
    connector.helper = MagicMock()
    connector.beaconbeagle_link_tool = "CobaltStrike"
    connector.beaconbeagle_link_tool_id = tool_id
    connector.beaconbeagle_link_ap = "Standard Application Layer Protocol"
    connector.beaconbeagle_link_ap_id = ap_id
    connector.beaconbeagle_marking = MARKING
    return connector


def test_link_observables_links_every_observable_to_tool_and_attack_pattern():
    domain = stix2.DomainName(value="beacon.example.org")
    read_back = {"id": "a1b2", "standard_id": IPV4.id, "name": "read back"}

    links = _connector().link_observables(
        [IPV4, domain, read_back], IDENTITY_ID, START_TIME
    )

    assert [(link.source_ref, link.target_ref) for link in links] == [
        (IPV4.id, TOOL_ID),
        (IPV4.id, AP_ID),
        (domain.id, TOOL_ID),
        (domain.id, AP_ID),
        (IPV4.id, TOOL_ID),
        (IPV4.id, AP_ID),
    ]
    assert "(Link ObsTool)" in links[0].description
    assert "(Link ObsAttackPattern)" in links[1].description


def test_link_observables_without_tool_or_attack_pattern_writes_nothing():
    links = _connector(tool_id=None, ap_id=None).link_observables(
        [IPV4], IDENTITY_ID, START_TIME
    )

    assert links == []


def test_link_observables_logs_and_skips_an_observable_without_id():
    connector = _connector()

    links = connector.link_observables(
        [{"value": "no id"}, IPV4], IDENTITY_ID, START_TIME
    )

    assert [(link.source_ref, link.target_ref) for link in links] == [
        (IPV4.id, TOOL_ID),
        (IPV4.id, AP_ID),
    ]
    assert connector.helper.connector_logger.error.call_count == 2
