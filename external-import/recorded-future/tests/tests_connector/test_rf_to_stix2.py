import pytest
from pycti import Identity as PyctiIdentity
from src.rflib.rf_to_stix2 import ENTITY_TYPE_MAPPER
from stix2 import (
    URL,
    AttackPattern,
    Campaign,
    DomainName,
    File,
    Identity,
    Indicator,
    IPv4Address,
    Location,
    Malware,
    Relationship,
    Software,
    ThreatActor,
    Vulnerability,
)


def fake_valid_author():
    return Identity(
        id=PyctiIdentity.generate_id("Fake author", "organization"),
        name="Fake author",
        identity_class="organization",
    )


def fake_valid_markings():
    return "red"


@pytest.mark.parametrize(
    "rf_type, name, created_objs",
    [
        ("IpAddress", "1.1.1.1", [Indicator, IPv4Address, Relationship]),
        (
            "InternetDomainName",
            "http://test.com",
            [Indicator, DomainName, Relationship],
        ),
        ("URL", "test.com", [Indicator, URL, Relationship]),
        (
            "Hash",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            [Indicator, File, Relationship],
        ),
        ("MitreAttackIdentifier", "test mitreattack", [Identity, AttackPattern]),
        ("Company", "test company", [Identity, Identity]),
        ("Person", "test person", [Identity, Identity]),
        ("Organization", "test organization", [Identity, Identity]),
        ("Malware", "test malware", [Identity, Malware]),
        ("CyberVulnerability", "test cybervuln", [Vulnerability]),
        ("Product", "test product", [Software]),
        ("Country", "test country", [Location]),
        ("City", "test city", [Location]),
        ("ProvinceOrState", "test province", [Location]),
        ("Industry", "test industry", [Identity, Identity]),
        ("Operation", "test operation", [Campaign]),
        ("Threat Actor", "test threat actor", [Identity, ThreatActor]),
    ],
)
def test_maps_rf_types_to_the_corresponding_stix_object(rf_type, name, created_objs):
    """testing the correct generation of entities with ENTITY_TYPE_MAPPER"""
    # Given
    author = fake_valid_author()
    tlp = fake_valid_markings()
    rf_object = ENTITY_TYPE_MAPPER[rf_type](name, rf_type, author, tlp)

    # When
    stix_objects = rf_object.to_stix_objects()

    # Then
    for i, stix_obj in enumerate(stix_objects):
        assert isinstance(stix_obj, created_objs[i])
