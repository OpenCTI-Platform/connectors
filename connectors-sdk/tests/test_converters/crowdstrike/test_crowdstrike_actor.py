# pragma: no cover # Do not compute coverage on test files
"""Offer tests for the CrowdStrike converters."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from connectors_sdk.converters import ConversionError
from connectors_sdk.converters.crowdstrike import (
    CrowdStrikeActorConverter,
    CrowdStrikeActorInput,
    CrowdStrikeEntity,
    CrowdStrikeLocationConverter,
    CrowdStrikeSectorConverter,
)
from connectors_sdk.models import (
    AttackPattern,
    BaseIdentifiedObject,
    Country,
    IntrusionSet,
    Malware,
    OrganizationAuthor,
    Region,
    Relationship,
    Sector,
    TLPMarking,
)

FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.filterwarnings("ignore:Value 'geopolitical'")


def load() -> dict[str, Any]:
    """Load the actor fixture."""
    return json.loads((FIXTURES / "actor_full.json").read_text())  # type: ignore[no-any-return]


def of_type(objects: list[BaseIdentifiedObject], cls: type) -> list[Any]:
    """Return the objects of a type."""
    return [obj for obj in objects if isinstance(obj, cls)]


def relationships(objects: list[BaseIdentifiedObject], kind: str) -> list[Relationship]:
    """Return the relationships of a type."""
    return [r for r in of_type(objects, Relationship) if r.type == kind]


@pytest.fixture
def author() -> OrganizationAuthor:
    """Return the CrowdStrike author."""
    return OrganizationAuthor(name="CrowdStrike")


@pytest.fixture
def markings() -> list[TLPMarking]:
    """Return markings."""
    return [TLPMarking(level="amber")]


@pytest.fixture
def converter(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> CrowdStrikeActorConverter:
    """Return an actor converter."""
    return CrowdStrikeActorConverter(author=author, markings=markings)


@pytest.mark.parametrize(
    ("entity", "expected"),
    [
        ({"slug": "fr", "value": "France"}, (Country, "France")),
        (
            {"slug": "western-europe", "value": "Western Europe"},
            (Region, "Western Europe"),
        ),
        ({"slug": "unknown", "value": "Unknown"}, None),
        ({"slug": None, "value": "France"}, None),
        ({"slug": "fr", "value": None}, None),
    ],
)
def test_location_converter(
    author: OrganizationAuthor,
    markings: list[TLPMarking],
    entity: dict[str, Any],
    expected: tuple[type, str] | None,
) -> None:
    """Test that 2-letter slugs are countries and longer ones regions."""
    converter = CrowdStrikeLocationConverter(author=author, markings=markings)

    result = converter.transform(CrowdStrikeEntity.model_validate(entity))

    assert [(type(obj), obj.name) for obj in result] == (  # type: ignore[attr-defined]
        [expected] if expected else []
    )


def test_location_converter_country_code_alias(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that the country code is kept as an alias."""
    converter = CrowdStrikeLocationConverter(author=author, markings=markings)

    (country,) = converter.transform(CrowdStrikeEntity(slug="fr", value="France"))

    assert isinstance(country, Country)
    assert country.aliases == ["FR"]


def test_sector_converter(
    author: OrganizationAuthor, markings: list[TLPMarking]
) -> None:
    """Test that an industry becomes a sector, and an empty one nothing."""
    converter = CrowdStrikeSectorConverter(author=author, markings=markings)

    assert [s.name for s in converter.transform(CrowdStrikeEntity(value="Energy"))] == [  # type: ignore[attr-defined]
        "Energy"
    ]
    assert converter.transform(CrowdStrikeEntity(value="")) == []


def test_full_actor(converter: CrowdStrikeActorConverter) -> None:
    """Test an actor with origins, targets, TTPs and malware."""
    objects = converter.transform(CrowdStrikeActorInput.model_validate(load()))

    (intrusion_set,) = of_type(objects, IntrusionSet)
    regions = of_type(objects, Region)
    countries = of_type(objects, Country)
    sectors = of_type(objects, Sector)
    attack_patterns = of_type(objects, AttackPattern)
    malware = of_type(objects, Malware)
    assert len(objects) == 47
    # The intrusion set
    assert intrusion_set.name == "SCION SPIDER"
    assert intrusion_set.description == "SCION SPIDER is a test eCrime actor."
    assert intrusion_set.aliases == [
        "SCIONSPIDER",
        "TestRansomware Group",
        "MockCrime",
        "TestCriminal",
    ]
    assert intrusion_set.primary_motivation == "personal-gain"
    assert intrusion_set.secondary_motivations is None
    assert intrusion_set.labels == ["Criminal", "ecrime"]
    assert intrusion_set.first_seen == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert intrusion_set.last_seen == datetime(2022, 1, 1, tzinfo=timezone.utc)
    assert [
        (r.source_name, r.external_id) for r in intrusion_set.external_references or []
    ] == [("CrowdStrike", "123456")]
    # Origins are regions, target countries are countries
    assert [r.name for r in regions] == ["Test Region Alpha", "Mock Continent"]
    assert len(countries) == 6
    assert len(sectors) == 6
    assert {r.target.id for r in relationships(objects, "originates-from")} == {
        r.id for r in regions
    }
    assert {r.target.id for r in relationships(objects, "targets")} == {
        o.id for o in countries + sectors
    }
    # Techniques are deduplicated and malformed ids ignored
    assert [a.mitre_id for a in attack_patterns] == [
        "T1190",
        "T1047",
        "T1059.001",
        "T1059.003",
        "T1059.005",
    ]
    # Used malware is linked with uses, developed malware with authored-by
    assert [m.name for m in malware] == ["TestRansomware", "TestStealer", "TestBuilder"]
    uses = relationships(objects, "uses")
    assert {r.target.id for r in uses} == {o.id for o in attack_patterns + malware}
    assert all(
        (r.start_time, r.stop_time)
        == (intrusion_set.first_seen, intrusion_set.last_seen)
        for r in uses
    )
    assert {
        (r.source.id, r.target.id) for r in relationships(objects, "authored-by")
    } == {
        (m.id, intrusion_set.id)
        for m in malware
        if m.name in {"TestRansomware", "TestBuilder"}
    }


def test_minimal_actor(converter: CrowdStrikeActorConverter) -> None:
    """Test that an actor with only an id, a name and a URL gives the intrusion set."""
    actor = CrowdStrikeActorInput.model_validate(
        {"actor": {"id": 1, "name": "FANCY BEAR", "url": "https://example.com/fb"}}
    )

    (intrusion_set,) = converter.transform(actor)

    assert isinstance(intrusion_set, IntrusionSet)
    assert intrusion_set.description is None
    assert intrusion_set.aliases == ["FANCYBEAR"]
    assert intrusion_set.labels is None
    assert intrusion_set.primary_motivation is None
    assert [r.url for r in intrusion_set.external_references or []] == [
        "https://example.com/fb"
    ]


def test_motivations_mapping(converter: CrowdStrikeActorConverter) -> None:
    """Test the mapping of CrowdStrike motivations to STIX values."""
    payload = load()
    payload["actor"]["motivations"] = [
        {"value": "State-Sponsored"},
        {"value": "criminal"},
        {"value": "Unsupported"},
        {"slug": "no-value"},
    ]

    (intrusion_set,) = of_type(
        converter.transform(CrowdStrikeActorInput.model_validate(payload)), IntrusionSet
    )

    assert intrusion_set.primary_motivation == "geopolitical"
    assert intrusion_set.secondary_motivations == ["personal-gain"]
    assert intrusion_set.labels == [
        "State-Sponsored",
        "criminal",
        "Unsupported",
        "no-value",
        "ecrime",
    ]


@pytest.mark.parametrize(
    ("first", "last", "expected"),
    [
        (1640995200, 1577836800, (2020, 2022)),  # inverted dates are swapped
        (1577836800, 1577836800, (2020, 2020)),  # equal dates are spread by 1 second
        (0, 1577836800, (None, 2020)),  # 0 means unknown
    ],
)
def test_activity_dates(
    converter: CrowdStrikeActorConverter,
    first: int,
    last: int,
    expected: tuple[int | None, int | None],
) -> None:
    """Test that first seen is never later than last seen."""
    payload = load()
    payload["actor"].update(first_activity_date=first, last_activity_date=last)

    (intrusion_set,) = of_type(
        converter.transform(CrowdStrikeActorInput.model_validate(payload)), IntrusionSet
    )

    years = tuple(
        d.year if d else None
        for d in (intrusion_set.first_seen, intrusion_set.last_seen)
    )
    assert years == expected
    if intrusion_set.first_seen and intrusion_set.last_seen:
        assert intrusion_set.first_seen < intrusion_set.last_seen


def test_description_fallbacks(converter: CrowdStrikeActorConverter) -> None:
    """Test that the rich text, then the short description, are used."""
    payload = load()
    payload["actor"]["description"] = ""
    rich_text = CrowdStrikeActorInput.model_validate(payload)
    payload["actor"]["rich_text_description"] = None
    short = CrowdStrikeActorInput.model_validate(payload)

    assert converter.transform(rich_text)[0].description == (  # type: ignore[attr-defined]
        "SCION SPIDER is a test eCrime actor."
    )
    assert converter.transform(short)[0].description == "Test eCrime actor."  # type: ignore[attr-defined]


def test_invalid_actor_raises_conversion_error(
    converter: CrowdStrikeActorConverter,
) -> None:
    """Test that a value rejected by the SDK models raises a ConversionError."""
    actor = CrowdStrikeActorInput.model_validate({"actor": {"id": 1, "name": ""}})

    with pytest.raises(ConversionError, match="Cannot convert actor"):
        converter.transform(actor)


def test_sub_converter_output_carries_parent_context(
    converter: CrowdStrikeActorConverter,
) -> None:
    """Test that every object, including sub-converter output, has the parent context."""
    objects = converter.transform(CrowdStrikeActorInput.model_validate(load()))

    for obj in objects:
        stix = obj.to_stix2_object()
        assert stix["created_by_ref"] == converter.author.id
        assert stix["object_marking_refs"] == [converter.markings[0].id]


def test_determinism(converter: CrowdStrikeActorConverter) -> None:
    """Test that the same actor gives the same ids in the same order."""
    actor = CrowdStrikeActorInput.model_validate(load())

    assert [o.id for o in converter.transform(actor)] == [
        o.id for o in converter.transform(actor)
    ]
