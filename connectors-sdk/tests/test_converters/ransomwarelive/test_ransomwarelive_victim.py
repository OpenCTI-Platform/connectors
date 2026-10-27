# pragma: no cover # Do not compute coverage on test files
"""Offer tests for RansomwareLiveVictimConverter."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from connectors_sdk.converters import ConversionError
from connectors_sdk.converters.ransomwarelive import (
    RansomwareLiveVictimConverter,
    RansomwareLiveVictimInput,
)
from connectors_sdk.models import (
    BaseIdentifiedObject,
    Country,
    DomainName,
    Individual,
    IntrusionSet,
    Organization,
    OrganizationAuthor,
    Relationship,
    Report,
    Sector,
    TLPMarking,
)
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures"
pytestmark = pytest.mark.filterwarnings("ignore:Value 'Ransomware-report'")


def load(name: str) -> dict[str, Any]:
    """Load a JSON fixture."""
    return json.loads((FIXTURES / name).read_text())  # type: ignore[no-any-return]


def make_input(payload: dict[str, Any]) -> RansomwareLiveVictimInput:
    """Validate a payload."""
    return RansomwareLiveVictimInput.model_validate(payload)


@pytest.fixture
def converter() -> RansomwareLiveVictimConverter:
    """Return a converter with default flags."""
    return RansomwareLiveVictimConverter(
        author=OrganizationAuthor(name="Ransomware.Live"),
        markings=[TLPMarking(level="clear")],
    )


def of_type(objects: list[BaseIdentifiedObject], cls: type) -> list[Any]:
    """Return the objects of a type."""
    return [obj for obj in objects if isinstance(obj, cls)]


def relationships(objects: list[BaseIdentifiedObject]) -> set[tuple[str, str, str]]:
    """Return (type, source id, target id) of every relationship."""
    return {(r.type, r.source.id, r.target.id) for r in of_type(objects, Relationship)}


def test_full_victim(converter: RansomwareLiveVictimConverter) -> None:
    """Test a victim with group, sector, domain and country."""
    objects = converter.transform(make_input(load("victim_full.json")))

    (victim,) = of_type(objects, Organization)
    (intrusion_set,) = of_type(objects, IntrusionSet)
    (sector,) = of_type(objects, Sector)
    (domain,) = of_type(objects, DomainName)
    (country,) = of_type(objects, Country)
    (report,) = of_type(objects, Report)
    assert victim.name == "Acme Industries"
    assert sector.name == "Manufacturing"
    assert domain.value == "www.acme-industries.example.com"
    assert country.name == "France"
    # The intrusion set comes from the group entry
    assert intrusion_set.name == "akira"
    assert intrusion_set.description.startswith("Akira is")
    assert intrusion_set.aliases == ["Akira Ransomware"]
    assert intrusion_set.labels == ["ransomware"]
    assert [r.url for r in intrusion_set.external_references or []] == [
        "https://www.ransomware.live/group/akira"
    ]
    # The relationships link the graph
    assert relationships(objects) == {
        ("targets", intrusion_set.id, victim.id),
        ("part-of", victim.id, sector.id),
        ("targets", intrusion_set.id, sector.id),
        ("belongs-to", domain.id, victim.id),
        ("targets", intrusion_set.id, country.id),
        ("located-at", victim.id, country.id),
    }
    # Dated relationships use the attack and discovery dates, read as UTC
    targets = [r for r in of_type(objects, Relationship) if r.type == "targets"]
    assert {r.start_time for r in targets} == {
        datetime(2025, 1, 1, 7, 20, 50, tzinfo=timezone.utc)
    }
    # The report references every other object
    assert report.name == "akira has published a new victim: Acme Industries"
    assert report.publication_date == datetime(
        2025, 1, 1, 7, 20, 50, tzinfo=timezone.utc
    )
    assert {obj.id for obj in report.objects or []} == {
        obj.id for obj in objects if obj is not report
    }
    assert [r.url for r in report.external_references or []] == [
        "https://images.ransomware.live/victims/acme.png",
        "https://acme-industries.example.com",
    ]


def test_minimal_victim(converter: RansomwareLiveVictimConverter) -> None:
    """Test a victim with only a name, a group and an attack date."""
    objects = converter.transform(make_input(load("victim_minimal.json")))

    assert [type(obj).__name__ for obj in objects] == [
        "Organization",
        "IntrusionSet",
        "Relationship",
        "Report",
    ]
    intrusion_set = objects[1]
    assert isinstance(intrusion_set, IntrusionSet)
    # LockBit variants are merged into one intrusion set
    assert intrusion_set.name == "lockbit"
    assert intrusion_set.description == "No description available"
    assert intrusion_set.aliases is None
    assert intrusion_set.external_references is None
    report = objects[3]
    assert isinstance(report, Report)
    assert report.external_references is None


def test_leak_references_flags() -> None:
    """Test that leak-site and leak-post references are opt-in."""
    converter = RansomwareLiveVictimConverter(
        author=OrganizationAuthor(name="Ransomware.Live"),
        markings=[],
        include_leak_site_references=True,
        include_leak_post_references=True,
    )
    payload = load("victim_full.json")
    payload["group"]["locations"].append({"slug": "http://akiraleak.onion"})

    objects = converter.transform(make_input(payload))

    (intrusion_set,) = of_type(objects, IntrusionSet)
    assert [
        (r.url, r.description) for r in intrusion_set.external_references or []
    ] == [
        (
            "https://www.ransomware.live/group/akira",
            "ransomware.live group profile page",
        ),
        ("http://akiraleak.onion", "Leak site: Akira leak site"),
        ("http://akira2.onion", "Leak site: Leak site"),
    ]
    (report,) = of_type(objects, Report)
    assert "http://akiraleak.onion/post/acme" in [
        r.url for r in report.external_references or []
    ]


@pytest.mark.parametrize(
    ("victim", "domain", "expected"),
    [
        ("acme.example.com", "https://other.example.org", "acme.example.com"),
        ("Acme", "acme.example.com​", "acme.example.com"),
        ("Acme", "http://acme.example.com:8080/path", "acme.example.com"),
        ("Acme", "acme.example.com/path", "acme.example.com"),
        ("Acme", "not a domain", None),
        ("Acme", "", None),
        ("Acme", None, None),
    ],
)
def test_domain_detection(
    converter: RansomwareLiveVictimConverter,
    victim: str,
    domain: str | None,
    expected: str | None,
) -> None:
    """Test how the victim domain name is found."""
    payload = load("victim_minimal.json")
    payload["victim"].update(victim=victim, domain=domain)

    objects = converter.transform(make_input(payload))

    assert [d.value for d in of_type(objects, DomainName)] == (
        [expected] if expected else []
    )


def test_short_names(converter: RansomwareLiveVictimConverter) -> None:
    """Test that short victim and group names still give valid objects."""
    payload = load("victim_minimal.json")
    payload["victim"].update(victim="AB", group="x")
    payload["group"] = {"name": "x", "description": "null", "altname": " "}

    objects = converter.transform(make_input(payload))

    (victim,) = of_type(objects, Individual)
    (intrusion_set,) = of_type(objects, IntrusionSet)
    assert victim.name == "AB:<)"
    assert intrusion_set.name == "x "
    assert intrusion_set.description == "No description available"
    assert intrusion_set.aliases is None


def test_unknown_sector_is_skipped(converter: RansomwareLiveVictimConverter) -> None:
    """Test that the 'Not Found' activity gives no sector."""
    payload = load("victim_minimal.json")
    payload["victim"]["activity"] = "Not Found"

    assert of_type(converter.transform(make_input(payload)), Sector) == []


def test_validation_error_raises_conversion_error(
    converter: RansomwareLiveVictimConverter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that a model validation error is wrapped in a ConversionError."""
    with pytest.raises(ValidationError) as validation_error:
        Sector(name="")

    def fail(*_: Any) -> None:
        raise validation_error.value

    monkeypatch.setattr(converter, "_convert", fail)
    with pytest.raises(ConversionError, match="Globex"):
        converter.transform(make_input(load("victim_minimal.json")))


def test_determinism_and_context(converter: RansomwareLiveVictimConverter) -> None:
    """Test that ids are stable and every object carries author and markings."""
    victim_input = make_input(load("victim_full.json"))

    first = converter.transform(victim_input)
    second = converter.transform(victim_input)

    assert [o.id for o in first] == [o.id for o in second]
    for obj in first:
        stix = obj.to_stix2_object()
        created_by = stix.get("created_by_ref") or stix.get("x_opencti_created_by_ref")
        assert created_by == converter.author.id
        assert stix["object_marking_refs"] == [converter.markings[0].id]
