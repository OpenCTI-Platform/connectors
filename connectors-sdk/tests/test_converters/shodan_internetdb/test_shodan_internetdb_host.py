# pragma: no cover # Do not compute coverage on test files
"""Offer tests for ShodanInternetDbHostConverter."""

from pathlib import Path

import pytest
from connectors_sdk.converters.shodan_internetdb import (
    ShodanInternetDbHostConverter,
    ShodanInternetDbHostInput,
    ShodanInternetDbResult,
)
from connectors_sdk.models import (
    DomainName,
    IPV4Address,
    Note,
    OrganizationAuthor,
    Relationship,
    TLPMarking,
    Vulnerability,
)
from freezegun import freeze_time

FIXTURES = Path(__file__).parent / "fixtures"
IP = "198.51.100.7"


@pytest.fixture
def converter() -> ShodanInternetDbHostConverter:
    """Return a converter."""
    return ShodanInternetDbHostConverter(
        author=OrganizationAuthor(name="Shodan"),
        markings=[TLPMarking(level="clear")],
    )


@pytest.fixture
def host_input() -> ShodanInternetDbHostInput:
    """Return the enrichment input built from the fixture."""
    result = ShodanInternetDbResult.model_validate_json(
        (FIXTURES / "internetdb_result.json").read_text()
    )
    return ShodanInternetDbHostInput(observable_value=IP, result=result)


def test_full_result(
    converter: ShodanInternetDbHostConverter, host_input: ShodanInternetDbHostInput
) -> None:
    """Test the objects produced from a result with every field."""
    observable_id = IPV4Address(value=IP).id

    result = converter.transform(host_input)

    domains = [obj for obj in result if isinstance(obj, DomainName)]
    vulnerabilities = [obj for obj in result if isinstance(obj, Vulnerability)]
    relationships = [obj for obj in result if isinstance(obj, Relationship)]
    observables = [obj for obj in result if isinstance(obj, IPV4Address)]
    notes = [obj for obj in result if isinstance(obj, Note)]
    assert len(result) == 8
    # One domain name per hostname, resolving to the observable
    assert [d.value for d in domains] == ["dns.example.com", "example.com"]
    assert all([r.id for r in d.resolves_to or []] == [observable_id] for d in domains)
    # One vulnerability per CVE, related to the observable
    assert [v.name for v in vulnerabilities] == ["CVE-2023-38408", "CVE-2021-41617"]
    assert [(r.type, r.source.id, r.target.id) for r in relationships] == [
        ("related-to", observable_id, v.id) for v in vulnerabilities
    ]
    # The observable carries the tags as labels
    assert [(o.id, o.labels) for o in observables] == [
        (observable_id, ["cloud", "self-signed"])
    ]
    # One note attached to the observable
    (note,) = notes
    assert [obj.id for obj in note.objects or []] == [observable_id]
    assert note.abstract == f"Shodan InternetDB enrichment of {IP}"
    assert "\n- cpe:/a:nginx:nginx" in note.content
    assert "\n- 443" in note.content


def test_empty_result(converter: ShodanInternetDbHostConverter) -> None:
    """Test that an empty result only produces the note."""
    result = ShodanInternetDbResult(
        cpes=[], hostnames=[], ip=IP, ports=[], tags=[], vulns=[]
    )

    objects = converter.transform(
        ShodanInternetDbHostInput(observable_value=IP, result=result)
    )

    assert len(objects) == 1
    assert isinstance(objects[0], Note)
    assert objects[0].content.count("n/a") == 4


def test_determinism_across_runs(
    converter: ShodanInternetDbHostConverter, host_input: ShodanInternetDbHostInput
) -> None:
    """Test that the ids do not depend on the conversion date."""
    with freeze_time("2026-10-01"):
        first = [obj.id for obj in converter.transform(host_input)]
    with freeze_time("2026-12-01"):
        second = [obj.id for obj in converter.transform(host_input)]

    assert first == second


def test_author_and_markings(
    converter: ShodanInternetDbHostConverter, host_input: ShodanInternetDbHostInput
) -> None:
    """Test that every object references the author and markings."""
    for obj in converter.transform(host_input):
        stix = obj.to_stix2_object()
        created_by = stix.get("created_by_ref") or stix.get("x_opencti_created_by_ref")
        assert created_by == converter.author.id
        assert stix["object_marking_refs"] == [converter.markings[0].id]
