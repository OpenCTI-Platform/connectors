from datetime import datetime, timezone

import pytest
from connectors_sdk.models import (
    AdministrativeArea,
    AssociatedFile,
    City,
    Country,
    CourseOfAction,
    ExternalReference,
    File,
    Hostname,
    Indicator,
    Individual,
    IPV4Address,
    MediaContent,
    Organization,
    OrganizationAuthor,
    Region,
    Report,
    Sector,
    Sighting,
    System,
    Text,
    Vulnerability,
)
from connectors_sdk.models.enums import CvssSeverity, Reliability

AUTHOR = OrganizationAuthor(name="Example Corp")
COMMON = {
    "author": AUTHOR,
    "external_references": [
        ExternalReference(source_name="example", url="https://example.com")
    ],
    "labels": ["label"],
}
OBSERVABLE = {
    **COMMON,
    "score": 80,
    "description": "Description",
    "create_indicator": True,
    "associated_files": [AssociatedFile(name="file.txt", content=b"content")],
}
INDICATOR = Indicator(
    name="Indicator",
    pattern="[ipv4-addr:value = '1.1.1.1']",
    pattern_type="stix",
    valid_from="2026-01-01T00:00:00Z",
    score=70,
    main_observable_type="IPv4-Addr",
    create_observables=True,
    associated_files=[AssociatedFile(name="file.txt", content=b"content")],
    **COMMON,
)


@pytest.mark.parametrize(
    "model",
    [
        pytest.param(IPV4Address(value="1.1.1.1", **OBSERVABLE), id="ipv4_address"),
        pytest.param(
            File(name="a.txt", additional_names=["b.txt"], **OBSERVABLE), id="file"
        ),
        pytest.param(Hostname(value="example.com", **OBSERVABLE), id="hostname"),
        pytest.param(Text(value="text", **OBSERVABLE), id="text"),
        pytest.param(
            MediaContent(url="https://example.com/a", **OBSERVABLE), id="media_content"
        ),
        pytest.param(INDICATOR, id="indicator"),
        pytest.param(
            Vulnerability(
                name="CVE-2025-0001",
                score=50,
                aliases=["alias"],
                cvss_v3_vector_string="CVSS:3.1/AV:N",
                cvss_v2_vector_string="AV:N/AC:L",
                cvss_v4_vector_string="CVSS:4.0/AV:N",
                cvss_v3_base_severity=CvssSeverity.HIGH,
                **COMMON,
            ),
            id="vulnerability",
        ),
        pytest.param(
            Organization(
                name="Organization",
                organization_type="vendor",
                reliability=Reliability.A,
                aliases=["alias"],
                **COMMON,
            ),
            id="organization",
        ),
        pytest.param(
            Individual(
                name="Individual", reliability=Reliability.A, aliases=["a"], **COMMON
            ),
            id="individual",
        ),
        pytest.param(
            Sector(name="Sector", reliability=Reliability.A, aliases=["a"], **COMMON),
            id="sector",
        ),
        pytest.param(
            System(name="System", reliability=Reliability.A, aliases=["a"], **COMMON),
            id="system",
        ),
        pytest.param(City(name="Paris", aliases=["a"], **COMMON), id="city"),
        pytest.param(Country(name="France", aliases=["a"], **COMMON), id="country"),
        pytest.param(Region(name="Europe", aliases=["a"], **COMMON), id="region"),
        pytest.param(
            AdministrativeArea(name="Area", aliases=["a"], **COMMON),
            id="administrative_area",
        ),
        pytest.param(
            CourseOfAction(name="Course of action", aliases=["a"], **COMMON),
            id="course_of_action",
        ),
        pytest.param(
            Report(
                name="Report",
                publication_date="2025-01-01T12:00:00Z",
                reliability=Reliability.A,
                objects=[AUTHOR],
                **COMMON,
            ),
            id="report",
        ),
        pytest.param(
            Sighting(
                sighting_of=INDICATOR,
                where_sighted=[AUTHOR],
                first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
                last_seen=datetime(2026, 3, 1, tzinfo=timezone.utc),
                qualification=True,
                **COMMON,
            ),
            id="sighting",
        ),
    ],
)
def test_x_opencti_properties_match_their_counterparts(model) -> None:
    """Test that each OpenCTI property has the same value in both of its places.

    During the deprecation period, every model that writes OpenCTI properties must
    write them in the platform layout and as x_opencti_* properties. The models
    build their properties with _merge_stix2_properties, which checks it.
    """
    # Given a model with OpenCTI properties
    # When converting it to a STIX object (the merge checks the properties)
    stix2_object = model.to_stix2_object()
    # Then it has x_opencti_* properties, so the check had something to verify
    assert [key for key in stix2_object if key.startswith("x_opencti_")]
