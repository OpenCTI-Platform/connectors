"""Tests that IOC mapper create_relationship() produces relationships with description=None."""

from typing import Any
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_iocs.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.mappers.gti_iocs.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.mappers.gti_iocs.gti_ip_to_stix_ip import (
    GTIIPToSTIXIP,
)
from connector.src.custom.mappers.gti_iocs.gti_url_to_stix_url import (
    GTIUrlToSTIXUrl,
)
from connector.src.custom.models.gti.gti_domain_model import (
    DomainModel,
    GTIDomainData,
)
from connector.src.custom.models.gti.gti_file_model import (
    FileModel,
    GTIFileData,
)
from connector.src.custom.models.gti.gti_ip_addresses_model import (
    GTIIPData,
    IPModel,
)
from connector.src.custom.models.gti.gti_url_model import (
    GTIURLData,
    URLModel,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore

# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


class DomainModelFactory(ModelFactory[DomainModel]):
    """Factory for DomainModel."""

    __model__ = DomainModel


class GTIDomainDataFactory(ModelFactory[GTIDomainData]):
    """Factory for GTIDomainData."""

    __model__ = GTIDomainData
    type = "domain"
    attributes = Use(DomainModelFactory.build)


class IPModelFactory(ModelFactory[IPModel]):
    """Factory for IPModel."""

    __model__ = IPModel


class GTIIPDataFactory(ModelFactory[GTIIPData]):
    """Factory for GTIIPData."""

    __model__ = GTIIPData
    type = "ip_address"
    attributes = Use(IPModelFactory.build)


class URLModelFactory(ModelFactory[URLModel]):
    """Factory for URLModel."""

    __model__ = URLModel


class GTIURLDataFactory(ModelFactory[GTIURLData]):
    """Factory for GTIURLData."""

    __model__ = GTIURLData
    type = "url"
    attributes = Use(URLModelFactory.build)


class FileModelFactory(ModelFactory[FileModel]):
    """Factory for FileModel."""

    __model__ = FileModel


class GTIFileDataFactory(ModelFactory[GTIFileData]):
    """Factory for GTIFileData."""

    __model__ = GTIFileData
    type = "file"
    attributes = Use(FileModelFactory.build)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_organization():
    """Mock organization Identity object."""
    return Identity(  # pylint: disable=W9101
        name="Test Organization",
        identity_class="organization",
    )


@pytest.fixture
def mock_tlp_marking():
    """Mock TLP marking definition object."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def domain_stix_objects(mock_organization, mock_tlp_marking) -> list[Any]:
    """Produce [domain_observable, indicator, relationship] from a domain mapper."""
    domain_data = GTIDomainDataFactory.build(
        id="example.com",
        attributes=DomainModelFactory.build(
            creation_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )
    mapper = GTIDomainToSTIXDomain(
        domain=domain_data, organization=mock_organization, tlp_marking=mock_tlp_marking
    )
    return mapper.to_stix()


@pytest.fixture
def ip_stix_objects(mock_organization, mock_tlp_marking) -> list[Any]:
    """Produce [ip_observable, indicator, relationship] from an IP mapper."""
    ip_data = GTIIPDataFactory.build(
        id="192.168.1.1",
        attributes=IPModelFactory.build(
            last_analysis_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )
    mapper = GTIIPToSTIXIP(
        ip=ip_data, organization=mock_organization, tlp_marking=mock_tlp_marking
    )
    return mapper.to_stix()


@pytest.fixture
def url_stix_objects(mock_organization, mock_tlp_marking) -> list[Any]:
    """Produce [url_observable, indicator, relationship] from a URL mapper."""
    url_data = GTIURLDataFactory.build(
        id="https://example.com/test",
        attributes=URLModelFactory.build(
            url="https://example.com/test",
            first_submission_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )
    mapper = GTIUrlToSTIXUrl(
        url=url_data, organization=mock_organization, tlp_marking=mock_tlp_marking
    )
    return mapper.to_stix()


@pytest.fixture
def file_stix_objects(mock_organization, mock_tlp_marking) -> list[Any]:
    """Produce [file_observable, indicator, relationship] from a file mapper."""
    file_data = GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1=None,
            md5=None,
            first_submission_date=None,
            last_submission_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )
    mapper = GTIFileToSTIXFile(
        file=file_data, organization=mock_organization, tlp_marking=mock_tlp_marking
    )
    return mapper.to_stix()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _then_relationship_has_no_description(relationship) -> None:  # noqa: ANN001
    assert relationship.relationship_type is not None  # noqa: S101
    assert relationship.description is None  # noqa: S101


# ---------------------------------------------------------------------------
# Tests — Domain mapper create_relationship
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_domain_indicates_relationship_has_no_description(domain_stix_objects):
    """Domain create_relationship with IndicatorModel target must produce description=None."""
    # GIVEN — objects from to_stix(): [domain_observable, indicator, ...]
    indicator = domain_stix_objects[1]

    # WHEN — pass indicator as target; src_entity needs created_by_ref/object_marking_refs
    relationship = GTIDomainToSTIXDomain.create_relationship(
        indicator, "indicates", indicator
    )

    # THEN
    assert relationship.relationship_type == "indicates"  # noqa: S101
    _then_relationship_has_no_description(relationship)


@pytest.mark.order(1)
def test_domain_generic_relationship_has_no_description(domain_stix_objects):
    """Domain create_relationship with non-Indicator target must produce description=None."""
    # GIVEN
    domain_observable = domain_stix_objects[0]
    indicator = domain_stix_objects[1]

    # WHEN — use indicator as src (has created_by_ref), domain_observable as target (not IndicatorModel)
    relationship = GTIDomainToSTIXDomain.create_relationship(
        indicator, "related-to", domain_observable
    )

    # THEN
    assert relationship.relationship_type == "related-to"  # noqa: S101
    _then_relationship_has_no_description(relationship)


# ---------------------------------------------------------------------------
# Tests — IP mapper create_relationship
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_ip_indicates_relationship_has_no_description(ip_stix_objects):
    """IP create_relationship with IndicatorModel target must produce description=None."""
    # GIVEN
    indicator = ip_stix_objects[1]

    # WHEN
    relationship = GTIIPToSTIXIP.create_relationship(indicator, "indicates", indicator)

    # THEN
    assert relationship.relationship_type == "indicates"  # noqa: S101
    _then_relationship_has_no_description(relationship)


@pytest.mark.order(1)
def test_ip_generic_relationship_has_no_description(ip_stix_objects):
    """IP create_relationship with non-Indicator target must produce description=None."""
    # GIVEN
    ip_observable = ip_stix_objects[0]
    indicator = ip_stix_objects[1]

    # WHEN
    relationship = GTIIPToSTIXIP.create_relationship(
        indicator, "related-to", ip_observable
    )

    # THEN
    assert relationship.relationship_type == "related-to"  # noqa: S101
    _then_relationship_has_no_description(relationship)


# ---------------------------------------------------------------------------
# Tests — URL mapper create_relationship
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_url_indicates_relationship_has_no_description(url_stix_objects):
    """URL create_relationship with IndicatorModel target must produce description=None."""
    # GIVEN
    indicator = url_stix_objects[1]

    # WHEN
    relationship = GTIUrlToSTIXUrl.create_relationship(
        indicator, "indicates", indicator
    )

    # THEN
    assert relationship.relationship_type == "indicates"  # noqa: S101
    _then_relationship_has_no_description(relationship)


@pytest.mark.order(1)
def test_url_generic_relationship_has_no_description(url_stix_objects):
    """URL create_relationship with non-Indicator target must produce description=None."""
    # GIVEN
    url_observable = url_stix_objects[0]
    indicator = url_stix_objects[1]

    # WHEN
    relationship = GTIUrlToSTIXUrl.create_relationship(
        indicator, "related-to", url_observable
    )

    # THEN
    assert relationship.relationship_type == "related-to"  # noqa: S101
    _then_relationship_has_no_description(relationship)


# ---------------------------------------------------------------------------
# Tests — File mapper create_relationship
# ---------------------------------------------------------------------------


@pytest.mark.order(1)
def test_file_indicates_relationship_has_no_description(file_stix_objects):
    """File create_relationship with IndicatorModel target must produce description=None."""
    # GIVEN
    indicator = file_stix_objects[1]

    # WHEN
    relationship = GTIFileToSTIXFile.create_relationship(
        indicator, "indicates", indicator
    )

    # THEN
    assert relationship.relationship_type == "indicates"  # noqa: S101
    _then_relationship_has_no_description(relationship)


@pytest.mark.order(1)
def test_file_generic_relationship_has_no_description(file_stix_objects):
    """File create_relationship with non-Indicator target must produce description=None."""
    # GIVEN
    file_observable = file_stix_objects[0]
    indicator = file_stix_objects[1]

    # WHEN
    relationship = GTIFileToSTIXFile.create_relationship(
        indicator, "related-to", file_observable
    )

    # THEN
    assert relationship.relationship_type == "related-to"  # noqa: S101
    _then_relationship_has_no_description(relationship)
