"""Tests for the GTIReportToSTIXIdentity mapper."""

from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_identity import (
    GTIReportToSTIXIdentity,
)
from connector.src.custom.models.gti_reports.gti_report_model import (
    GTIReportData,
    Links,
    ReportModel,
)
from connector.src.stix.v21.models.sdos.identity_model import IdentityModel
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


class LinksFactory(ModelFactory[Links]):
    """Factory for Links model."""

    __model__ = Links


class ReportModelFactory(ModelFactory[ReportModel]):
    """Factory for ReportModel."""

    __model__ = ReportModel


class GTIReportDataFactory(ModelFactory[GTIReportData]):
    """Factory for GTIReportData."""

    __model__ = GTIReportData

    type = "report"
    attributes = Use(ReportModelFactory.build)


@pytest.fixture
def mock_organization():
    """Mock organization Identity object."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
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
def report_with_author() -> GTIReportData:
    """Fixture for GTI report with author information."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(author="Security Research Team")
    )


@pytest.fixture
def report_with_short_author() -> GTIReportData:
    """Fixture for GTI report with short author name."""
    return GTIReportDataFactory.build(attributes=ReportModelFactory.build(author="AI"))


@pytest.fixture
def report_without_author() -> GTIReportData:
    """Fixture for GTI report without author information."""
    return GTIReportDataFactory.build(attributes=ReportModelFactory.build(author=None))


@pytest.fixture
def report_with_empty_author() -> GTIReportData:
    """Fixture for GTI report with empty author string."""
    return GTIReportDataFactory.build(attributes=ReportModelFactory.build(author=""))


@pytest.fixture
def report_without_attributes() -> GTIReportData:
    """Fixture for GTI report without attributes."""
    return GTIReportDataFactory.build(attributes=None)


@pytest.fixture
def report_with_long_author_name() -> GTIReportData:
    """Fixture for GTI report with very long author name."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(author="A" * 1000)
    )


@pytest.fixture
def report_with_special_characters_in_author() -> GTIReportData:
    """Fixture for GTI report with special characters in author name."""
    return GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(
            author="Research & Development Team - Security Division"
        )
    )


def test_gti_report_to_stix_identity_with_author(
    report_with_author, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with author to STIX identity."""
    # GIVEN: A GTI report containing author information (Security Research Team)
    # and valid organization and TLP marking objects for STIX identity creation
    mapper = _given_gti_report_identity_mapper(
        report_with_author, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # using the report's author name as the identity name
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_has_correct_properties(identity, mock_organization)
    _then_stix_identity_uses_report_author(
        identity, report_with_author.attributes.author
    )


def test_gti_report_to_stix_identity_with_short_author(
    report_with_short_author, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with short author name."""
    # GIVEN: A GTI report containing a very short author name (AI - 2 characters)
    # which is below the minimum length threshold for using custom author names
    mapper = _given_gti_report_identity_mapper(
        report_with_short_author, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # but use the default author name instead of the short custom author
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_uses_default_author(identity)


def test_gti_report_to_stix_identity_without_author(
    report_without_author, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report without author information."""
    # GIVEN: A GTI report with author field set to None
    # indicating no author information is available in the report
    mapper = _given_gti_report_identity_mapper(
        report_without_author, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # using the default author name since no custom author is provided
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_uses_default_author(identity)


def test_gti_report_to_stix_identity_with_empty_author(
    report_with_empty_author, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with empty author string."""
    # GIVEN: A GTI report with author field set to empty string
    # representing a case where author field exists but contains no meaningful data
    mapper = _given_gti_report_identity_mapper(
        report_with_empty_author, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # using the default author name since empty strings are treated as invalid
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_uses_default_author(identity)


def test_gti_report_to_stix_identity_without_attributes(
    report_without_attributes, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report without attributes raises ValueError."""
    # GIVEN: A GTI report with attributes field set to None
    # making it impossible to access any report data including author information
    mapper = _given_gti_report_identity_mapper(
        report_without_attributes, mock_organization, mock_tlp_marking
    )

    # WHEN: Attempting to convert the GTI report data to STIX identity object
    # THEN: A ValueError should be raised with message about invalid attributes
    # since the mapper cannot process a report without proper attribute structure
    _when_convert_to_stix_raises_error(mapper, ValueError, "Invalid report attributes")


def test_gti_report_to_stix_identity_with_long_author_name(
    report_with_long_author_name, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with very long author name."""
    # GIVEN: A GTI report containing an extremely long author name (1000 characters)
    # to test boundary conditions and ensure long names are handled properly
    mapper = _given_gti_report_identity_mapper(
        report_with_long_author_name, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # preserving the full length of the author name without truncation
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_preserves_long_author_name(identity)


def test_gti_report_to_stix_identity_with_special_characters(
    report_with_special_characters_in_author, mock_organization, mock_tlp_marking
):
    """Test conversion of GTI report with special characters in author name."""
    # GIVEN: A GTI report containing author name with special characters
    # (ampersands, hyphens, spaces) to test character encoding and preservation
    mapper = _given_gti_report_identity_mapper(
        report_with_special_characters_in_author, mock_organization, mock_tlp_marking
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # preserving all special characters in the author name without modification
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_preserves_special_characters(identity)


def test_gti_report_to_stix_identity_without_tlp_marking(
    report_with_author, mock_organization
):
    """Test conversion of GTI report without TLP marking."""
    # GIVEN: A GTI report with valid author information and organization
    # but no TLP marking definition provided for classification
    mapper = _given_gti_report_identity_mapper_without_tlp(
        report_with_author, mock_organization
    )

    # WHEN: Converting the GTI report data to STIX identity object
    identity = _when_convert_to_stix(mapper)

    # THEN: A STIX Identity object should be created successfully
    # even without TLP marking, maintaining other correct properties
    _then_stix_identity_created_successfully(identity)
    _then_stix_identity_has_correct_properties(identity, mock_organization)


def test_gti_report_identity_mapper_initialization(
    report_with_author, mock_organization, mock_tlp_marking
):
    """Test GTIReportToSTIXIdentity mapper initialization."""
    # GIVEN: Valid GTI report data, organization, and TLP marking objects
    # for initializing the mapper with all required dependencies
    # WHEN: Creating a new GTIReportToSTIXIdentity mapper instance
    mapper = GTIReportToSTIXIdentity(
        report=report_with_author,
        organization=mock_organization,
        tlp_marking=mock_tlp_marking,
    )

    # THEN: The mapper should be initialized correctly
    # with all provided objects properly assigned to instance attributes
    assert mapper.report == report_with_author  # noqa: S101
    assert mapper.organization == mock_organization  # noqa: S101


def test_author_length_validation_edge_cases(mock_organization, mock_tlp_marking):
    """Test author length validation with edge cases."""
    # GIVEN: A GTI report with 2-character author name (just below minimum threshold)
    # to test the exact boundary condition for author name length validation
    report_two_chars = GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(author="AB")
    )
    mapper = _given_gti_report_identity_mapper(
        report_two_chars, mock_organization, mock_tlp_marking
    )
    # WHEN: Converting the report with 2-character author to STIX identity
    identity = _when_convert_to_stix(mapper)
    # THEN: Default author should be used since 2 characters is too short
    _then_stix_identity_uses_default_author(identity)

    # GIVEN: A GTI report with 3-character author name (just at minimum threshold)
    # to test that the minimum acceptable length is properly handled
    report_three_chars = GTIReportDataFactory.build(
        attributes=ReportModelFactory.build(author="ABC")
    )
    mapper = _given_gti_report_identity_mapper(
        report_three_chars, mock_organization, mock_tlp_marking
    )
    # WHEN: Converting the report with 3-character author to STIX identity
    identity = _when_convert_to_stix(mapper)
    # THEN: The custom author name should be used since it meets minimum length
    _then_stix_identity_uses_report_author(identity, "ABC")


def _given_gti_report_identity_mapper(
    report: GTIReportData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIReportToSTIXIdentity:
    """Create a GTIReportToSTIXIdentity mapper instance."""
    return GTIReportToSTIXIdentity(
        report=report,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _given_gti_report_identity_mapper_without_tlp(
    report: GTIReportData, organization: Identity
) -> GTIReportToSTIXIdentity:
    """Create a GTIReportToSTIXIdentity mapper instance without TLP marking."""
    return GTIReportToSTIXIdentity(
        report=report,
        organization=organization,
    )


def _when_convert_to_stix(mapper: GTIReportToSTIXIdentity) -> IdentityModel:
    """Convert GTI report to STIX identity."""
    return mapper.to_stix()


def _when_convert_to_stix_raises_error(
    mapper: GTIReportToSTIXIdentity, error_type: type, error_message: str
):
    """Test that conversion raises expected error."""
    with pytest.raises(error_type, match=error_message):
        mapper.to_stix()


def _then_stix_identity_created_successfully(identity: IdentityModel):
    """Assert that STIX identity was created successfully."""
    assert isinstance(identity, IdentityModel)  # noqa: S101
    assert hasattr(identity, "name")  # noqa: S101
    assert hasattr(identity, "identity_class")  # noqa: S101
    assert hasattr(identity, "spec_version")  # noqa: S101
    assert hasattr(identity, "created")  # noqa: S101
    assert hasattr(identity, "modified")  # noqa: S101


def _then_stix_identity_has_correct_properties(
    identity: IdentityModel, organization: Identity
):
    """Assert that STIX identity has correct properties."""
    assert identity.created_by_ref == organization.id  # noqa: S101
    assert identity.identity_class.value == "organization"  # noqa: S101
    assert identity.spec_version == "2.1"  # noqa: S101


def _then_stix_identity_uses_report_author(
    identity: IdentityModel, expected_author: str
):
    """Assert that STIX identity uses the report's author name."""
    assert identity.name == expected_author  # noqa: S101


def _then_stix_identity_uses_default_author(identity: IdentityModel):
    """Assert that STIX identity uses the default author name."""
    assert identity.name == "Google Threat Intelligence"  # noqa: S101


def _then_stix_identity_preserves_long_author_name(identity: IdentityModel):
    """Assert that STIX identity preserves long author names."""
    assert len(identity.name) == 1000  # noqa: S101
    assert identity.name == "A" * 1000  # noqa: S101


def _then_stix_identity_preserves_special_characters(identity: IdentityModel):
    """Assert that STIX identity preserves special characters in author names."""
    assert "&" in identity.name  # noqa: S101
    assert "-" in identity.name  # noqa: S101
    assert (  # noqa: S101
        identity.name == "Research & Development Team - Security Division"
    )
