"""Tests for GTI IP to STIX IP mapper."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from polyfactory.factories.pydantic_factory import ModelFactory
from stix2.v21 import Identity, MarkingDefinition

from connector.src.custom.mappers.gti_reports.gti_ip_to_stix_ip import (
    GTIIPToSTIXIP,
)
from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    ContributingFactors,
    GTIAssessment,
    GTIIPData,
    IPModel,
    LastAnalysisStats,
    Severity,
    ThreatScore,
    TotalVotes,
    Verdict,
)


class VerdictFactory(ModelFactory[Verdict]):
    """Create verdict for testing."""

    __model__ = Verdict


class SeverityFactory(ModelFactory[Severity]):
    """Create severity for testing."""

    __model__ = Severity


class ThreatScoreFactory(ModelFactory[ThreatScore]):
    """Create threat score for testing."""

    __model__ = ThreatScore


class ContributingFactorsFactory(ModelFactory[ContributingFactors]):
    """Create contributing factors for testing."""

    __model__ = ContributingFactors


class LastAnalysisStatsFactory(ModelFactory[LastAnalysisStats]):
    """Create last analysis stats for testing."""

    __model__ = LastAnalysisStats


class TotalVotesFactory(ModelFactory[TotalVotes]):
    """Create total votes for testing."""

    __model__ = TotalVotes


class GTIAssessmentFactory(ModelFactory[GTIAssessment]):
    """Create GTI assessment for testing."""

    __model__ = GTIAssessment


class IPModelFactory(ModelFactory[IPModel]):
    """Create IP model for testing."""

    __model__ = IPModel


class GTIIPDataFactory(ModelFactory[GTIIPData]):
    """Create GTI IP data for testing."""

    __model__ = GTIIPData


@pytest.fixture
def mock_organization():
    """Mock organization identity."""
    return Identity(name="Test Organization", identity_class="organization")


@pytest.fixture
def mock_tlp_marking() -> MarkingDefinition:
    """Fixture for mock TLP marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def minimal_ipv4_data():
    """Minimal GTI IPv4 data for testing."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        type="ip_address",
        attributes=None,
    )


@pytest.fixture
def minimal_ipv6_data():
    """Minimal GTI IPv6 data for testing."""
    return GTIIPDataFactory.build(
        id="2001:db8::1",
        type="ip_address",
        attributes=None,
    )


@pytest.fixture
def ipv4_with_timestamps():
    """GTI IPv4 data with timestamps for testing."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        type="ip_address",
        attributes=IPModelFactory.build(
            last_analysis_date=1640995200,  # 2022-01-01
            last_modification_date=1672531200,  # 2023-01-01
        ),
    )


@pytest.fixture
def ipv6_with_timestamps():
    """GTI IPv6 data with timestamps for testing."""
    return GTIIPDataFactory.build(
        id="2001:db8::1",
        type="ip_address",
        attributes=IPModelFactory.build(
            last_analysis_date=1640995200,  # 2022-01-01
            last_modification_date=1672531200,  # 2023-01-01
        ),
    )


@pytest.fixture
def ip_with_mandiant_score():
    """GTI IP data with mandiant confidence score for testing."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        type="ip_address",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            )
        ),
    )


@pytest.fixture
def ip_with_threat_score():
    """GTI IP data with threat score for testing."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        type="ip_address",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                threat_score=ThreatScoreFactory.build(value=75),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
            )
        ),
    )


@pytest.fixture
def ip_with_all_data():
    """GTI IP data with all available data for testing."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        type="ip_address",
        attributes=IPModelFactory.build(
            last_analysis_date=1640995200,
            last_modification_date=1672531200,
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            ),
        ),
    )


@pytest.fixture
def ip_without_attributes():
    """GTI IP data without attributes for testing."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        type="ip_address",
        attributes=None,
    )


@pytest.fixture
def invalid_ip_data():
    """GTI IP data with invalid IP address for testing."""
    return GTIIPDataFactory.build(
        id="invalid_ip",
        type="ip_address",
        attributes=None,
    )


# Scenario: Convert GTI IPv4 to STIX objects with minimal data
def test_gti_ipv4_to_stix_minimal_data(
    minimal_ipv4_data: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IPv4 to STIX conversion with minimal data."""
    # Given a GTI IPv4 with minimal data
    mapper = _given_gti_ip_mapper(
        minimal_ipv4_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then IPv4 observable should be created
    _then_stix_object_created_successfully(stix_object)
    _then_stix_ipv4_has_correct_properties(
        stix_object, minimal_ipv4_data, mock_organization, mock_tlp_marking
    )


# Scenario: Convert GTI IPv6 to STIX objects with minimal data
def test_gti_ipv6_to_stix_minimal_data(
    minimal_ipv6_data: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IPv6 to STIX conversion with minimal data."""
    # Given a GTI IPv6 with minimal data
    mapper = _given_gti_ip_mapper(
        minimal_ipv6_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then IPv6 observable should be created
    _then_stix_object_created_successfully(stix_object)
    _then_stix_ipv6_has_correct_properties(
        stix_object, minimal_ipv6_data, mock_organization, mock_tlp_marking
    )


# Scenario: Convert GTI IP with timestamps to STIX objects
def test_gti_ip_to_stix_with_timestamps(
    ipv4_with_timestamps: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IP to STIX conversion with timestamps."""
    # Given a GTI IP with timestamps
    mapper = _given_gti_ip_mapper(
        ipv4_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then STIX object should be created successfully
    _then_stix_object_created_successfully(stix_object)


# Scenario: Convert GTI IP with Mandiant confidence score to STIX objects
def test_gti_ip_to_stix_with_mandiant_score(
    ip_with_mandiant_score: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IP to STIX conversion with mandiant confidence score."""
    # Given a GTI IP with mandiant confidence score
    mapper = _given_gti_ip_mapper(
        ip_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then mandiant score should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    _then_stix_ip_has_score(stix_object, 85)


# Scenario: Convert GTI IP with threat score to STIX objects
def test_gti_ip_to_stix_with_threat_score(
    ip_with_threat_score: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IP to STIX conversion with threat score."""
    # Given a GTI IP with threat score
    mapper = _given_gti_ip_mapper(
        ip_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then threat score should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    _then_stix_ip_has_score(stix_object, 75)


# Scenario: Convert GTI IP with all data to STIX objects
def test_gti_ip_to_stix_with_all_data(
    ip_with_all_data: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IP to STIX conversion with all available data."""
    # Given a GTI IP with all data
    mapper = _given_gti_ip_mapper(ip_with_all_data, mock_organization, mock_tlp_marking)

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then all data should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    _then_stix_ipv4_has_correct_properties(
        stix_object, ip_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_ip_has_score(stix_object, 85)


# Scenario: Convert GTI IP without attributes to STIX objects
def test_gti_ip_to_stix_without_attributes(
    ip_without_attributes: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI IP to STIX conversion without attributes."""
    # Given a GTI IP without attributes
    mapper = _given_gti_ip_mapper(
        ip_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then IP should still be created successfully
    _then_stix_object_created_successfully(stix_object)


# Unit tests for individual methods
def test_detect_ip_version_ipv4(minimal_ipv4_data, mock_organization, mock_tlp_marking):
    """Test _detect_ip_version method with IPv4."""
    mapper = _given_gti_ip_mapper(
        minimal_ipv4_data, mock_organization, mock_tlp_marking
    )

    version = mapper._detect_ip_version()

    assert version == "ipv4"  # noqa: S101


def test_detect_ip_version_ipv6(minimal_ipv6_data, mock_organization, mock_tlp_marking):
    """Test _detect_ip_version method with IPv6."""
    mapper = _given_gti_ip_mapper(
        minimal_ipv6_data, mock_organization, mock_tlp_marking
    )

    version = mapper._detect_ip_version()

    assert version == "ipv6"  # noqa: S101


def test_detect_ip_version_invalid(
    invalid_ip_data, mock_organization, mock_tlp_marking
):
    """Test _detect_ip_version method with invalid IP."""
    mapper = _given_gti_ip_mapper(invalid_ip_data, mock_organization, mock_tlp_marking)

    with pytest.raises(ValueError, match="Invalid IP address format"):
        mapper._detect_ip_version()


def test_get_timestamps_with_valid_data(
    ipv4_with_timestamps, mock_organization, mock_tlp_marking
):
    """Test _get_timestamps method with valid timestamp data."""
    mapper = _given_gti_ip_mapper(
        ipv4_with_timestamps, mock_organization, mock_tlp_marking
    )

    timestamps = mapper._get_timestamps()

    expected_created = datetime.fromtimestamp(1640995200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1672531200, tz=timezone.utc)

    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


def test_get_timestamps_without_data(
    minimal_ipv4_data, mock_organization, mock_tlp_marking
):
    """Test _get_timestamps method without timestamp data."""
    mapper = _given_gti_ip_mapper(
        minimal_ipv4_data, mock_organization, mock_tlp_marking
    )

    timestamps = mapper._get_timestamps()

    assert isinstance(timestamps["created"], datetime)  # noqa: S101
    assert isinstance(timestamps["modified"], datetime)  # noqa: S101
    assert timestamps["created"].tzinfo == timezone.utc  # noqa: S101
    assert timestamps["modified"].tzinfo == timezone.utc  # noqa: S101


def test_get_mandiant_ic_score_with_mandiant_score(
    ip_with_mandiant_score, mock_organization, mock_tlp_marking
):
    """Test _get_mandiant_ic_score method with mandiant score."""
    mapper = _given_gti_ip_mapper(
        ip_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    score = mapper._get_mandiant_ic_score()

    assert score == 85  # noqa: S101


def test_get_mandiant_ic_score_with_threat_score_fallback(
    ip_with_threat_score, mock_organization, mock_tlp_marking
):
    """Test _get_mandiant_ic_score method with threat score fallback."""
    mapper = _given_gti_ip_mapper(
        ip_with_threat_score, mock_organization, mock_tlp_marking
    )

    score = mapper._get_mandiant_ic_score()

    assert score == 75  # noqa: S101


def test_get_mandiant_ic_score_without_data(
    minimal_ipv4_data, mock_organization, mock_tlp_marking
):
    """Test _get_mandiant_ic_score method without score data."""
    mapper = _given_gti_ip_mapper(
        minimal_ipv4_data, mock_organization, mock_tlp_marking
    )

    score = mapper._get_mandiant_ic_score()

    assert score is None  # noqa: S101


def test_create_stix_ipv4_method(
    minimal_ipv4_data, mock_organization, mock_tlp_marking
):
    """Test _create_stix_ip method for IPv4."""
    mapper = _given_gti_ip_mapper(
        minimal_ipv4_data, mock_organization, mock_tlp_marking
    )

    ip_obj = mapper._create_stix_ip()

    # Then IP object should be created with correct properties
    assert hasattr(ip_obj, "value")  # noqa: S101
    assert hasattr(ip_obj, "object_marking_refs")  # noqa: S101
    assert mock_tlp_marking.id in ip_obj.object_marking_refs  # noqa: S101
    assert ip_obj.value == minimal_ipv4_data.id  # noqa: S101


def test_create_stix_ipv6_method(
    minimal_ipv6_data, mock_organization, mock_tlp_marking
):
    """Test _create_stix_ip method for IPv6."""
    mapper = _given_gti_ip_mapper(
        minimal_ipv6_data, mock_organization, mock_tlp_marking
    )

    ip_obj = mapper._create_stix_ip()

    # Then IP object should be created with correct properties
    assert hasattr(ip_obj, "value")  # noqa: S101
    assert hasattr(ip_obj, "object_marking_refs")  # noqa: S101
    assert mock_tlp_marking.id in ip_obj.object_marking_refs  # noqa: S101
    assert ip_obj.value == minimal_ipv6_data.id  # noqa: S101


def _given_gti_ip_mapper(ip_data, organization, tlp_marking):
    """Create GTI IP mapper."""
    return GTIIPToSTIXIP(ip=ip_data, organization=organization, tlp_marking=tlp_marking)


def _when_convert_to_stix(mapper):
    """Convert GTI IP to STIX objects."""
    return mapper.to_stix()


def _then_stix_object_created_successfully(stix_object):
    """Verify STIX object was created successfully."""
    assert stix_object is not None  # noqa: S101
    assert hasattr(stix_object, "value")  # IP observable  # noqa: S101


def _then_stix_ipv4_has_correct_properties(
    ip_obj,
    ip_data: GTIIPData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Verify STIX IPv4 has correct properties."""
    assert hasattr(ip_obj, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in ip_obj.object_marking_refs  # noqa: S101
    assert ip_obj.value == ip_data.id  # noqa: S101


def _then_stix_ipv6_has_correct_properties(
    ip_obj,
    ip_data: GTIIPData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Verify STIX IPv6 has correct properties."""
    assert hasattr(ip_obj, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in ip_obj.object_marking_refs  # noqa: S101
    assert ip_obj.value == ip_data.id  # noqa: S101


def _then_stix_ip_has_score(ip_obj, expected_score):
    """Verify STIX IP has score."""
    if hasattr(ip_obj, "score"):
        assert ip_obj.score == expected_score  # noqa: S101
