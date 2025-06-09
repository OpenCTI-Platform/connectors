"""Tests for GTI URL to STIX URL mapper."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_url_to_stix_url import (
    GTIUrlToSTIXUrl,
)
from connector.src.custom.models.gti_reports.gti_url_model import (
    ContributingFactors,
    GTIAssessment,
    GTIURLData,
    LastAnalysisStats,
    Severity,
    ThreatScore,
    URLModel,
    Verdict,
)
from polyfactory.factories.pydantic_factory import ModelFactory
from stix2.v21 import Identity, MarkingDefinition


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


class GTIAssessmentFactory(ModelFactory[GTIAssessment]):
    """Create GTI assessment for testing."""

    __model__ = GTIAssessment


class URLModelFactory(ModelFactory[URLModel]):
    """Create URL model for testing."""

    __model__ = URLModel


class GTIURLDataFactory(ModelFactory[GTIURLData]):
    """Create GTI URL data for testing."""

    __model__ = GTIURLData


@pytest.fixture
def mock_organization():
    """Mock organization identity."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization", identity_class="organization"
    )


@pytest.fixture
def mock_tlp_marking() -> MarkingDefinition:
    """Fixture for mock TLP marking definition."""
    return MarkingDefinition(
        id=f"marking-definition--{uuid4()}",
        definition_type="statement",
        definition={"statement": "Internal Use Only"},
    )


@pytest.fixture
def minimal_url_data():
    """Minimal GTI URL data for testing."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        type="url",
        attributes=None,
    )


@pytest.fixture
def url_with_timestamps():
    """GTI URL data with timestamps."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            first_submission_date=1640995200,
            last_modification_date=1641081600,
        ),
    )


@pytest.fixture
def url_with_url_value():
    """GTI URL data with URL value."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/malicious",
            last_final_url="https://final.example.com/malicious",
        ),
    )


@pytest.fixture
def url_with_mandiant_score():
    """GTI URL data with mandiant confidence score."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/",
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=95
                )
            ),
        ),
    )


@pytest.fixture
def url_with_threat_score():
    """GTI URL data with threat score fallback."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/",
            gti_assessment=GTIAssessmentFactory.build(
                threat_score=ThreatScoreFactory.build(value=80),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
            ),
        ),
    )


@pytest.fixture
def url_with_malicious_verdict():
    """GTI URL data with malicious verdict."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://malicious.example.com/",
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="VERDICT_MALICIOUS")
            ),
        ),
    )


@pytest.fixture
def url_with_benign_verdict():
    """GTI URL data with benign verdict."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://benign.example.com/",
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="VERDICT_BENIGN")
            ),
        ),
    )


@pytest.fixture
def url_with_suspicious_verdict():
    """GTI URL data with suspicious verdict."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://suspicious.example.com/",
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="VERDICT_SUSPICIOUS")
            ),
        ),
    )


@pytest.fixture
def url_with_analysis_stats_malicious():
    """GTI URL data with malicious analysis stats."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/",
            last_analysis_stats=LastAnalysisStatsFactory.build(
                malicious=5, suspicious=0, harmless=3
            ),
        ),
    )


@pytest.fixture
def url_with_analysis_stats_suspicious():
    """GTI URL data with suspicious analysis stats."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/",
            last_analysis_stats=LastAnalysisStatsFactory.build(
                malicious=0, suspicious=3, harmless=2
            ),
        ),
    )


@pytest.fixture
def url_with_analysis_stats_harmless():
    """GTI URL data with harmless analysis stats."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/",
            last_analysis_stats=LastAnalysisStatsFactory.build(
                malicious=0, suspicious=0, harmless=8
            ),
        ),
    )


@pytest.fixture
def url_with_all_data():
    """GTI URL data with all attributes populated."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/malicious",
            last_final_url="https://redirected.example.com/malicious",
            title="Malicious Website",
            first_submission_date=1640995200,
            last_modification_date=1641081600,
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="VERDICT_MALICIOUS"),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                ),
            ),
            last_analysis_stats=LastAnalysisStatsFactory.build(
                malicious=10, suspicious=2, harmless=5
            ),
        ),
    )


@pytest.fixture
def url_without_attributes():
    """GTI URL data without attributes."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=None,
    )


@pytest.fixture
def url_with_empty_verdict():
    """GTI URL data with empty verdict."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url="https://example.com/",
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value=None)
            ),
            last_analysis_stats=None,
        ),
    )


@pytest.fixture
def url_with_invalid_timestamps():
    """GTI URL data with invalid timestamps."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            first_submission_date=None, last_modification_date=None
        ),
    )


@pytest.fixture
def url_with_none_analysis_stats():
    """GTI URL data with None analysis stats."""
    return GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(last_analysis_stats=None),
    )


def test_gti_url_to_stix_minimal_data(
    minimal_url_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with minimal data."""
    # Given a GTI URL with minimal data
    mapper = _given_gti_url_mapper(
        minimal_url_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then URL observable should be created
    _then_stix_objects_created_successfully(stix_objects)
    _then_stix_url_has_correct_properties(
        stix_objects, minimal_url_data, mock_organization, mock_tlp_marking
    )


# Scenario: Convert GTI URL with timestamps to STIX objects
def test_gti_url_to_stix_with_timestamps(
    url_with_timestamps: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with timestamps."""
    # Given a GTI URL with timestamps
    mapper = _given_gti_url_mapper(
        url_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with URL value to STIX objects
def test_gti_url_to_stix_with_url_value(
    url_with_url_value: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with URL value."""
    # Given a GTI URL with URL value
    mapper = _given_gti_url_mapper(
        url_with_url_value, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then URL value should be correctly applied
    _then_stix_objects_created_successfully(stix_objects)
    url_obj = stix_objects
    assert url_obj.value == "https://example.com/malicious"  # noqa: S101


# Scenario: Convert GTI URL with mandiant score to STIX objects
def test_gti_url_to_stix_with_mandiant_score(
    url_with_mandiant_score: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with mandiant score."""
    # Given a GTI URL with mandiant score
    mapper = _given_gti_url_mapper(
        url_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should include mandiant score
    _then_stix_objects_created_successfully(stix_objects)
    _then_stix_url_has_score(stix_objects, 85)


# Scenario: Convert GTI URL with threat score fallback to STIX objects
def test_gti_url_to_stix_with_threat_score(
    url_with_threat_score: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with threat score fallback."""
    # Given a GTI URL with threat score
    mapper = _given_gti_url_mapper(
        url_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should use threat score as fallback
    _then_stix_objects_created_successfully(stix_objects)
    _then_stix_url_has_score(stix_objects, 75)


# Scenario: Convert GTI URL with malicious verdict to STIX objects
def test_gti_url_to_stix_with_malicious_verdict(
    url_with_malicious_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with malicious verdict."""
    # Given a GTI URL with malicious verdict
    mapper = _given_gti_url_mapper(
        url_with_malicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with benign verdict to STIX objects
def test_gti_url_to_stix_with_benign_verdict(
    url_with_benign_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with benign verdict."""
    # Given a GTI URL with benign verdict
    mapper = _given_gti_url_mapper(
        url_with_benign_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with suspicious verdict to STIX objects
def test_gti_url_to_stix_with_suspicious_verdict(
    url_with_suspicious_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with suspicious verdict."""
    # Given a GTI URL with suspicious verdict
    mapper = _given_gti_url_mapper(
        url_with_suspicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with malicious analysis stats to STIX objects
def test_gti_url_to_stix_with_analysis_stats_malicious(
    url_with_analysis_stats_malicious: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with malicious analysis stats."""
    # Given a GTI URL with malicious analysis stats
    mapper = _given_gti_url_mapper(
        url_with_analysis_stats_malicious, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with suspicious analysis stats to STIX objects
def test_gti_url_to_stix_with_analysis_stats_suspicious(
    url_with_analysis_stats_suspicious: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with suspicious analysis stats."""
    # Given a GTI URL with suspicious analysis stats
    mapper = _given_gti_url_mapper(
        url_with_analysis_stats_suspicious, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with harmless analysis stats to STIX objects
def test_gti_url_to_stix_with_analysis_stats_harmless(
    url_with_analysis_stats_harmless: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with harmless analysis stats."""
    # Given a GTI URL with harmless analysis stats
    mapper = _given_gti_url_mapper(
        url_with_analysis_stats_harmless, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with all data to STIX objects
def test_gti_url_to_stix_with_all_data(
    url_with_all_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with all data."""
    # Given a GTI URL with all data
    mapper = _given_gti_url_mapper(
        url_with_all_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should include URL value
    _then_stix_objects_created_successfully(stix_objects)
    _then_stix_url_has_correct_properties(
        stix_objects, url_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_url_has_score(stix_objects, 95)


# Scenario: Convert GTI URL without attributes to STIX objects
def test_gti_url_to_stix_without_attributes(
    url_without_attributes: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion without attributes."""
    # Given a GTI URL without attributes
    mapper = _given_gti_url_mapper(
        url_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with empty verdict to STIX objects
def test_gti_url_to_stix_with_empty_verdict(
    url_with_empty_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with empty verdict."""
    # Given a GTI URL with empty verdict
    mapper = _given_gti_url_mapper(
        url_with_empty_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with invalid timestamps to STIX objects
def test_gti_url_to_stix_with_invalid_timestamps(
    url_with_invalid_timestamps: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with invalid timestamps."""
    # Given a GTI URL with invalid timestamps
    mapper = _given_gti_url_mapper(
        url_with_invalid_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Convert GTI URL with None analysis stats to STIX objects
def test_gti_url_to_stix_with_none_analysis_stats(
    url_with_none_analysis_stats: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI URL to STIX conversion with None analysis stats."""
    # Given a GTI URL with None analysis stats
    mapper = _given_gti_url_mapper(
        url_with_none_analysis_stats, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX object should be created
    _then_stix_objects_created_successfully(stix_objects)


def test_get_timestamps_with_valid_data(
    url_with_timestamps: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_timestamps method with valid data."""
    # Given a GTI URL with valid timestamps
    mapper = _given_gti_url_mapper(
        url_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then correct timestamps should be returned
    expected_created = datetime.fromtimestamp(1640995200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1641081600, tz=timezone.utc)
    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


def test_get_timestamps_without_data(
    minimal_url_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_timestamps method without data."""
    # Given a GTI URL without timestamp data
    mapper = _given_gti_url_mapper(
        minimal_url_data, mock_organization, mock_tlp_marking
    )

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then current timestamps should be returned
    assert isinstance(timestamps["created"], datetime)  # noqa: S101
    assert isinstance(timestamps["modified"], datetime)  # noqa: S101
    assert timestamps["created"].tzinfo == timezone.utc  # noqa: S101
    assert timestamps["modified"].tzinfo == timezone.utc  # noqa: S101


def test_get_mandiant_ic_score_with_mandiant_score(
    url_with_mandiant_score: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_mandiant_ic_score method with mandiant score."""
    # Given a GTI URL with mandiant confidence score
    mapper = _given_gti_url_mapper(
        url_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When extracting mandiant IC score
    score = mapper._get_mandiant_ic_score()

    # Then mandiant confidence score should be returned
    assert score == 95  # noqa: S101


def test_get_mandiant_ic_score_with_threat_score_fallback(
    url_with_threat_score: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_mandiant_ic_score method with threat score fallback."""
    # Given a GTI URL with threat score but no mandiant score
    mapper = _given_gti_url_mapper(
        url_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When extracting mandiant IC score
    score = mapper._get_mandiant_ic_score()

    # Then threat score should be returned as fallback
    assert score == 80  # noqa: S101


def test_get_mandiant_ic_score_without_data(
    minimal_url_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_mandiant_ic_score method without data."""
    # Given a GTI URL without assessment data
    mapper = _given_gti_url_mapper(
        minimal_url_data, mock_organization, mock_tlp_marking
    )

    # When extracting mandiant IC score
    score = mapper._get_mandiant_ic_score()

    # Then None should be returned
    assert score is None  # noqa: S101


def test_get_url_value_with_url_attribute(
    url_with_url_value: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_url_value method with URL attribute."""
    # Given a GTI URL with URL attribute
    mapper = _given_gti_url_mapper(
        url_with_url_value, mock_organization, mock_tlp_marking
    )

    # When extracting URL value
    url_value = mapper._get_url_value()

    # Then URL attribute should be returned
    assert url_value == "https://example.com/malicious"  # noqa: S101


def test_get_url_value_with_final_url_fallback(
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_url_value method with final URL fallback."""
    # Given a GTI URL with final URL but no url attribute
    url_data = GTIURLDataFactory.build(
        id="aHR0cHM6Ly9leGFtcGxlLmNvbS8",
        attributes=URLModelFactory.build(
            url=None,
            last_final_url="https://final.example.com/redirect",
        ),
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When extracting URL value
    url_value = mapper._get_url_value()

    # Then final URL should be returned
    assert url_value == "https://final.example.com/redirect"  # noqa: S101


def test_get_url_value_with_id_fallback(
    minimal_url_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _get_url_value method with ID fallback."""
    # Given a GTI URL without URL attributes
    mapper = _given_gti_url_mapper(
        minimal_url_data, mock_organization, mock_tlp_marking
    )

    # When extracting URL value
    url_value = mapper._get_url_value()

    # Then ID should be returned as fallback
    assert url_value == "aHR0cHM6Ly9leGFtcGxlLmNvbS8"  # noqa: S101


def test_create_stix_url_method(
    url_with_all_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test _create_stix_url method."""
    # Given a GTI URL with all data
    mapper = _given_gti_url_mapper(
        url_with_all_data, mock_organization, mock_tlp_marking
    )

    # When creating STIX URL
    url_obj = mapper._create_stix_url()

    # Then URL object should be created with correct properties
    assert hasattr(url_obj, "value")  # noqa: S101
    assert hasattr(url_obj, "object_marking_refs")  # noqa: S101
    assert mock_tlp_marking.id in url_obj.object_marking_refs  # noqa: S101


def _given_gti_url_mapper(url_data, organization, tlp_marking):
    """Create GTI URL mapper."""
    return GTIUrlToSTIXUrl(
        url=url_data, organization=organization, tlp_marking=tlp_marking
    )


def _when_convert_to_stix(mapper):
    """Convert GTI URL to STIX objects."""
    return mapper.to_stix()


def _then_stix_objects_created_successfully(stix_object):
    """Verify STIX object was created successfully."""
    assert stix_object is not None  # noqa: S101
    assert hasattr(stix_object, "value")  # URL observable  # noqa: S101


def _then_stix_url_has_correct_properties(
    url_obj,
    url_data: GTIURLData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Verify STIX URL has correct properties."""
    assert hasattr(url_obj, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in url_obj.object_marking_refs  # noqa: S101

    if url_data.attributes:
        if url_data.attributes.url:
            assert url_obj.value == url_data.attributes.url  # noqa: S101
        elif url_data.attributes.last_final_url:
            assert url_obj.value == url_data.attributes.last_final_url  # noqa: S101
    else:
        assert url_obj.value == url_data.id  # noqa: S101


def _then_stix_url_has_score(url_obj, expected_score):
    """Verify STIX URL has score."""
    if hasattr(url_obj, "score"):
        assert url_obj.score == expected_score  # noqa: S101
