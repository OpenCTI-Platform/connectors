"""Tests for GTI URL to STIX URL mapper."""

from datetime import datetime, timezone
from typing import Any, List
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_url_to_stix_url import (
    GTIUrlToSTIXUrl,
)
from connector.src.custom.models.gti_reports.gti_url_model import (
    ContributingFactors,
    GTIAssessment,
    GTIURLData,
    ThreatScore,
    URLModel,
    Verdict,
)
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition


class VerdictFactory(ModelFactory[Verdict]):
    """Factory for Verdict model."""

    __model__ = Verdict


class ThreatScoreFactory(ModelFactory[ThreatScore]):
    """Factory for ThreatScore model."""

    __model__ = ThreatScore


class ContributingFactorsFactory(ModelFactory[ContributingFactors]):
    """Factory for ContributingFactors model."""

    __model__ = ContributingFactors


class GTIAssessmentFactory(ModelFactory[GTIAssessment]):
    """Factory for GTIAssessment model."""

    __model__ = GTIAssessment


class URLModelFactory(ModelFactory[URLModel]):
    """Factory for URLModel."""

    __model__ = URLModel


class GTIURLDataFactory(ModelFactory[GTIURLData]):
    """Factory for GTIURLData."""

    __model__ = GTIURLData

    type = "url"
    attributes = Use(URLModelFactory.build)


@pytest.fixture
def mock_organization() -> Identity:
    """Fixture for mock organization identity."""
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
def minimal_url_data() -> GTIURLData:
    """Fixture for minimal URL data."""
    return GTIURLDataFactory.build(
        id="https://example.com",
        attributes=URLModelFactory.build(
            first_submission_date=None,
            last_modification_date=None,
            gti_assessment=None,
            url=None,
            last_final_url=None,
        ),
    )


@pytest.fixture
def url_with_timestamps() -> GTIURLData:
    """Fixture for URL data with timestamps."""
    return GTIURLDataFactory.build(
        id="https://example.com/path",
        attributes=URLModelFactory.build(
            first_submission_date=1672531200,
            last_modification_date=1672617600,
            gti_assessment=None,
            url=None,
            last_final_url=None,
        ),
    )


@pytest.fixture
def url_with_url_value() -> GTIURLData:
    """Fixture for URL data with specific URL value."""
    return GTIURLDataFactory.build(
        id="url-id-123",
        attributes=URLModelFactory.build(
            url="https://malicious.example.com/malware",
            last_final_url="https://final.example.com/endpoint",
            gti_assessment=None,
        ),
    )


@pytest.fixture
def url_with_mandiant_score() -> GTIURLData:
    """Fixture for URL data with mandiant confidence score."""
    return GTIURLDataFactory.build(
        id="https://suspicious.example.com",
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                ),
                threat_score=None,
                verdict=None,
            ),
        ),
    )


@pytest.fixture
def url_with_threat_score() -> GTIURLData:
    """Fixture for URL data with threat score fallback."""
    return GTIURLDataFactory.build(
        id="https://threat.example.com",
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
                threat_score=ThreatScoreFactory.build(value=70),
                verdict=None,
            ),
        ),
    )


@pytest.fixture
def url_with_malicious_verdict() -> GTIURLData:
    """Fixture for URL data with malicious verdict."""
    return GTIURLDataFactory.build(
        id="https://malware.example.com",
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def url_with_benign_verdict() -> GTIURLData:
    """Fixture for URL data with benign verdict."""
    return GTIURLDataFactory.build(
        id="https://google.com",
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="BENIGN"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def url_with_suspicious_verdict() -> GTIURLData:
    """Fixture for URL data with suspicious verdict."""
    return GTIURLDataFactory.build(
        id="https://suspicious.example.com",
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="SUSPICIOUS"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def url_with_all_data() -> GTIURLData:
    """Fixture for URL data with all available data."""
    return GTIURLDataFactory.build(
        id="url-comprehensive-123",
        attributes=URLModelFactory.build(
            url="https://original.example.com/malware",
            last_final_url="https://final.example.com/endpoint",
            first_submission_date=1672531200,
            last_modification_date=1672617600,
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS"),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=95
                ),
                threat_score=ThreatScoreFactory.build(value=85),
            ),
        ),
    )


@pytest.fixture
def url_without_attributes() -> GTIURLData:
    """Fixture for URL data without attributes."""
    return GTIURLDataFactory.build(id="https://localhost", attributes=None)


@pytest.fixture
def url_with_empty_verdict() -> GTIURLData:
    """Fixture for URL data with empty verdict."""
    return GTIURLDataFactory.build(
        id="https://empty.example.com",
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value=""),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def url_with_invalid_timestamps() -> GTIURLData:
    """Fixture for URL data with invalid timestamps."""
    return GTIURLDataFactory.build(
        id="https://invalid.example.com",
        attributes=URLModelFactory.build(
            first_submission_date=-1,
            last_modification_date=0,
            gti_assessment=None,
        ),
    )


# Scenario: Convert GTI URL with minimal data to STIX objects
def test_gti_url_to_stix_minimal_data(
    minimal_url_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with minimal data to STIX objects."""
    # Given a GTI URL with minimal data
    mapper = _given_gti_url_mapper(
        minimal_url_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then URL observable, indicator, and relationship should be created
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_url_has_correct_properties(
        url_observable, minimal_url_data, mock_organization, mock_tlp_marking
    )
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI URL with timestamps to STIX objects
def test_gti_url_to_stix_with_timestamps(
    url_with_timestamps: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with timestamps to STIX objects."""
    # Given a GTI URL with timestamps
    mapper = _given_gti_url_mapper(
        url_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_correct_timestamps(indicator, url_with_timestamps)


# Scenario: Convert GTI URL with specific URL value to STIX objects
def test_gti_url_to_stix_with_url_value(
    url_with_url_value: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with specific URL value to STIX objects."""
    # Given a GTI URL with specific URL value
    mapper = _given_gti_url_mapper(
        url_with_url_value, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should use the correct URL value
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_url_has_value(url_observable, "https://malicious.example.com/malware")
    _then_stix_indicator_has_url_pattern(
        indicator, "https://malicious.example.com/malware"
    )


# Scenario: Convert GTI URL with Mandiant confidence score to STIX objects
def test_gti_url_to_stix_with_mandiant_score(
    url_with_mandiant_score: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with mandiant confidence score to STIX objects."""
    # Given a GTI URL with mandiant confidence score
    mapper = _given_gti_url_mapper(
        url_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include mandiant score
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(url_observable, indicator, 85)


# Scenario: Convert GTI URL with threat score fallback to STIX objects
def test_gti_url_to_stix_with_threat_score(
    url_with_threat_score: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with threat score fallback to STIX objects."""
    # Given a GTI URL with threat score fallback
    mapper = _given_gti_url_mapper(
        url_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should use threat score as fallback
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(url_observable, indicator, 70)


# Scenario: Convert GTI URL with malicious verdict to STIX objects
def test_gti_url_to_stix_with_malicious_verdict(
    url_with_malicious_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with malicious verdict to STIX objects."""
    # Given a GTI URL with malicious verdict
    mapper = _given_gti_url_mapper(
        url_with_malicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with malicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))


# Scenario: Convert GTI URL with benign verdict to STIX objects
def test_gti_url_to_stix_with_benign_verdict(
    url_with_benign_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with benign verdict to STIX objects."""
    # Given a GTI URL with benign verdict
    mapper = _given_gti_url_mapper(
        url_with_benign_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with benign indicator type
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("BENIGN"))


# Scenario: Convert GTI URL with suspicious verdict to STIX objects
def test_gti_url_to_stix_with_suspicious_verdict(
    url_with_suspicious_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with suspicious verdict to STIX objects."""
    # Given a GTI URL with suspicious verdict
    mapper = _given_gti_url_mapper(
        url_with_suspicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with suspicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("SUSPICIOUS"))


# Scenario: Convert GTI URL with all data populated to STIX objects
def test_gti_url_to_stix_with_all_data(
    url_with_all_data: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with all data to STIX objects."""
    # Given a GTI URL with comprehensive data
    mapper = _given_gti_url_mapper(
        url_with_all_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include all available data
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_url_has_correct_properties(
        url_observable, url_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_objects_have_score(url_observable, indicator, 95)
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))
    _then_stix_indicator_has_correct_timestamps(indicator, url_with_all_data)
    _then_stix_url_has_value(url_observable, "https://original.example.com/malware")


# Scenario: Convert GTI URL without attributes to STIX objects
def test_gti_url_to_stix_without_attributes(
    url_without_attributes: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL without attributes to STIX objects."""
    # Given a GTI URL without attributes
    mapper = _given_gti_url_mapper(
        url_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then objects should still be created with fallback behavior
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI URL with empty verdict to STIX objects
def test_gti_url_to_stix_with_empty_verdict(
    url_with_empty_verdict: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with empty verdict to STIX objects."""
    # Given a GTI URL with empty verdict
    mapper = _given_gti_url_mapper(
        url_with_empty_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with unknown indicator type
    _then_stix_objects_created_successfully(stix_objects)
    url_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI URL with invalid timestamps to STIX objects
def test_gti_url_to_stix_with_invalid_timestamps(
    url_with_invalid_timestamps: GTIURLData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI URL with invalid timestamps to STIX objects."""
    # Given a GTI URL with invalid timestamps
    mapper = _given_gti_url_mapper(
        url_with_invalid_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Extract timestamps from GTI URL with valid timestamp data
def test_get_timestamps_with_valid_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method with valid timestamp data."""
    # Given a URL with valid timestamps
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            first_submission_date=1672531200,
            last_modification_date=1672617600,
        )
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then timestamps should be correctly converted
    expected_created = datetime.fromtimestamp(1672531200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1672617600, tz=timezone.utc)
    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


# Scenario: Extract timestamps from GTI URL without timestamp data
def test_get_timestamps_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method without timestamp data."""
    # Given a URL without timestamps
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            first_submission_date=None,
            last_modification_date=None,
        )
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then current time should be used
    assert isinstance(timestamps["created"], datetime)  # noqa: S101
    assert isinstance(timestamps["modified"], datetime)  # noqa: S101
    assert timestamps["created"].tzinfo == timezone.utc  # noqa: S101
    assert timestamps["modified"].tzinfo == timezone.utc  # noqa: S101


# Scenario: Extract score with mandiant confidence score available
def test_get_score_with_mandiant_score(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method with mandiant confidence score."""
    # Given a URL with mandiant confidence score
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            )
        )
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then score should be returned
    assert score == 85  # noqa: S101


# Scenario: Extract score with threat score fallback
def test_get_score_with_threat_score_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method with threat score fallback."""
    # Given a URL with threat score but no mandiant score
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
                threat_score=ThreatScoreFactory.build(value=70),
            )
        )
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then threat score should be returned as fallback
    assert score == 70  # noqa: S101


# Scenario: Extract score without any score data available
def test_get_score_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method without score data."""
    # Given a URL without score data
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then None should be returned
    assert score is None  # noqa: S101


# Scenario: Get URL value with url attribute
def test_get_url_value_with_url_attribute(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_url_value method with url attribute."""
    # Given a URL with url attribute
    url_data = GTIURLDataFactory.build(
        id="fallback-url",
        attributes=URLModelFactory.build(
            url="https://primary.example.com",
            last_final_url="https://final.example.com",
        ),
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When getting URL value
    url_value = mapper._get_url_value()

    # Then primary URL should be returned
    assert url_value == "https://primary.example.com"  # noqa: S101


# Scenario: Get URL value with final URL fallback
def test_get_url_value_with_final_url_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_url_value method with final URL fallback."""
    # Given a URL with final URL but no primary URL
    url_data = GTIURLDataFactory.build(
        id="fallback-url",
        attributes=URLModelFactory.build(
            url=None,
            last_final_url="https://final.example.com",
        ),
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When getting URL value
    url_value = mapper._get_url_value()

    # Then final URL should be returned
    assert url_value == "https://final.example.com"  # noqa: S101


# Scenario: Get URL value with ID fallback
def test_get_url_value_with_id_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_url_value method with ID fallback."""
    # Given a URL without url attributes
    url_data = GTIURLDataFactory.build(
        id="https://id-fallback.example.com",
        attributes=URLModelFactory.build(
            url=None,
            last_final_url=None,
        ),
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When getting URL value
    url_value = mapper._get_url_value()

    # Then ID should be returned as fallback
    assert url_value == "https://id-fallback.example.com"  # noqa: S101


# Scenario: Build STIX pattern with URL
def test_build_stix_pattern_with_url(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_stix_pattern method with URL."""
    # Given a URL
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            url="https://test.example.com/path",
        )
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When building STIX pattern
    pattern = mapper._build_stix_pattern()

    # Then URL pattern should be returned
    assert pattern == "[url:value = 'https://test.example.com/path']"  # noqa: S101


# Scenario: Test determine indicator types method
def test_determine_indicator_types_with_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method with verdict."""
    # Given a URL with malicious verdict
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        )
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then malicious indicator type should be returned
    assert indicator_types == [IndicatorTypeOV("MALICIOUS")]  # noqa: S101


# Scenario: Test determine indicator types method without verdict
def test_determine_indicator_types_without_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method without verdict."""
    # Given a URL without verdict
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then unknown indicator type should be returned
    assert indicator_types == [IndicatorTypeOV.UNKNOWN]  # noqa: S101


# Scenario: Test create STIX URL method
def test_create_stix_url_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_url method directly."""
    # Given a URL with score
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            url="https://test.example.com",
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                )
            ),
        ),
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When creating STIX URL
    url_observable = mapper._create_stix_url()

    # Then URL observable should be created correctly
    assert url_observable is not None  # noqa: S101
    assert hasattr(url_observable, "value")  # noqa: S101
    assert url_observable.value == "https://test.example.com"  # noqa: S101


# Scenario: Test create STIX indicator method
def test_create_stix_indicator_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_indicator method directly."""
    # Given a URL with verdict
    url_data = GTIURLDataFactory.build(
        attributes=URLModelFactory.build(
            url="https://test.example.com",
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            ),
        ),
    )
    mapper = _given_gti_url_mapper(url_data, mock_organization, mock_tlp_marking)

    # When creating STIX indicator
    indicator = mapper._create_stix_indicator()

    # Then indicator should be created correctly
    assert indicator is not None  # noqa: S101
    assert hasattr(indicator, "name")  # noqa: S101
    assert indicator.name == "https://test.example.com"  # noqa: S101
    assert indicator.pattern == "[url:value = 'https://test.example.com']"  # noqa: S101


def _given_gti_url_mapper(
    url: GTIURLData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIUrlToSTIXUrl:
    """Create a GTIUrlToSTIXUrl mapper instance."""
    return GTIUrlToSTIXUrl(
        url=url,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIUrlToSTIXUrl) -> List[Any]:
    """Convert GTI URL to STIX objects."""
    return mapper.to_stix()


def _then_stix_objects_created_successfully(stix_objects: List[Any]) -> None:
    """Assert that STIX objects were created successfully."""
    assert stix_objects is not None  # noqa: S101
    assert len(stix_objects) == 3  # noqa: S101
    url_observable, indicator, relationship = stix_objects
    assert url_observable is not None  # noqa: S101
    assert indicator is not None  # noqa: S101
    assert relationship is not None  # noqa: S101


def _then_stix_url_has_correct_properties(
    url_observable: Any,
    gti_url: GTIURLData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Assert that STIX URL observable has correct properties."""
    assert hasattr(url_observable, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in url_observable.object_marking_refs  # noqa: S101


def _then_stix_objects_have_score(
    url_observable: Any, indicator: Any, expected_score: int
) -> None:
    """Assert that STIX objects have score."""
    if hasattr(url_observable, "score"):
        assert url_observable.score == expected_score  # noqa: S101
    if hasattr(indicator, "score"):
        assert indicator.score == expected_score  # noqa: S101


def _then_stix_indicator_has_type(
    indicator: Any, expected_type: IndicatorTypeOV
) -> None:
    """Assert that STIX indicator has correct type."""
    assert hasattr(indicator, "indicator_types")  # noqa: S101
    assert expected_type in indicator.indicator_types  # noqa: S101


def _then_stix_indicator_has_unknown_type(indicator: Any) -> None:
    """Assert that STIX indicator has unknown type."""
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV.UNKNOWN)


def _then_stix_indicator_has_correct_timestamps(
    indicator: Any, gti_url: GTIURLData
) -> None:
    """Assert that STIX indicator has correct timestamps."""
    if gti_url.attributes and gti_url.attributes.first_submission_date:
        expected_created = datetime.fromtimestamp(
            gti_url.attributes.first_submission_date, tz=timezone.utc
        )
        assert indicator.created == expected_created  # noqa: S101


def _then_stix_url_has_value(url_observable: Any, expected_value: str) -> None:
    """Assert that STIX URL has correct value."""
    assert hasattr(url_observable, "value")  # noqa: S101
    assert url_observable.value == expected_value  # noqa: S101


def _then_stix_indicator_has_url_pattern(indicator: Any, expected_url: str) -> None:
    """Assert that STIX indicator has correct URL pattern."""
    expected_pattern = f"[url:value = '{expected_url}']"
    assert indicator.pattern == expected_pattern  # noqa: S101
