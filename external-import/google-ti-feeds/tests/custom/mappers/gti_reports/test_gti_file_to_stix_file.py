"""Tests for GTI file to STIX file mapper."""

from datetime import datetime, timezone
from typing import Any, List
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.models.gti_reports.gti_file_model import (
    ContributingFactors,
    FileModel,
    GTIAssessment,
    GTIFileData,
    ThreatScore,
    Verdict,
)
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition


class VerdictFactory(ModelFactory[Verdict]):
    """Create verdict for testing."""

    __model__ = Verdict


class ThreatScoreFactory(ModelFactory[ThreatScore]):
    """Create threat score for testing."""

    __model__ = ThreatScore


class ContributingFactorsFactory(ModelFactory[ContributingFactors]):
    """Create contributing factors for testing."""

    __model__ = ContributingFactors


class GTIAssessmentFactory(ModelFactory[GTIAssessment]):
    """Create GTI assessment for testing."""

    __model__ = GTIAssessment


class FileModelFactory(ModelFactory[FileModel]):
    """Create file model for testing."""

    __model__ = FileModel


class GTIFileDataFactory(ModelFactory[GTIFileData]):
    """Create GTI file data for testing."""

    __model__ = GTIFileData

    type = "file"
    attributes = Use(FileModelFactory.build)


@pytest.fixture
def mock_organization() -> Identity:
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
def minimal_file_data() -> GTIFileData:
    """Minimal GTI file data for testing."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            creation_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def file_with_timestamps() -> GTIFileData:
    """GTI file data with timestamps."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            creation_date=1640995200,
            last_modification_date=1641081600,
            first_submission_date=1640995200,
            last_submission_date=1641081600,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def file_with_hashes() -> GTIFileData:
    """GTI file data with hash values."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            gti_assessment=None,
        ),
    )


@pytest.fixture
def file_with_mandiant_score() -> GTIFileData:
    """GTI file data with mandiant confidence score."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                ),
                threat_score=None,
                verdict=None,
            )
        ),
    )


@pytest.fixture
def file_with_threat_score() -> GTIFileData:
    """GTI file data with threat score."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                threat_score=ThreatScoreFactory.build(value=75),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
                verdict=None,
            )
        ),
    )


@pytest.fixture
def file_with_malicious_verdict() -> GTIFileData:
    """GTI file data with malicious verdict."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS"),
                contributing_factors=None,
                threat_score=None,
            )
        ),
    )


@pytest.fixture
def file_with_benign_verdict() -> GTIFileData:
    """GTI file data with benign verdict."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="BENIGN"),
                contributing_factors=None,
                threat_score=None,
            )
        ),
    )


@pytest.fixture
def file_with_suspicious_verdict() -> GTIFileData:
    """GTI file data with suspicious verdict."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="SUSPICIOUS"),
                contributing_factors=None,
                threat_score=None,
            )
        ),
    )


@pytest.fixture
def file_with_all_data() -> GTIFileData:
    """GTI file data with all attributes populated."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            meaningful_name="test_file.exe",
            names=["test_file.exe", "malware.exe"],
            size=1024,
            creation_date=1640995200,
            last_modification_date=1641081600,
            first_submission_date=1640995200,
            last_submission_date=1641081600,
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS"),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                ),
                threat_score=ThreatScoreFactory.build(value=85),
            ),
        ),
    )


@pytest.fixture
def file_without_attributes() -> GTIFileData:
    """GTI file data without attributes."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=None,
    )


@pytest.fixture
def file_with_empty_verdict() -> GTIFileData:
    """GTI file data with empty verdict."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value=""),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def file_with_invalid_timestamps() -> GTIFileData:
    """GTI file data with invalid timestamp values."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            creation_date=-1,
            last_modification_date=0,
            gti_assessment=None,
        ),
    )


# Scenario: Convert GTI file with minimal data to STIX objects
def test_gti_file_to_stix_minimal_data(
    minimal_file_data: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with minimal data to STIX objects."""
    # Given a GTI file with minimal data
    mapper = _given_gti_file_mapper(
        minimal_file_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then file observable, indicator, and relationship should be created
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_file_has_correct_properties(
        file_observable, minimal_file_data, mock_organization, mock_tlp_marking
    )
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI file with timestamps to STIX objects
def test_gti_file_to_stix_with_timestamps(
    file_with_timestamps: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with timestamps to STIX objects."""
    # Given a GTI file with timestamps
    mapper = _given_gti_file_mapper(
        file_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_correct_timestamps(indicator, file_with_timestamps)


# Scenario: Convert GTI file with hashes to STIX objects
def test_gti_file_to_stix_with_hashes(
    file_with_hashes: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with hashes to STIX objects."""
    # Given a GTI file with hash values
    mapper = _given_gti_file_mapper(
        file_with_hashes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with correct hashes
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_file_has_hashes(file_observable, file_with_hashes)
    _then_stix_indicator_has_hash_pattern(indicator, file_with_hashes)


# Scenario: Convert GTI file with Mandiant confidence score to STIX objects
def test_gti_file_to_stix_with_mandiant_score(
    file_with_mandiant_score: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with mandiant confidence score to STIX objects."""
    # Given a GTI file with mandiant confidence score
    mapper = _given_gti_file_mapper(
        file_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include mandiant score
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(file_observable, indicator, 85)


# Scenario: Convert GTI file with threat score fallback to STIX objects
def test_gti_file_to_stix_with_threat_score(
    file_with_threat_score: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with threat score fallback to STIX objects."""
    # Given a GTI file with threat score fallback
    mapper = _given_gti_file_mapper(
        file_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should use threat score as fallback
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(file_observable, indicator, 75)


# Scenario: Convert GTI file with malicious verdict to STIX objects
def test_gti_file_to_stix_with_malicious_verdict(
    file_with_malicious_verdict: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with malicious verdict to STIX objects."""
    # Given a GTI file with malicious verdict
    mapper = _given_gti_file_mapper(
        file_with_malicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with malicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))


# Scenario: Convert GTI file with benign verdict to STIX objects
def test_gti_file_to_stix_with_benign_verdict(
    file_with_benign_verdict: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with benign verdict to STIX objects."""
    # Given a GTI file with benign verdict
    mapper = _given_gti_file_mapper(
        file_with_benign_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with benign indicator type
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("BENIGN"))


# Scenario: Convert GTI file with suspicious verdict to STIX objects
def test_gti_file_to_stix_with_suspicious_verdict(
    file_with_suspicious_verdict: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with suspicious verdict to STIX objects."""
    # Given a GTI file with suspicious verdict
    mapper = _given_gti_file_mapper(
        file_with_suspicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with suspicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("SUSPICIOUS"))


# Scenario: Convert GTI file with all data populated to STIX objects
def test_gti_file_to_stix_with_all_data(
    file_with_all_data: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with all data to STIX objects."""
    # Given a GTI file with comprehensive data
    mapper = _given_gti_file_mapper(
        file_with_all_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include all available data
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_file_has_correct_properties(
        file_observable, file_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_objects_have_score(file_observable, indicator, 90)
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))
    _then_stix_indicator_has_correct_timestamps(indicator, file_with_all_data)
    _then_stix_file_has_hashes(file_observable, file_with_all_data)


# Scenario: Convert GTI file without attributes to STIX objects
def test_gti_file_to_stix_without_attributes(
    file_without_attributes: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file without attributes to STIX objects."""
    # Given a GTI file without attributes
    mapper = _given_gti_file_mapper(
        file_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then objects should still be created with fallback behavior
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI file with empty verdict to STIX objects
def test_gti_file_to_stix_with_empty_verdict(
    file_with_empty_verdict: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with empty verdict to STIX objects."""
    # Given a GTI file with empty verdict
    mapper = _given_gti_file_mapper(
        file_with_empty_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with unknown indicator type
    _then_stix_objects_created_successfully(stix_objects)
    file_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI file with invalid timestamps to STIX objects
def test_gti_file_to_stix_with_invalid_timestamps(
    file_with_invalid_timestamps: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI file with invalid timestamps to STIX objects."""
    # Given a GTI file with invalid timestamps
    mapper = _given_gti_file_mapper(
        file_with_invalid_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Extract timestamps from GTI file with valid timestamp data
def test_get_timestamps_with_valid_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method with valid timestamp data."""
    # Given a file with valid timestamps
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            creation_date=1640995200,
            last_modification_date=1641081600,
            first_submission_date=1640995200,
            last_submission_date=1641081600,
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then timestamps should be correctly converted
    expected_created = datetime.fromtimestamp(1640995200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1641081600, tz=timezone.utc)
    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


# Scenario: Extract timestamps from GTI file without timestamp data
def test_get_timestamps_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method without timestamp data."""
    # Given a file without timestamps
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            creation_date=None,
            last_modification_date=None,
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

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
    # Given a file with mandiant confidence score
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            )
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then score should be returned
    assert score == 85  # noqa: S101


# Scenario: Extract score with threat score fallback
def test_get_score_with_threat_score_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method with threat score fallback."""
    # Given a file with threat score but no mandiant score
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
                threat_score=ThreatScoreFactory.build(value=70),
            )
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then threat score should be returned as fallback
    assert score == 70  # noqa: S101


# Scenario: Extract score without any score data available
def test_get_score_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method without score data."""
    # Given a file without score data
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then None should be returned
    assert score is None  # noqa: S101


# Scenario: Build hashes with all hash types
def test_build_hashes_with_all_hashes(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_hashes method with all hash types."""
    # Given a file with all hash types
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When building hashes
    hashes = mapper._build_hashes()

    # Then all hashes should be included
    expected_hashes = {
        "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
    }
    assert hashes == expected_hashes  # noqa: S101


# Scenario: Build hashes without attributes
def test_build_hashes_without_attributes(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_hashes method without attributes."""
    # Given a file without attributes
    file_data = GTIFileDataFactory.build(attributes=None)
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When building hashes
    hashes = mapper._build_hashes()

    # Then None should be returned
    assert hashes is None  # noqa: S101


# Scenario: Build STIX pattern with hashes
def test_build_stix_pattern_with_hashes(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_stix_pattern method with hashes."""
    # Given a file with hashes
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            md5="d41d8cd98f00b204e9800998ecf8427e",
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When building STIX pattern
    pattern = mapper._build_stix_pattern()

    # Then pattern should include both hashes
    assert (  # noqa: S101
        "file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"
        in pattern
    )
    assert (  # noqa: S101
        "file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e'" in pattern
    )
    assert " OR " in pattern  # noqa: S101


# Scenario: Build STIX pattern fallback
def test_build_stix_pattern_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_stix_pattern method fallback."""
    # Given a file without hash attributes
    file_data = GTIFileDataFactory.build(
        id="test_hash",
        attributes=FileModelFactory.build(
            sha256=None,
            md5=None,
            sha1=None,
        ),
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When building STIX pattern
    pattern = mapper._build_stix_pattern()

    # Then fallback pattern should use file ID
    expected_pattern = "[file:hashes.'SHA-256' = 'test_hash']"
    assert pattern == expected_pattern  # noqa: S101


# Scenario: Test determine indicator types method
def test_determine_indicator_types_with_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method with verdict."""
    # Given a file with malicious verdict
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then malicious indicator type should be returned
    assert indicator_types == [IndicatorTypeOV("MALICIOUS")]  # noqa: S101


# Scenario: Test determine indicator types method without verdict
def test_determine_indicator_types_without_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method without verdict."""
    # Given a file without verdict
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then unknown indicator type should be returned
    assert indicator_types == [IndicatorTypeOV.UNKNOWN]  # noqa: S101


# Scenario: Test create STIX file method
def test_create_stix_file_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_file method directly."""
    # Given a file with score and creation date
    file_data = GTIFileDataFactory.build(
        id="test_file_hash",
        attributes=FileModelFactory.build(
            meaningful_name="test.exe",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            creation_date=1640995200,
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                )
            ),
        ),
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When creating STIX file
    file_observable = mapper._create_stix_file()

    # Then file observable should be created correctly
    assert file_observable is not None  # noqa: S101
    assert hasattr(file_observable, "hashes")  # noqa: S101
    assert hasattr(file_observable, "name")  # noqa: S101
    assert hasattr(file_observable, "ctime")  # noqa: S101
    _then_stix_file_has_correct_ctime(file_observable, file_data)


# Scenario: Test create STIX indicator method
def test_create_stix_indicator_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_indicator method directly."""
    # Given a file with verdict
    file_data = GTIFileDataFactory.build(
        id="test_indicator_hash",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        ),
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When creating STIX indicator
    indicator = mapper._create_stix_indicator()

    # Then indicator should be created correctly
    assert indicator is not None  # noqa: S101
    assert hasattr(indicator, "pattern")  # noqa: S101
    assert hasattr(indicator, "indicator_types")  # noqa: S101


def test_file_observable_ctime_property(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test that file observable includes ctime when creation_date is available."""
    # Given a file with creation_date
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            creation_date=1640995200,
            meaningful_name="test.exe",
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When creating STIX file
    file_observable = mapper._create_stix_file()

    # Then file should have correct ctime
    _then_stix_file_has_correct_ctime(file_observable, file_data)


def test_file_observable_without_creation_date(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test that file observable has no ctime when creation_date is not available."""
    # Given a file without creation_date
    file_data = GTIFileDataFactory.build(
        attributes=FileModelFactory.build(
            meaningful_name="test.exe",
            creation_date=None,
        )
    )
    mapper = _given_gti_file_mapper(file_data, mock_organization, mock_tlp_marking)

    # When creating STIX file
    file_observable = mapper._create_stix_file()

    # Then file should not have ctime or it should be None
    _then_stix_file_has_correct_ctime(file_observable, file_data)


def _given_gti_file_mapper(
    file: GTIFileData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIFileToSTIXFile:
    """Create a GTIFileToSTIXFile mapper instance."""
    return GTIFileToSTIXFile(
        file=file,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIFileToSTIXFile) -> List[Any]:
    """Convert GTI file to STIX objects."""
    return mapper.to_stix()


def _then_stix_objects_created_successfully(stix_objects: List[Any]) -> None:
    """Assert that STIX objects were created successfully."""
    assert stix_objects is not None  # noqa: S101
    assert len(stix_objects) == 3  # noqa: S101
    file_observable, indicator, relationship = stix_objects
    assert file_observable is not None  # noqa: S101
    assert indicator is not None  # noqa: S101
    assert relationship is not None  # noqa: S101


def _then_stix_file_has_correct_properties(
    file_observable: Any,
    gti_file: GTIFileData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Assert that STIX file observable has correct properties."""
    assert hasattr(file_observable, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in file_observable.object_marking_refs  # noqa: S101
    _then_stix_file_has_correct_ctime(file_observable, gti_file)


def _then_stix_objects_have_score(
    file_observable: Any, indicator: Any, expected_score: int
) -> None:
    """Assert that STIX objects have score."""
    if hasattr(file_observable, "score"):
        assert file_observable.score == expected_score  # noqa: S101
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
    indicator: Any, gti_file: GTIFileData
) -> None:
    """Assert that STIX indicator has correct timestamps."""
    if gti_file.attributes and gti_file.attributes.first_submission_date:
        expected_created = datetime.fromtimestamp(
            gti_file.attributes.first_submission_date, tz=timezone.utc
        )
        assert indicator.created == expected_created  # noqa: S101
    if gti_file.attributes and gti_file.attributes.last_submission_date:
        expected_modified = datetime.fromtimestamp(
            gti_file.attributes.last_submission_date, tz=timezone.utc
        )
        assert indicator.modified == expected_modified  # noqa: S101


def _then_stix_file_has_hashes(file_observable: Any, gti_file: GTIFileData) -> None:
    """Assert that STIX file has correct hashes."""
    if gti_file.attributes:
        expected_hashes = {}
        if gti_file.attributes.sha256:
            expected_hashes["SHA-256"] = gti_file.attributes.sha256
        if gti_file.attributes.sha1:
            expected_hashes["SHA-1"] = gti_file.attributes.sha1
        if gti_file.attributes.md5:
            expected_hashes["MD5"] = gti_file.attributes.md5

        if expected_hashes:
            assert hasattr(file_observable, "hashes")  # noqa: S101
            assert file_observable.hashes == expected_hashes  # noqa: S101


def _then_stix_indicator_has_hash_pattern(
    indicator: Any, gti_file: GTIFileData
) -> None:
    """Assert that STIX indicator has correct hash pattern."""
    if gti_file.attributes:
        if gti_file.attributes.sha256:
            assert (  # noqa: S101
                f"file:hashes.'SHA-256' = '{gti_file.attributes.sha256}'"
                in indicator.pattern
            )
        if gti_file.attributes.md5:
            assert (  # noqa: S101
                f"file:hashes.MD5 = '{gti_file.attributes.md5}'" in indicator.pattern
            )
        if gti_file.attributes.sha1:
            assert (  # noqa: S101
                f"file:hashes.'SHA-1' = '{gti_file.attributes.sha1}'"
                in indicator.pattern
            )


def _then_stix_file_has_correct_ctime(
    file_observable: Any, gti_file: GTIFileData
) -> None:
    """Assert that STIX file has correct ctime (creation timestamp)."""
    if gti_file.attributes and gti_file.attributes.creation_date:
        expected_ctime = datetime.fromtimestamp(
            gti_file.attributes.creation_date, tz=timezone.utc
        )
        assert hasattr(file_observable, "ctime")  # noqa: S101
        assert file_observable.ctime == expected_ctime  # noqa: S101
    else:
        # If no creation_date, ctime should be None
        if hasattr(file_observable, "ctime"):
            assert file_observable.ctime is None  # noqa: S101
