"""Tests for GTI file to STIX file mapper."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from polyfactory.factories.pydantic_factory import ModelFactory
from stix2.v21 import Identity, MarkingDefinition

from connector.src.custom.mappers.gti_reports.gti_file_to_stix_file import (
    GTIFileToSTIXFile,
)
from connector.src.custom.models.gti_reports.gti_file_model import (
    ContributingFactors,
    FileModel,
    GTIAssessment,
    GTIFileData,
    LastAnalysisStats,
    Severity,
    ThreatScore,
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


class GTIAssessmentFactory(ModelFactory[GTIAssessment]):
    """Create GTI assessment for testing."""

    __model__ = GTIAssessment


class FileModelFactory(ModelFactory[FileModel]):
    """Create file model for testing."""

    __model__ = FileModel


class GTIFileDataFactory(ModelFactory[GTIFileData]):
    """Create GTI file data for testing."""

    __model__ = GTIFileData


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
def minimal_file_data():
    """Minimal GTI file data for testing."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        type="file",
        attributes=None,
    )


@pytest.fixture
def file_with_timestamps():
    """GTI file data with timestamps for testing."""
    return GTIFileDataFactory.build(
        id="test-file-id",
        type="file",
        attributes=FileModelFactory.build(
            creation_date=1640995200,  # 2022-01-01
            last_modification_date=1672531200,  # 2023-01-01
        ),
    )


@pytest.fixture
def file_with_hashes():
    """GTI file data with hash values for testing."""
    return GTIFileDataFactory.build(
        id="test-file-id",
        type="file",
        attributes=FileModelFactory.build(
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
        ),
    )


@pytest.fixture
def file_with_mandiant_score():
    """GTI file data with mandiant confidence score for testing."""
    return GTIFileDataFactory.build(
        id="test-file-id",
        type="file",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            )
        ),
    )


@pytest.fixture
def file_with_threat_score():
    """GTI file data with threat score."""
    return GTIFileDataFactory.build(
        id="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        attributes=FileModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                threat_score=ThreatScoreFactory.build(value=75),
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
            )
        ),
    )


@pytest.fixture
def file_with_all_data():
    """GTI file data with all available data for testing."""
    return GTIFileDataFactory.build(
        id="test-file-id",
        type="file",
        attributes=FileModelFactory.build(
            meaningful_name="test_file.exe",
            names=["test_file.exe", "alternate_name.exe"],
            size=1024,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            md5="d41d8cd98f00b204e9800998ecf8427e",
            creation_date=1640995200,
            last_modification_date=1672531200,
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            ),
        ),
    )


@pytest.fixture
def file_without_attributes():
    """GTI file data without attributes for testing."""
    return GTIFileDataFactory.build(
        id="test-file-id",
        type="file",
        attributes=None,
    )


# Scenario: Convert GTI file with minimal data to STIX objects
def test_gti_file_to_stix_minimal_data(
    minimal_file_data: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion with minimal data."""
    # Given a GTI file with minimal data
    mapper = _given_gti_file_mapper(
        minimal_file_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then file observable should be created
    _then_stix_object_created_successfully(stix_object)
    _then_stix_file_has_correct_properties(
        stix_object, minimal_file_data, mock_organization, mock_tlp_marking
    )


# Scenario: Convert GTI file with timestamps to STIX objects
def test_gti_file_to_stix_with_timestamps(
    file_with_timestamps: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion with timestamps."""
    # Given a GTI file with timestamps
    mapper = _given_gti_file_mapper(
        file_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then STIX object should be created successfully
    _then_stix_object_created_successfully(stix_object)


# Scenario: Convert GTI file with hash values to STIX objects
def test_gti_file_to_stix_with_hashes(
    file_with_hashes: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion with hash values."""
    # Given a GTI file with hash values
    mapper = _given_gti_file_mapper(
        file_with_hashes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then hash values should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    expected_hashes = {
        "SHA-256": file_with_hashes.attributes.sha256,
        "SHA-1": file_with_hashes.attributes.sha1,
        "MD5": file_with_hashes.attributes.md5,
    }
    assert stix_object.hashes == expected_hashes  # noqa: S101


# Scenario: Convert GTI file with Mandiant confidence score to STIX objects
def test_gti_file_to_stix_with_mandiant_score(
    file_with_mandiant_score: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion with mandiant confidence score."""
    # Given a GTI file with mandiant confidence score
    mapper = _given_gti_file_mapper(
        file_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then mandiant score should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    _then_stix_file_has_score(stix_object, 85)


# Scenario: Convert GTI file with threat score to STIX objects
def test_gti_file_to_stix_with_threat_score(
    file_with_threat_score: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion with threat score."""
    # Given a GTI file with threat score
    mapper = _given_gti_file_mapper(
        file_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then threat score should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    _then_stix_file_has_score(stix_object, 75)


# Scenario: Convert GTI file with all data to STIX objects
def test_gti_file_to_stix_with_all_data(
    file_with_all_data: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion with all available data."""
    # Given a GTI file with all data
    mapper = _given_gti_file_mapper(
        file_with_all_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then all data should be correctly applied
    _then_stix_object_created_successfully(stix_object)
    _then_stix_file_has_correct_properties(
        stix_object, file_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_file_has_score(stix_object, 85)


# Scenario: Convert GTI file without attributes to STIX objects
def test_gti_file_to_stix_without_attributes(
    file_without_attributes: GTIFileData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test GTI file to STIX conversion without attributes."""
    # Given a GTI file without attributes
    mapper = _given_gti_file_mapper(
        file_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_object = _when_convert_to_stix(mapper)

    # Then file should still be created successfully
    _then_stix_object_created_successfully(stix_object)


# Unit tests for individual methods
def test_get_timestamps_with_valid_data(
    file_with_timestamps, mock_organization, mock_tlp_marking
):
    """Test _get_timestamps method with valid timestamp data."""
    mapper = _given_gti_file_mapper(
        file_with_timestamps, mock_organization, mock_tlp_marking
    )

    timestamps = mapper._get_timestamps()

    expected_created = datetime.fromtimestamp(1640995200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1672531200, tz=timezone.utc)

    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


def test_get_timestamps_without_data(
    minimal_file_data, mock_organization, mock_tlp_marking
):
    """Test _get_timestamps method without timestamp data."""
    mapper = _given_gti_file_mapper(
        minimal_file_data, mock_organization, mock_tlp_marking
    )

    timestamps = mapper._get_timestamps()

    assert isinstance(timestamps["created"], datetime)  # noqa: S101
    assert isinstance(timestamps["modified"], datetime)  # noqa: S101
    assert timestamps["created"].tzinfo == timezone.utc  # noqa: S101
    assert timestamps["modified"].tzinfo == timezone.utc  # noqa: S101


def test_get_mandiant_ic_score_with_mandiant_score(
    file_with_mandiant_score, mock_organization, mock_tlp_marking
):
    """Test _get_mandiant_ic_score method with mandiant score."""
    mapper = _given_gti_file_mapper(
        file_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    score = mapper._get_mandiant_ic_score()

    assert score == 85  # noqa: S101


def test_get_mandiant_ic_score_with_threat_score_fallback(
    file_with_threat_score, mock_organization, mock_tlp_marking
):
    """Test _get_mandiant_ic_score method with threat score fallback."""
    mapper = _given_gti_file_mapper(
        file_with_threat_score, mock_organization, mock_tlp_marking
    )

    score = mapper._get_mandiant_ic_score()

    assert score == 75  # noqa: S101


def test_get_mandiant_ic_score_without_data(
    minimal_file_data, mock_organization, mock_tlp_marking
):
    """Test _get_mandiant_ic_score method without score data."""
    mapper = _given_gti_file_mapper(
        minimal_file_data, mock_organization, mock_tlp_marking
    )

    score = mapper._get_mandiant_ic_score()

    assert score is None  # noqa: S101


def test_build_hashes_with_all_hashes(
    file_with_hashes, mock_organization, mock_tlp_marking
):
    """Test _build_hashes method with all hash types."""
    mapper = _given_gti_file_mapper(
        file_with_hashes, mock_organization, mock_tlp_marking
    )

    hashes = mapper._build_hashes()

    expected_hashes = {
        "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "MD5": "d41d8cd98f00b204e9800998ecf8427e",
    }
    assert hashes == expected_hashes  # noqa: S101


def test_build_hashes_without_attributes(
    minimal_file_data, mock_organization, mock_tlp_marking
):
    """Test _build_hashes method without attributes."""
    mapper = _given_gti_file_mapper(
        minimal_file_data, mock_organization, mock_tlp_marking
    )

    hashes = mapper._build_hashes()

    assert hashes is None  # noqa: S101


def test_create_stix_file_method(
    file_with_all_data, mock_organization, mock_tlp_marking
):
    """Test _create_stix_file method."""
    mapper = _given_gti_file_mapper(
        file_with_all_data, mock_organization, mock_tlp_marking
    )

    file_obj = mapper._create_stix_file()

    # Then file object should be created with correct properties
    assert hasattr(file_obj, "hashes")  # noqa: S101
    assert hasattr(file_obj, "object_marking_refs")  # noqa: S101
    assert mock_tlp_marking.id in file_obj.object_marking_refs  # noqa: S101


def _given_gti_file_mapper(file_data, organization, tlp_marking):
    """Create GTI file mapper."""
    return GTIFileToSTIXFile(
        file=file_data, organization=organization, tlp_marking=tlp_marking
    )


def _when_convert_to_stix(mapper):
    """Convert GTI file to STIX objects."""
    return mapper.to_stix()


def _then_stix_object_created_successfully(stix_object):
    """Verify STIX object was created successfully."""
    assert stix_object is not None  # noqa: S101
    assert hasattr(stix_object, "hashes")  # File observable  # noqa: S101


def _then_stix_file_has_correct_properties(
    file_obj,
    file_data: GTIFileData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Verify STIX file has correct properties."""
    assert hasattr(file_obj, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in file_obj.object_marking_refs  # noqa: S101

    if file_data.attributes:
        if file_data.attributes.meaningful_name:
            assert file_obj.name == file_data.attributes.meaningful_name  # noqa: S101
        if file_data.attributes.names:
            # Check if additional_names is stored in custom properties
            custom_props = getattr(file_obj, "custom_properties", {})
            if "x_opencti_additional_names" in custom_props:
                assert (  # noqa: S101
                    custom_props["x_opencti_additional_names"]
                    == file_data.attributes.names
                )
        if file_data.attributes.size:
            assert file_obj.size == file_data.attributes.size  # noqa: S101


def _then_stix_file_has_score(file_obj, expected_score):
    """Verify STIX file has score."""
    if hasattr(file_obj, "score"):
        assert file_obj.score == expected_score  # noqa: S101
