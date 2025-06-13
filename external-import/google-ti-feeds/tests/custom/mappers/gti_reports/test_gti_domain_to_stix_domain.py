"""Tests for the GTIDomainToSTIXDomain mapper."""

from datetime import datetime, timezone
from typing import Any, List
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_domain_to_stix_domain import (
    GTIDomainToSTIXDomain,
)
from connector.src.custom.models.gti_reports.gti_domain_model import (
    ContributingFactors,
    DomainModel,
    GTIAssessment,
    GTIDomainData,
    ThreatScore,
    Verdict,
)
from connector.src.stix.v21.models.ovs.indicator_type_ov_enums import IndicatorTypeOV
from polyfactory.factories.pydantic_factory import ModelFactory
from polyfactory.fields import Use
from stix2.v21 import Identity, MarkingDefinition  # type: ignore


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


class DomainModelFactory(ModelFactory[DomainModel]):
    """Factory for DomainModel."""

    __model__ = DomainModel


class GTIDomainDataFactory(ModelFactory[GTIDomainData]):
    """Factory for GTIDomainData."""

    __model__ = GTIDomainData

    type = "domain"
    attributes = Use(DomainModelFactory.build)


@pytest.fixture
def mock_organization() -> Identity:
    """Fixture for mock organization identity."""
    return Identity(  # pylint: disable=W9101  # it's a test no real ingest
        name="Test Organization",
        identity_class="organization",
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
def minimal_domain_data() -> GTIDomainData:
    """Fixture for minimal domain data."""
    return GTIDomainDataFactory.build(
        id="example.com",
        attributes=DomainModelFactory.build(
            creation_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def domain_with_timestamps() -> GTIDomainData:
    """Fixture for domain data with timestamps."""
    return GTIDomainDataFactory.build(
        id="example.com",
        attributes=DomainModelFactory.build(
            creation_date=1672531200,
            last_modification_date=1672617600,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def domain_with_mandiant_score() -> GTIDomainData:
    """Fixture for domain data with mandiant confidence score."""
    return GTIDomainDataFactory.build(
        id="malicious.example.com",
        attributes=DomainModelFactory.build(
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
def domain_with_threat_score() -> GTIDomainData:
    """Fixture for domain data with threat score fallback."""
    return GTIDomainDataFactory.build(
        id="suspicious.example.com",
        attributes=DomainModelFactory.build(
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
def domain_with_malicious_verdict() -> GTIDomainData:
    """Fixture for domain data with malicious verdict."""
    return GTIDomainDataFactory.build(
        id="malicious.example.com",
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def domain_with_benign_verdict() -> GTIDomainData:
    """Fixture for domain data with benign verdict."""
    return GTIDomainDataFactory.build(
        id="benign.example.com",
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="BENIGN"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def domain_with_suspicious_verdict() -> GTIDomainData:
    """Fixture for domain data with suspicious verdict."""
    return GTIDomainDataFactory.build(
        id="suspicious.example.com",
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="SUSPICIOUS"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def domain_with_all_data() -> GTIDomainData:
    """Fixture for domain data with all available data."""
    return GTIDomainDataFactory.build(
        id="comprehensive.example.com",
        attributes=DomainModelFactory.build(
            creation_date=1672531200,
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
def domain_without_attributes() -> GTIDomainData:
    """Fixture for domain data without attributes."""
    return GTIDomainDataFactory.build(id="no-attrs.example.com", attributes=None)


@pytest.fixture
def domain_with_empty_verdict() -> GTIDomainData:
    """Fixture for domain data with empty verdict."""
    return GTIDomainDataFactory.build(
        id="empty-verdict.example.com",
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value=""),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def domain_with_invalid_timestamps() -> GTIDomainData:
    """Fixture for domain data with invalid timestamps."""
    return GTIDomainDataFactory.build(
        id="invalid-timestamps.example.com",
        attributes=DomainModelFactory.build(
            creation_date=-1,
            last_modification_date=0,
            gti_assessment=None,
        ),
    )


# Scenario: Convert GTI domain with minimal data to STIX objects
def test_gti_domain_to_stix_minimal_data(
    minimal_domain_data: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with minimal data to STIX objects."""
    # Given a GTI domain with minimal data
    mapper = _given_gti_domain_mapper(
        minimal_domain_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then domain observable, indicator, and relationship should be created
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_domain_has_correct_properties(
        domain_observable, minimal_domain_data, mock_organization, mock_tlp_marking
    )
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI domain with timestamps to STIX objects
def test_gti_domain_to_stix_with_timestamps(
    domain_with_timestamps: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with timestamps to STIX objects."""
    # Given a GTI domain with timestamps
    mapper = _given_gti_domain_mapper(
        domain_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_correct_timestamps(indicator, domain_with_timestamps)


# Scenario: Convert GTI domain with Mandiant confidence score to STIX objects
def test_gti_domain_to_stix_with_mandiant_score(
    domain_with_mandiant_score: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with mandiant confidence score to STIX objects."""
    # Given a GTI domain with mandiant confidence score
    mapper = _given_gti_domain_mapper(
        domain_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include mandiant score
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(domain_observable, indicator, 85)


# Scenario: Convert GTI domain with threat score fallback to STIX objects
def test_gti_domain_to_stix_with_threat_score(
    domain_with_threat_score: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with threat score fallback to STIX objects."""
    # Given a GTI domain with threat score fallback
    mapper = _given_gti_domain_mapper(
        domain_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should use threat score as fallback
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(domain_observable, indicator, 70)


# Scenario: Convert GTI domain with malicious verdict to STIX objects
def test_gti_domain_to_stix_with_malicious_verdict(
    domain_with_malicious_verdict: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with malicious verdict to STIX objects."""
    # Given a GTI domain with malicious verdict
    mapper = _given_gti_domain_mapper(
        domain_with_malicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with malicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))


# Scenario: Convert GTI domain with benign verdict to STIX objects
def test_gti_domain_to_stix_with_benign_verdict(
    domain_with_benign_verdict: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with benign verdict to STIX objects."""
    # Given a GTI domain with benign verdict
    mapper = _given_gti_domain_mapper(
        domain_with_benign_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with benign indicator type
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("BENIGN"))


# Scenario: Convert GTI domain with suspicious verdict to STIX objects
def test_gti_domain_to_stix_with_suspicious_verdict(
    domain_with_suspicious_verdict: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with suspicious verdict to STIX objects."""
    # Given a GTI domain with suspicious verdict
    mapper = _given_gti_domain_mapper(
        domain_with_suspicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with suspicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("SUSPICIOUS"))


# Scenario: Convert GTI domain with all data populated to STIX objects
def test_gti_domain_to_stix_with_all_data(
    domain_with_all_data: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with all data to STIX objects."""
    # Given a GTI domain with comprehensive data
    mapper = _given_gti_domain_mapper(
        domain_with_all_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include all available data
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_domain_has_correct_properties(
        domain_observable, domain_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_objects_have_score(domain_observable, indicator, 95)
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))
    _then_stix_indicator_has_correct_timestamps(indicator, domain_with_all_data)


# Scenario: Convert GTI domain without attributes to STIX objects
def test_gti_domain_to_stix_without_attributes(
    domain_without_attributes: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain without attributes to STIX objects."""
    # Given a GTI domain without attributes
    mapper = _given_gti_domain_mapper(
        domain_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then objects should still be created with fallback behavior
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI domain with empty verdict to STIX objects
def test_gti_domain_to_stix_with_empty_verdict(
    domain_with_empty_verdict: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with empty verdict to STIX objects."""
    # Given a GTI domain with empty verdict
    mapper = _given_gti_domain_mapper(
        domain_with_empty_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with unknown indicator type
    _then_stix_objects_created_successfully(stix_objects)
    domain_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI domain with invalid timestamps to STIX objects
def test_gti_domain_to_stix_with_invalid_timestamps(
    domain_with_invalid_timestamps: GTIDomainData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI domain with invalid timestamps to STIX objects."""
    # Given a GTI domain with invalid timestamps
    mapper = _given_gti_domain_mapper(
        domain_with_invalid_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Extract timestamps from GTI domain with valid timestamp data
def test_get_timestamps_with_valid_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method with valid timestamp data."""
    # Given a domain with valid timestamps
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(
            creation_date=1672531200,
            last_modification_date=1672617600,
        )
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then timestamps should be correctly converted
    expected_created = datetime.fromtimestamp(1672531200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1672617600, tz=timezone.utc)
    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


# Scenario: Extract timestamps from GTI domain without timestamp data
def test_get_timestamps_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method without timestamp data."""
    # Given a domain without timestamps
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(
            creation_date=None,
            last_modification_date=None,
        )
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

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
    # Given a domain with mandiant confidence score
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            )
        )
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then score should be returned
    assert score == 85  # noqa: S101


# Scenario: Extract score with threat score fallback
def test_get_score_with_threat_score_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method with threat score fallback."""
    # Given a domain with threat score but no mandiant score
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
                threat_score=ThreatScoreFactory.build(value=70),
            )
        )
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then threat score should be returned as fallback
    assert score == 70  # noqa: S101


# Scenario: Extract score without any score data available
def test_get_score_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method without score data."""
    # Given a domain without score data
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then None should be returned
    assert score is None  # noqa: S101


# Scenario: Test determine indicator types method
def test_determine_indicator_types_with_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method with verdict."""
    # Given a domain with malicious verdict
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        )
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then malicious indicator type should be returned
    assert indicator_types == [IndicatorTypeOV("MALICIOUS")]  # noqa: S101


# Scenario: Test determine indicator types method without verdict
def test_determine_indicator_types_without_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method without verdict."""
    # Given a domain without verdict
    domain_data = GTIDomainDataFactory.build(
        attributes=DomainModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then unknown indicator type should be returned
    assert indicator_types == [IndicatorTypeOV.UNKNOWN]  # noqa: S101


# Scenario: Test create STIX domain method
def test_create_stix_domain_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_domain method directly."""
    # Given a domain with mandiant score
    domain_data = GTIDomainDataFactory.build(
        id="test.example.com",
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                )
            )
        ),
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When creating STIX domain
    domain_observable = mapper._create_stix_domain()

    # Then domain observable should be created correctly
    assert domain_observable is not None  # noqa: S101
    assert hasattr(domain_observable, "value")  # noqa: S101
    assert domain_observable.value == "test.example.com"  # noqa: S101


# Scenario: Test create STIX indicator method
def test_create_stix_indicator_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_indicator method directly."""
    # Given a domain with verdict
    domain_data = GTIDomainDataFactory.build(
        id="test.example.com",
        attributes=DomainModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        ),
    )
    mapper = _given_gti_domain_mapper(domain_data, mock_organization, mock_tlp_marking)

    # When creating STIX indicator
    indicator = mapper._create_stix_indicator()

    # Then indicator should be created correctly
    assert indicator is not None  # noqa: S101
    assert hasattr(indicator, "name")  # noqa: S101
    assert indicator.name == "test.example.com"  # noqa: S101
    assert indicator.pattern == "[domain-name:value='test.example.com']"  # noqa: S101


def _given_gti_domain_mapper(
    domain: GTIDomainData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIDomainToSTIXDomain:
    """Create a GTIDomainToSTIXDomain mapper instance."""
    return GTIDomainToSTIXDomain(
        domain=domain,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIDomainToSTIXDomain) -> List[Any]:
    """Convert GTI domain to STIX objects."""
    return mapper.to_stix()


def _then_stix_objects_created_successfully(stix_objects: List[Any]) -> None:
    """Assert that STIX objects were created successfully."""
    assert stix_objects is not None  # noqa: S101
    assert len(stix_objects) == 3  # noqa: S101
    domain_observable, indicator, relationship = stix_objects
    assert domain_observable is not None  # noqa: S101
    assert indicator is not None  # noqa: S101
    assert relationship is not None  # noqa: S101


def _then_stix_domain_has_correct_properties(
    domain_observable: Any,
    gti_domain: GTIDomainData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Assert that STIX domain observable has correct properties."""
    assert domain_observable.value == gti_domain.id  # noqa: S101
    assert hasattr(domain_observable, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in domain_observable.object_marking_refs  # noqa: S101


def _then_stix_objects_have_score(
    domain_observable: Any, indicator: Any, expected_score: int
) -> None:
    """Assert that STIX objects have score."""
    if hasattr(domain_observable, "score"):
        assert domain_observable.score == expected_score  # noqa: S101
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
    indicator: Any, gti_domain: GTIDomainData
) -> None:
    """Assert that STIX indicator has correct timestamps."""
    if gti_domain.attributes and gti_domain.attributes.creation_date:
        expected_created = datetime.fromtimestamp(
            gti_domain.attributes.creation_date, tz=timezone.utc
        )
        assert indicator.created == expected_created  # noqa: S101
