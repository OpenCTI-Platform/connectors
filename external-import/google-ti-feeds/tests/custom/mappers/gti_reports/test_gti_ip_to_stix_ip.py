"""Tests for GTI IP to STIX IP mapper."""

from datetime import datetime, timezone
from typing import Any, List
from uuid import uuid4

import pytest
from connector.src.custom.mappers.gti_reports.gti_ip_to_stix_ip import (
    GTIIPToSTIXIP,
)
from connector.src.custom.models.gti_reports.gti_ip_addresses_model import (
    ContributingFactors,
    GTIAssessment,
    GTIIPData,
    IPModel,
    ThreatScore,
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


class IPModelFactory(ModelFactory[IPModel]):
    """Factory for IPModel."""

    __model__ = IPModel


class GTIIPDataFactory(ModelFactory[GTIIPData]):
    """Factory for GTIIPData."""

    __model__ = GTIIPData

    type = "ip_address"
    attributes = Use(IPModelFactory.build)


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
def minimal_ipv4_data() -> GTIIPData:
    """Fixture for minimal IPv4 data."""
    return GTIIPDataFactory.build(
        id="192.168.1.1",
        attributes=IPModelFactory.build(
            last_analysis_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def minimal_ipv6_data() -> GTIIPData:
    """Fixture for minimal IPv6 data."""
    return GTIIPDataFactory.build(
        id="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        attributes=IPModelFactory.build(
            last_analysis_date=None,
            last_modification_date=None,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def ipv4_with_timestamps() -> GTIIPData:
    """Fixture for IPv4 data with timestamps."""
    return GTIIPDataFactory.build(
        id="10.0.0.1",
        attributes=IPModelFactory.build(
            last_analysis_date=1672531200,
            last_modification_date=1672617600,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def ipv6_with_timestamps() -> GTIIPData:
    """Fixture for IPv6 data with timestamps."""
    return GTIIPDataFactory.build(
        id="fe80::1",
        attributes=IPModelFactory.build(
            last_analysis_date=1672531200,
            last_modification_date=1672617600,
            gti_assessment=None,
        ),
    )


@pytest.fixture
def ip_with_mandiant_score() -> GTIIPData:
    """Fixture for IP data with mandiant confidence score."""
    return GTIIPDataFactory.build(
        id="203.0.113.1",
        attributes=IPModelFactory.build(
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
def ip_with_threat_score() -> GTIIPData:
    """Fixture for IP data with threat score fallback."""
    return GTIIPDataFactory.build(
        id="198.51.100.1",
        attributes=IPModelFactory.build(
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
def ip_with_malicious_verdict() -> GTIIPData:
    """Fixture for IP data with malicious verdict."""
    return GTIIPDataFactory.build(
        id="192.0.2.1",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def ip_with_benign_verdict() -> GTIIPData:
    """Fixture for IP data with benign verdict."""
    return GTIIPDataFactory.build(
        id="8.8.8.8",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="BENIGN"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def ip_with_suspicious_verdict() -> GTIIPData:
    """Fixture for IP data with suspicious verdict."""
    return GTIIPDataFactory.build(
        id="203.0.113.100",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="SUSPICIOUS"),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def ip_with_all_data() -> GTIIPData:
    """Fixture for IP data with all available data."""
    return GTIIPDataFactory.build(
        id="192.0.2.100",
        attributes=IPModelFactory.build(
            last_analysis_date=1672531200,
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
def ip_without_attributes() -> GTIIPData:
    """Fixture for IP data without attributes."""
    return GTIIPDataFactory.build(id="127.0.0.1", attributes=None)


@pytest.fixture
def ip_with_empty_verdict() -> GTIIPData:
    """Fixture for IP data with empty verdict."""
    return GTIIPDataFactory.build(
        id="10.0.0.100",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value=""),
                contributing_factors=None,
                threat_score=None,
            ),
        ),
    )


@pytest.fixture
def ip_with_invalid_timestamps() -> GTIIPData:
    """Fixture for IP data with invalid timestamps."""
    return GTIIPDataFactory.build(
        id="172.16.0.1",
        attributes=IPModelFactory.build(
            last_analysis_date=-1,
            last_modification_date=0,
            gti_assessment=None,
        ),
    )


# Scenario: Convert GTI IPv4 with minimal data to STIX objects
def test_gti_ipv4_to_stix_minimal_data(
    minimal_ipv4_data: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IPv4 with minimal data to STIX objects."""
    # Given a GTI IPv4 with minimal data
    mapper = _given_gti_ip_mapper(
        minimal_ipv4_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then IPv4 observable, indicator, and relationship should be created
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_ipv4_has_correct_properties(
        ip_observable, minimal_ipv4_data, mock_organization, mock_tlp_marking
    )
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI IPv6 with minimal data to STIX objects
def test_gti_ipv6_to_stix_minimal_data(
    minimal_ipv6_data: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IPv6 with minimal data to STIX objects."""
    # Given a GTI IPv6 with minimal data
    mapper = _given_gti_ip_mapper(
        minimal_ipv6_data, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then IPv6 observable, indicator, and relationship should be created
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_ipv6_has_correct_properties(
        ip_observable, minimal_ipv6_data, mock_organization, mock_tlp_marking
    )
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI IP with timestamps to STIX objects
def test_gti_ip_to_stix_with_timestamps(
    ipv4_with_timestamps: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with timestamps to STIX objects."""
    # Given a GTI IP with timestamps
    mapper = _given_gti_ip_mapper(
        ipv4_with_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_correct_timestamps(indicator, ipv4_with_timestamps)


# Scenario: Convert GTI IP with Mandiant confidence score to STIX objects
def test_gti_ip_to_stix_with_mandiant_score(
    ip_with_mandiant_score: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with mandiant confidence score to STIX objects."""
    # Given a GTI IP with mandiant confidence score
    mapper = _given_gti_ip_mapper(
        ip_with_mandiant_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include mandiant score
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(ip_observable, indicator, 85)


# Scenario: Convert GTI IP with threat score fallback to STIX objects
def test_gti_ip_to_stix_with_threat_score(
    ip_with_threat_score: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with threat score fallback to STIX objects."""
    # Given a GTI IP with threat score fallback
    mapper = _given_gti_ip_mapper(
        ip_with_threat_score, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should use threat score as fallback
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_objects_have_score(ip_observable, indicator, 70)


# Scenario: Convert GTI IP with malicious verdict to STIX objects
def test_gti_ip_to_stix_with_malicious_verdict(
    ip_with_malicious_verdict: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with malicious verdict to STIX objects."""
    # Given a GTI IP with malicious verdict
    mapper = _given_gti_ip_mapper(
        ip_with_malicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with malicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))


# Scenario: Convert GTI IP with benign verdict to STIX objects
def test_gti_ip_to_stix_with_benign_verdict(
    ip_with_benign_verdict: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with benign verdict to STIX objects."""
    # Given a GTI IP with benign verdict
    mapper = _given_gti_ip_mapper(
        ip_with_benign_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with benign indicator type
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("BENIGN"))


# Scenario: Convert GTI IP with suspicious verdict to STIX objects
def test_gti_ip_to_stix_with_suspicious_verdict(
    ip_with_suspicious_verdict: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with suspicious verdict to STIX objects."""
    # Given a GTI IP with suspicious verdict
    mapper = _given_gti_ip_mapper(
        ip_with_suspicious_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with suspicious indicator type
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("SUSPICIOUS"))


# Scenario: Convert GTI IP with all data populated to STIX objects
def test_gti_ip_to_stix_with_all_data(
    ip_with_all_data: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with all data to STIX objects."""
    # Given a GTI IP with comprehensive data
    mapper = _given_gti_ip_mapper(ip_with_all_data, mock_organization, mock_tlp_marking)

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should include all available data
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_ipv4_has_correct_properties(
        ip_observable, ip_with_all_data, mock_organization, mock_tlp_marking
    )
    _then_stix_objects_have_score(ip_observable, indicator, 95)
    _then_stix_indicator_has_type(indicator, IndicatorTypeOV("MALICIOUS"))
    _then_stix_indicator_has_correct_timestamps(indicator, ip_with_all_data)


# Scenario: Convert GTI IP without attributes to STIX objects
def test_gti_ip_to_stix_without_attributes(
    ip_without_attributes: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP without attributes to STIX objects."""
    # Given a GTI IP without attributes
    mapper = _given_gti_ip_mapper(
        ip_without_attributes, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then objects should still be created with fallback behavior
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI IP with empty verdict to STIX objects
def test_gti_ip_to_stix_with_empty_verdict(
    ip_with_empty_verdict: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with empty verdict to STIX objects."""
    # Given a GTI IP with empty verdict
    mapper = _given_gti_ip_mapper(
        ip_with_empty_verdict, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created with unknown indicator type
    _then_stix_objects_created_successfully(stix_objects)
    ip_observable, indicator, relationship = stix_objects
    _then_stix_indicator_has_unknown_type(indicator)


# Scenario: Convert GTI IP with invalid timestamps to STIX objects
def test_gti_ip_to_stix_with_invalid_timestamps(
    ip_with_invalid_timestamps: GTIIPData,
    mock_organization: Identity,
    mock_tlp_marking: MarkingDefinition,
) -> None:
    """Test conversion of GTI IP with invalid timestamps to STIX objects."""
    # Given a GTI IP with invalid timestamps
    mapper = _given_gti_ip_mapper(
        ip_with_invalid_timestamps, mock_organization, mock_tlp_marking
    )

    # When converting to STIX
    stix_objects = _when_convert_to_stix(mapper)

    # Then STIX objects should be created successfully
    _then_stix_objects_created_successfully(stix_objects)


# Scenario: Test IP version detection for IPv4
def test_detect_ip_version_ipv4(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _detect_ip_version method for IPv4."""
    # Given an IPv4 address
    ip_data = GTIIPDataFactory.build(id="192.168.1.1")
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When detecting IP version
    version = mapper._detect_ip_version()

    # Then IPv4 should be detected
    assert version == "ipv4"  # noqa: S101


# Scenario: Test IP version detection for IPv6
def test_detect_ip_version_ipv6(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _detect_ip_version method for IPv6."""
    # Given an IPv6 address
    ip_data = GTIIPDataFactory.build(id="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When detecting IP version
    version = mapper._detect_ip_version()

    # Then IPv6 should be detected
    assert version == "ipv6"  # noqa: S101


# Scenario: Test IP version detection with invalid IP
def test_detect_ip_version_invalid(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _detect_ip_version method with invalid IP."""
    # Given an invalid IP address
    ip_data = GTIIPDataFactory.build(id="invalid.ip.address")
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When detecting IP version
    # Then ValueError should be raised
    with pytest.raises(ValueError, match="Invalid IP address format"):
        mapper._detect_ip_version()


# Scenario: Extract timestamps from GTI IP with valid timestamp data
def test_get_timestamps_with_valid_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method with valid timestamp data."""
    # Given an IP with valid timestamps
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(
            last_analysis_date=1672531200,
            last_modification_date=1672617600,
        )
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When extracting timestamps
    timestamps = mapper._get_timestamps()

    # Then timestamps should be correctly converted
    expected_created = datetime.fromtimestamp(1672531200, tz=timezone.utc)
    expected_modified = datetime.fromtimestamp(1672617600, tz=timezone.utc)
    assert timestamps["created"] == expected_created  # noqa: S101
    assert timestamps["modified"] == expected_modified  # noqa: S101


# Scenario: Extract timestamps from GTI IP without timestamp data
def test_get_timestamps_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_timestamps method without timestamp data."""
    # Given an IP without timestamps
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(
            last_analysis_date=None,
            last_modification_date=None,
        )
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

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
    # Given an IP with mandiant confidence score
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=85
                )
            )
        )
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then score should be returned
    assert score == 85  # noqa: S101


# Scenario: Extract score with threat score fallback
def test_get_score_with_threat_score_fallback(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method with threat score fallback."""
    # Given an IP with threat score but no mandiant score
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=None
                ),
                threat_score=ThreatScoreFactory.build(value=70),
            )
        )
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then threat score should be returned as fallback
    assert score == 70  # noqa: S101


# Scenario: Extract score without any score data available
def test_get_score_without_data(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _get_score method without score data."""
    # Given an IP without score data
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When getting score
    score = mapper._get_score()

    # Then None should be returned
    assert score is None  # noqa: S101


# Scenario: Build STIX pattern for IPv4
def test_build_stix_pattern_ipv4(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_stix_pattern method for IPv4."""
    # Given an IPv4 address
    ip_data = GTIIPDataFactory.build(id="192.168.1.1")
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When building STIX pattern
    pattern = mapper._build_stix_pattern()

    # Then IPv4 pattern should be returned
    assert pattern == "[ipv4-addr:value = '192.168.1.1']"  # noqa: S101


# Scenario: Build STIX pattern for IPv6
def test_build_stix_pattern_ipv6(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _build_stix_pattern method for IPv6."""
    # Given an IPv6 address
    ip_data = GTIIPDataFactory.build(id="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When building STIX pattern
    pattern = mapper._build_stix_pattern()

    # Then IPv6 pattern should be returned
    assert (  # noqa: S101
        pattern == "[ipv6-addr:value = '2001:0db8:85a3:0000:0000:8a2e:0370:7334']"
    )


# Scenario: Test determine indicator types method
def test_determine_indicator_types_with_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method with verdict."""
    # Given an IP with malicious verdict
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        )
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then malicious indicator type should be returned
    assert indicator_types == [IndicatorTypeOV("MALICIOUS")]  # noqa: S101


# Scenario: Test determine indicator types method without verdict
def test_determine_indicator_types_without_verdict(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _determine_indicator_types method without verdict."""
    # Given an IP without verdict
    ip_data = GTIIPDataFactory.build(
        attributes=IPModelFactory.build(gti_assessment=None)
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When determining indicator types
    indicator_types = mapper._determine_indicator_types()

    # Then unknown indicator type should be returned
    assert indicator_types == [IndicatorTypeOV.UNKNOWN]  # noqa: S101


# Scenario: Test create STIX IPv4 method
def test_create_stix_ipv4_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_ip method for IPv4 directly."""
    # Given an IPv4 with score
    ip_data = GTIIPDataFactory.build(
        id="192.168.1.100",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                )
            )
        ),
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When creating STIX IP
    ip_observable = mapper._create_stix_ip()

    # Then IPv4 observable should be created correctly
    assert ip_observable is not None  # noqa: S101
    assert hasattr(ip_observable, "value")  # noqa: S101
    assert ip_observable.value == "192.168.1.100"  # noqa: S101


# Scenario: Test create STIX IPv6 method
def test_create_stix_ipv6_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_ip method for IPv6 directly."""
    # Given an IPv6 with score
    ip_data = GTIIPDataFactory.build(
        id="2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                contributing_factors=ContributingFactorsFactory.build(
                    mandiant_confidence_score=90
                )
            )
        ),
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When creating STIX IP
    ip_observable = mapper._create_stix_ip()

    # Then IPv6 observable should be created correctly
    assert ip_observable is not None  # noqa: S101
    assert hasattr(ip_observable, "value")  # noqa: S101
    assert (  # noqa: S101
        ip_observable.value == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    )


# Scenario: Test create STIX indicator method
def test_create_stix_indicator_method(
    mock_organization: Identity, mock_tlp_marking: MarkingDefinition
) -> None:
    """Test _create_stix_indicator method directly."""
    # Given an IP with verdict
    ip_data = GTIIPDataFactory.build(
        id="192.168.1.200",
        attributes=IPModelFactory.build(
            gti_assessment=GTIAssessmentFactory.build(
                verdict=VerdictFactory.build(value="MALICIOUS")
            )
        ),
    )
    mapper = _given_gti_ip_mapper(ip_data, mock_organization, mock_tlp_marking)

    # When creating STIX indicator
    indicator = mapper._create_stix_indicator()

    # Then indicator should be created correctly
    assert indicator is not None  # noqa: S101
    assert hasattr(indicator, "name")  # noqa: S101
    assert indicator.name == "192.168.1.200"  # noqa: S101
    assert indicator.pattern == "[ipv4-addr:value = '192.168.1.200']"  # noqa: S101


def _given_gti_ip_mapper(
    ip: GTIIPData, organization: Identity, tlp_marking: MarkingDefinition
) -> GTIIPToSTIXIP:
    """Create a GTIIPToSTIXIP mapper instance."""
    return GTIIPToSTIXIP(
        ip=ip,
        organization=organization,
        tlp_marking=tlp_marking,
    )


def _when_convert_to_stix(mapper: GTIIPToSTIXIP) -> List[Any]:
    """Convert GTI IP to STIX objects."""
    return mapper.to_stix()


def _then_stix_objects_created_successfully(stix_objects: List[Any]) -> None:
    """Assert that STIX objects were created successfully."""
    assert stix_objects is not None  # noqa: S101
    assert len(stix_objects) == 3  # noqa: S101
    ip_observable, indicator, relationship = stix_objects
    assert ip_observable is not None  # noqa: S101
    assert indicator is not None  # noqa: S101
    assert relationship is not None  # noqa: S101


def _then_stix_ipv4_has_correct_properties(
    ip_observable: Any,
    gti_ip: GTIIPData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Assert that STIX IPv4 observable has correct properties."""
    assert ip_observable.value == gti_ip.id  # noqa: S101
    assert hasattr(ip_observable, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in ip_observable.object_marking_refs  # noqa: S101


def _then_stix_ipv6_has_correct_properties(
    ip_observable: Any,
    gti_ip: GTIIPData,
    organization: Identity,
    tlp_marking: MarkingDefinition,
) -> None:
    """Assert that STIX IPv6 observable has correct properties."""
    assert ip_observable.value == gti_ip.id  # noqa: S101
    assert hasattr(ip_observable, "object_marking_refs")  # noqa: S101
    assert tlp_marking.id in ip_observable.object_marking_refs  # noqa: S101


def _then_stix_objects_have_score(
    ip_observable: Any, indicator: Any, expected_score: int
) -> None:
    """Assert that STIX objects have score."""
    if hasattr(ip_observable, "score"):
        assert ip_observable.score == expected_score  # noqa: S101
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
    indicator: Any, gti_ip: GTIIPData
) -> None:
    """Assert that STIX indicator has correct timestamps."""
    if gti_ip.attributes and gti_ip.attributes.last_analysis_date:
        expected_created = datetime.fromtimestamp(
            gti_ip.attributes.last_analysis_date, tz=timezone.utc
        )
        assert indicator.created == expected_created  # noqa: S101
