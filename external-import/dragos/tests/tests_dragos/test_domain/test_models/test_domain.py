"""Offer tests for the OpenCTI doamin models."""

from datetime import datetime, timezone

import dragos.domain.models.octi as octi
import dragos.domain.models.octi.enums as octi_enums
import pytest
import stix2
from pydantic import ValidationError


def fake_valid_organization_author():
    """Return a valid Organization Author."""
    return octi.OrganizationAuthor(name="Valid Author")


def fake_valid_tlp_marking():
    """Return a valid TLP Marking."""
    return octi.TLPMarking(level=octi_enums.TLPLevel.RED.value)


def fake_external_reference():
    """Return a valid External Reference."""
    return octi.ExternalReference(
        source_name="Test Source",
        description="Test Description",
        url="http://example.com",
        external_id="test_id",
    )


def fake_valid_indicator():
    """Return a valid Indicator."""
    return octi.Indicator(
        name="Test Indicator",
        pattern="[url:value='http://example.com']",
        pattern_type=octi_enums.PatternType.STIX.value,
        observable_type=octi_enums.ObservableType.URL.value,
        author=fake_valid_organization_author(),
        markings=[fake_valid_tlp_marking()],
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Indicator",
                "description": "Test Indicator description",
                "pattern": "[url:value='http://example.com']",
                "pattern_type": octi_enums.PatternType.STIX.value,
                "indicator_types": [
                    indicator_type.value for indicator_type in octi_enums.IndicatorType
                ],
                "kill_chain_phases": [
                    octi.KillChainPhase(
                        chain_name="Test Chain",
                        phase_name="Test Phase",
                    )
                ],
                "valid_from": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "valid_until": datetime.now(tz=timezone.utc),
                "score": 50,
                "observable_type": octi_enums.ObservableType.URL.value,
                "platforms": [platform.value for platform in octi_enums.Platform],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Indicator",
                "pattern": "[url:value='http://example.com']",
                "pattern_type": octi_enums.PatternType.STIX.value,
                "observable_type": octi_enums.ObservableType.URL.value,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_indicator_class_should_accept_valid_input(input_data):
    """Test that the Indicator class accepts valid input."""
    # Given: Valid indicator input data
    # When: Creating an indicator object
    indicator = octi.Indicator.model_validate(input_data)

    # Then: The indicator object should be valid
    assert (  # noqa: S101
        indicator.id is not None
        and indicator.name == input_data.get("name")
        and indicator.description == input_data.get("description")
        and indicator.pattern == input_data.get("pattern")
        and indicator.pattern_type == input_data.get("pattern_type")
        and indicator.observable_type == input_data.get("observable_type")
        and indicator.indicator_types == input_data.get("indicator_types")
        and indicator.platforms == input_data.get("platforms")
        and indicator.kill_chain_phases == input_data.get("kill_chain_phases")
        and indicator.valid_from == input_data.get("valid_from")
        and indicator.valid_until == input_data.get("valid_until")
        and indicator.score == input_data.get("score")
        and indicator.author == input_data.get("author")
        and indicator.external_references == input_data.get("external_references")
        and indicator.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "name": "Test Indicator",
                "pattern_type": octi_enums.PatternType.STIX.value,
                "observable_type": octi_enums.ObservableType.URL.value,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "pattern",
            id="missing_pattern",
        ),
        pytest.param(
            {
                "name": "Test Indicator",
                "pattern": "[url:value='http://example.com']",
                "pattern_type": octi_enums.PatternType.STIX.value,
                "observable_type": "random observable",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "observable_type",
            id="invalid_observable_type",
        ),
    ],
)
def test_indicator_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the Indicator class does not accept invalid input."""
    # Given: Invalid input data for the Indicator class
    # When: Trying to create a Indicator instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Indicator.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_indicator_to_stix2_object_returns_valid_stix_object():
    """Test that Indicator.to_stix2_object returns a valid STIX Indicator."""
    # Given: A valid indicator
    input_data = {
        "name": "Test Indicator",
        "description": "Test Indicator description",
        "pattern": "[url:value='http://example.com']",
        "pattern_type": octi_enums.PatternType.STIX.value,
        "indicator_types": [
            indicator_type.value for indicator_type in octi_enums.IndicatorType
        ],
        "kill_chain_phases": [
            octi.KillChainPhase(
                chain_name="Test Chain",
                phase_name="Test Phase",
            )
        ],
        "valid_from": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "valid_until": datetime.now(tz=timezone.utc),
        "score": 50,
        "platforms": [platform.value for platform in octi_enums.Platform],
        "observable_type": octi_enums.ObservableType.URL.value,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    indicator = octi.Indicator.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = indicator.to_stix2_object()

    # Then: A valid STIX Indicator is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Indicator)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.pattern == input_data.get("pattern")
        and stix2_obj.pattern_type == input_data.get("pattern_type")
        and stix2_obj.indicator_types == input_data.get("indicator_types")
        and stix2_obj.valid_from == input_data.get("valid_from")
        and stix2_obj.valid_until == input_data.get("valid_until")
        and stix2_obj.x_opencti_score == 50
        and stix2_obj.x_mitre_platforms == input_data.get("platforms")
        and stix2_obj.x_opencti_main_observable_type
        == input_data.get("observable_type")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Intrusion Set",
                "description": "Test Intrusion Set description",
                "aliases": ["alias1", "alias2"],
                "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "last_seen": datetime.now(tz=timezone.utc),
                "goals": ["goal1", "goal2"],
                "resource_level": octi_enums.AttackResourceLevel.CLUB.value,
                "primary_motivation": octi_enums.AttackMotivation.ACCIDENTAL.value,
                "secondary_motivations": [
                    attack_motivation.value
                    for attack_motivation in octi_enums.AttackMotivation
                ],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Intrusion Set",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_intrusion_set_class_should_accept_valid_input(input_data):
    """Test that the IntrusionSet class accepts valid input."""
    # Given: Valid intrusion set input data
    # When: Creating an intrusion set object
    intrusion_set = octi.IntrusionSet.model_validate(input_data)

    # Then: The intrusion set object should be valid
    assert (  # noqa: S101
        intrusion_set.id is not None
        and intrusion_set.name == input_data.get("name")
        and intrusion_set.description == input_data.get("description")
        and intrusion_set.aliases == input_data.get("aliases")
        and intrusion_set.first_seen == input_data.get("first_seen")
        and intrusion_set.last_seen == input_data.get("last_seen")
        and intrusion_set.goals == input_data.get("goals")
        and intrusion_set.resource_level == input_data.get("resource_level")
        and intrusion_set.primary_motivation == input_data.get("primary_motivation")
        and intrusion_set.secondary_motivations
        == input_data.get("secondary_motivations")
        and intrusion_set.author == input_data.get("author")
        and intrusion_set.external_references == input_data.get("external_references")
        and intrusion_set.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Intrusion Set description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Intrusion Set",
                "aliases": "alias",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "aliases",
            id="invalid_aliases_type",
        ),
    ],
)
def test_intrusion_set_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the IntrusionSet class does not accept invalid input."""
    # Given: Invalid input data for the IntrusionSet class
    # When: Trying to create a IntrusionSet instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.IntrusionSet.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_intrusion_set_to_stix2_object_returns_valid_stix_object():
    """Test that IntrusionSet.to_stix2_object returns a valid STIX IntrusionSet."""
    # Given: A valid intrusion set
    input_data = {
        "name": "Test Intrusion Set",
        "description": "Test Intrusion Set description",
        "aliases": ["alias1", "alias2"],
        "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime.now(tz=timezone.utc),
        "goals": ["goal1", "goal2"],
        "resource_level": octi_enums.AttackResourceLevel.CLUB.value,
        "primary_motivation": octi_enums.AttackMotivation.ACCIDENTAL.value,
        "secondary_motivations": [
            attack_motivation.value for attack_motivation in octi_enums.AttackMotivation
        ],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    intrusion_set = octi.IntrusionSet.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = intrusion_set.to_stix2_object()

    # Then: A valid STIX IntrusionSet is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.IntrusionSet)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.aliases == input_data.get("aliases")
        and stix2_obj.first_seen == input_data.get("first_seen")
        and stix2_obj.last_seen == input_data.get("last_seen")
        and stix2_obj.goals == input_data.get("goals")
        and stix2_obj.resource_level == input_data.get("resource_level")
        and stix2_obj.primary_motivation == input_data.get("primary_motivation")
        and stix2_obj.secondary_motivations == input_data.get("secondary_motivations")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Location Administrative Area",
                "description": "Test Location Administrative Area description",
                "latitude": 48.8575,
                "longitude": 2.3514,
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Location Administrative Area",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_location_administrative_area_class_should_accept_valid_input(input_data):
    """Test that the LocationAdministrativeArea class accepts valid input."""
    # Given: Valid location administrative area input data
    # When: Creating an location administrative area object
    location_administrative_area = octi.LocationAdministrativeArea.model_validate(
        input_data
    )

    # Then: The location administrative area object should be valid
    assert (  # noqa: S101
        location_administrative_area.id is not None
        and location_administrative_area.name == input_data.get("name")
        and location_administrative_area.description == input_data.get("description")
        and location_administrative_area.latitude == input_data.get("latitude")
        and location_administrative_area.longitude == input_data.get("longitude")
        and location_administrative_area.author == input_data.get("author")
        and location_administrative_area.external_references
        == input_data.get("external_references")
        and location_administrative_area.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Location Administrative Area description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Location Administrative Area",
                "latitude": "wrong latitude",
                "longitude": 2.3514,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "latitude",
            id="invalid_latitude_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test LocationAdministrativeArea",
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_location_administrative_area_class_should_not_accept_invalid_input(
    input_data, error_field
):
    """Test that the LocationAdministrativeArea class does not accept invalid input."""
    # Given: Invalid input data for the LocationAdministrativeArea class
    # When: Trying to create a LocationAdministrativeArea instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.LocationAdministrativeArea.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_location_administrative_area_to_stix2_object_returns_valid_stix_object():
    """Test that LocationAdministrativeArea.to_stix2_object returns a valid STIX Location."""
    # Given: A valid location administrative area
    input_data = {
        "name": "Test Location Administrative",
        "description": "Test Location Administrative description",
        "latitude": 48.8575,
        "longitude": 2.3514,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    location_administrative_area = octi.LocationAdministrativeArea.model_validate(
        input_data
    )

    # When: calling to_stix2_object method
    stix2_obj = location_administrative_area.to_stix2_object()

    # Then: A valid STIX Location is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Location)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.administrative_area == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.latitude == input_data.get("latitude")
        and stix2_obj.longitude == input_data.get("longitude")
        and stix2_obj.x_opencti_location_type
        == octi_enums.LocationType.ADMINISTRATIVE_AREA.value
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Location City",
                "description": "Test Location City description",
                "latitude": 48.8575,
                "longitude": 2.3514,
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Location City",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_location_city_class_should_accept_valid_input(input_data):
    """Test that the LocationCity class accepts valid input."""
    # Given: Valid location city input data
    # When: Creating an location city object
    location_city = octi.LocationCity.model_validate(input_data)

    # Then: The location city object should be valid
    assert (  # noqa: S101
        location_city.id is not None
        and location_city.name == input_data.get("name")
        and location_city.description == input_data.get("description")
        and location_city.latitude == input_data.get("latitude")
        and location_city.longitude == input_data.get("longitude")
        and location_city.author == input_data.get("author")
        and location_city.external_references == input_data.get("external_references")
        and location_city.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Location City description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Location City",
                "latitude": "wrong latitude",
                "longitude": 2.3514,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "latitude",
            id="invalid_latitude_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test Location City",
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_location_city_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the LocationCity class does not accept invalid input."""
    # Given: Invalid input data for the LocationCity class
    # When: Trying to create a LocationCity instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.LocationCity.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_location_city_to_stix2_object_returns_valid_stix_object():
    """Test that LocationCity.to_stix2_object returns a valid STIX Location."""
    # Given: A valid location city
    input_data = {
        "name": "Test Location City",
        "description": "Test Location City description",
        "latitude": 48.8575,
        "longitude": 2.3514,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    location_city = octi.LocationCity.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = location_city.to_stix2_object()

    # Then: A valid STIX Location is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Location)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.city == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.latitude == input_data.get("latitude")
        and stix2_obj.longitude == input_data.get("longitude")
        and stix2_obj.x_opencti_location_type == octi_enums.LocationType.CITY.value
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Location Country",
                "description": "Test Location Country description",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Location Country",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_location_country_class_should_accept_valid_input(input_data):
    """Test that the LocationCountry class accepts valid input."""
    # Given: Valid location country input data
    # When: Creating an location country object
    location_country = octi.LocationCountry.model_validate(input_data)

    # Then: The location country object should be valid
    assert (  # noqa: S101
        location_country.id is not None
        and location_country.name == input_data.get("name")
        and location_country.description == input_data.get("description")
        and location_country.author == input_data.get("author")
        and location_country.external_references
        == input_data.get("external_references")
        and location_country.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Location Country description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Location Country",
                "description": False,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "description",
            id="invalid_description_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test Location Country",
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_location_country_class_should_not_accept_invalid_input(
    input_data, error_field
):
    """Test that the LocationCountry class does not accept invalid input."""
    # Given: Invalid input data for the LocationCountry class
    # When: Trying to create a LocationCountry instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.LocationCountry.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_location_country_to_stix2_object_returns_valid_stix_object():
    """Test that LocationCountry.to_stix2_object returns a valid STIX Location."""
    # Given: A valid location country
    input_data = {
        "name": "Test Location Country",
        "description": "Test Location Country description",
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    location_country = octi.LocationCountry.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = location_country.to_stix2_object()

    # Then: A valid STIX LocationCountry is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Location)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.country == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.x_opencti_location_type == octi_enums.LocationType.COUNTRY.value
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Location Position",
                "description": "Test Location Position description",
                "latitude": 48.8575,
                "longitude": 2.3514,
                "street_address": "random street",
                "postal_code": "random code",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Location Position",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_location_position_class_should_accept_valid_input(input_data):
    """Test that the LocationPosition class accepts valid input."""
    # Given: Valid location position input data
    # When: Creating an location position object
    location_position = octi.LocationPosition.model_validate(input_data)

    # Then: The location position object should be valid
    assert (  # noqa: S101
        location_position.id is not None
        and location_position.name == input_data.get("name")
        and location_position.description == input_data.get("description")
        and location_position.latitude == input_data.get("latitude")
        and location_position.longitude == input_data.get("longitude")
        and location_position.street_address == input_data.get("street_address")
        and location_position.postal_code == input_data.get("postal_code")
        and location_position.author == input_data.get("author")
        and location_position.external_references
        == input_data.get("external_references")
        and location_position.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Location Position description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Location Position",
                "street_address": False,
                "postal_code": "random code",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "street_address",
            id="invalid_street_address_type",
        ),
        # pytest.param(
        #     {
        #         "name": "Test Location Position",
        #         "markings": [fake_valid_tlp_marking()],
        #     },
        #     "author",
        #     id="missing_author",
        # ),
    ],
)
def test_location_position_class_should_not_accept_invalid_input(
    input_data, error_field
):
    """Test that the LocationPosition class does not accept invalid input."""
    # Given: Invalid input data for the LocationPosition class
    # When: Trying to create a LocationPosition instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.LocationPosition.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_location_position_to_stix2_object_returns_valid_stix_object():
    """Test that LocationPosition.to_stix2_object returns a valid STIX Location."""
    # Given: A valid location position
    input_data = {
        "name": "Test Location Position",
        "description": "Test Location Position description",
        "latitude": 48.8575,
        "longitude": 2.3514,
        "street_address": "random street",
        "postal_code": "random code",
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    location_position = octi.LocationPosition.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = location_position.to_stix2_object()

    # Then: A valid STIX LocationPosition is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Location)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.latitude == input_data.get("latitude")
        and stix2_obj.longitude == input_data.get("longitude")
        and stix2_obj.street_address == input_data.get("street_address")
        and stix2_obj.postal_code == input_data.get("postal_code")
        and stix2_obj.x_opencti_location_type == octi_enums.LocationType.POSITION.value
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Location Region",
                "description": "Test Location Region description",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Location Region",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_location_region_class_should_accept_valid_input(input_data):
    """Test that the LocationRegion class accepts valid input."""
    # Given: Valid location region input data
    # When: Creating an location region object
    location_region = octi.LocationRegion.model_validate(input_data)

    # Then: The location region object should be valid
    assert (  # noqa: S101
        location_region.id is not None
        and location_region.name == input_data.get("name")
        and location_region.description == input_data.get("description")
        and location_region.author == input_data.get("author")
        and location_region.external_references == input_data.get("external_references")
        and location_region.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Location Region description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Location Region",
                "description": False,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "description",
            id="invalid_description_type",
        ),
    ],
)
def test_location_region_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the LocationRegion class does not accept invalid input."""
    # Given: Invalid input data for the LocationRegion class
    # When: Trying to create a LocationRegion instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.LocationRegion.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_location_region_to_stix2_object_returns_valid_stix_object():
    """Test that LocationRegion.to_stix2_object returns a valid STIX Location."""
    # Given: A valid location region
    input_data = {
        "name": "Test Location Region",
        "description": "Test Location Region description",
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    location_region = octi.LocationRegion.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = location_region.to_stix2_object()

    # Then: A valid STIX LocationRegion is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Location)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.region == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.x_opencti_location_type == octi_enums.LocationType.REGION.value
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Malware",
                "is_family": False,
                "description": "Test Malware description",
                "aliases": ["alias1", "alias2"],
                "types": [
                    malware_type.value for malware_type in octi_enums.MalwareType
                ],
                "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
                "last_seen": datetime.now(tz=timezone.utc),
                "architecture_execution_envs": [
                    processor_architecture.value
                    for processor_architecture in octi_enums.ProcessorArchitecture
                ],
                "implementation_languages": [
                    implementation_language.value
                    for implementation_language in octi_enums.ImplementationLanguage
                ],
                "kill_chain_phases": [
                    octi.KillChainPhase(
                        chain_name="Test Chain",
                        phase_name="Test Phase",
                    )
                ],
                "capabilities": [
                    capability.value for capability in octi_enums.MalwareCapability
                ],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Malware",
                "is_family": False,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_malware_class_should_accept_valid_input(input_data):
    """Test that the Malware class accepts valid input."""
    # Given: Valid malware input data
    # When: Creating an malware object
    malware = octi.Malware.model_validate(input_data)

    # Then: The malware object should be valid
    assert (  # noqa: S101
        malware.id is not None
        and malware.name == input_data.get("name")
        and malware.is_family == input_data.get("is_family")
        and malware.description == input_data.get("description")
        and malware.aliases == input_data.get("aliases")
        and malware.types == input_data.get("types")
        and malware.first_seen == input_data.get("first_seen")
        and malware.last_seen == input_data.get("last_seen")
        and malware.architecture_execution_envs
        == input_data.get("architecture_execution_envs")
        and malware.implementation_languages
        == input_data.get("implementation_languages")
        and malware.kill_chain_phases == input_data.get("kill_chain_phases")
        and malware.capabilities == input_data.get("capabilities")
        and malware.author == input_data.get("author")
        and malware.external_references == input_data.get("external_references")
        and malware.markings == input_data.get("markings")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "is_family": False,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Malware",
                "is_family": 42,
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "is_family",
            id="invalid_is_family_type",
        ),
    ],
)
def test_malware_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the Malware class does not accept invalid input."""
    # Given: Invalid input data for the Malware class
    # When: Trying to create a Malware instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Malware.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_malware_to_stix2_object_returns_valid_stix_object():
    """Test that Malware.to_stix2_object returns a valid STIX Malware."""
    # Given: A valid malware
    input_data = {
        "name": "Test Malware",
        "is_family": False,
        "description": "Test Malware description",
        "aliases": ["alias1", "alias2"],
        "types": [malware_type.value for malware_type in octi_enums.MalwareType],
        "first_seen": datetime(1970, 1, 1, tzinfo=timezone.utc),
        "last_seen": datetime.now(tz=timezone.utc),
        "architecture_execution_envs": [
            processor_architecture.value
            for processor_architecture in octi_enums.ProcessorArchitecture
        ],
        "implementation_languages": [
            implementation_language.value
            for implementation_language in octi_enums.ImplementationLanguage
        ],
        "kill_chain_phases": [
            octi.KillChainPhase(
                chain_name="Test Chain",
                phase_name="Test Phase",
            )
        ],
        "capabilities": [
            capability.value for capability in octi_enums.MalwareCapability
        ],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    malware = octi.Malware.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = malware.to_stix2_object()

    # Then: A valid STIX Malware is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Malware)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.is_family == input_data.get("is_family")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.aliases == input_data.get("aliases")
        and stix2_obj.malware_types == input_data.get("types")
        and stix2_obj.first_seen == input_data.get("first_seen")
        and stix2_obj.last_seen == input_data.get("last_seen")
        and stix2_obj.architecture_execution_envs
        == input_data.get("architecture_execution_envs")
        and stix2_obj.implementation_languages
        == input_data.get("implementation_languages")
        and stix2_obj.kill_chain_phases
        == [
            kill_chain_phase.to_stix2_object()
            for kill_chain_phase in input_data.get("kill_chain_phases")
        ]
        and stix2_obj.capabilities == input_data.get("capabilities")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Organization",
                "description": "Test Organization description",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
                "contact_information": "contact@example.com",
                "organization_type": octi_enums.OrganizationType.VENDOR.value,
                "reliability": octi_enums.Reliability.A.value,
                "aliases": ["Alias1", "Alias2"],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Organization",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_organization_class_should_accept_valid_input(input_data):
    """Test that the Organization class accepts valid input."""
    # Given: Valid organization input data
    # When: Creating an organization object
    organization = octi.Organization.model_validate(input_data)

    # Then: The organization object should be valid
    assert (  # noqa: S101
        organization.id is not None
        and organization.name == input_data.get("name")
        and organization.description == input_data.get("description")
        and organization.author == input_data.get("author")
        and organization.external_references == input_data.get("external_references")
        and organization.markings == input_data.get("markings")
        and organization.contact_information == input_data.get("contact_information")
        and organization.organization_type == input_data.get("organization_type")
        and organization.reliability == input_data.get("reliability")
        and organization.aliases == input_data.get("aliases")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Organization description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
    ],
)
def test_organization_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the Organization class does not accept invalid input."""
    # Given: Invalid input data for the Organization class
    # When: Trying to create an Organization instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Organization.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_organization_to_stix2_object_returns_valid_stix_object():
    """Test that Organization.to_stix2_object returns a valid STIX Identity."""
    # Given: A valid organization
    input_data = {
        "name": "Test Organization",
        "description": "Test Organization description",
        "contact_information": "contact@example.com",
        "organization_type": octi_enums.OrganizationType.VENDOR.value,
        "reliability": octi_enums.Reliability.A.value,
        "aliases": ["Alias1", "Alias2"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    organization = octi.Organization.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = organization.to_stix2_object()

    # Then: A valid STIX Identity is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Identity)
        and stix2_obj.id is not None
        and stix2_obj.identity_class == octi_enums.IdentityClass.ORGANIZATION.value
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.contact_information == input_data.get("contact_information")
        and stix2_obj.x_opencti_organization_type == input_data.get("organization_type")
        and stix2_obj.x_opencti_reliability == input_data.get("reliability")
        and stix2_obj.x_opencti_aliases == input_data.get("aliases")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Report",
                "description": "Test Report description",
                "publication_date": datetime.now(tz=timezone.utc),
                "report_types": [
                    report_type.value for report_type in octi_enums.ReportType
                ],
                "reliability": octi_enums.Reliability.A.value,
                "labels": ["labelA", "labelB"],
                "objects": [fake_valid_indicator()],
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Report",
                "publication_date": datetime.now(tz=timezone.utc),
                "objects": [fake_valid_indicator()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_report_class_should_accept_valid_input(input_data):
    """Test that the Report class accepts valid input."""
    # Given: Valid report input data
    # When: Creating a report object
    report = octi.Report.model_validate(input_data)

    # Then: The report object should be valid
    assert (  # noqa: S101
        report.id is not None
        and report.name == input_data.get("name")
        and report.publication_date == input_data.get("publication_date")
        and report.report_types == input_data.get("report_types")
        and report.reliability == input_data.get("reliability")
        and report.labels == input_data.get("labels")
        and report.description == input_data.get("description")
        and report.author == input_data.get("author")
        and report.external_references == input_data.get("external_references")
        and report.markings == input_data.get("markings")
        and report.objects == input_data.get("objects")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "publication_date": datetime.now(tz=timezone.utc),
                "objects": [fake_valid_organization_author()],
            },
            "name",
            id="missing_name",
        ),
        pytest.param(
            {
                "name": "Test Report",
                "objects": [fake_valid_organization_author()],
            },
            "publication_date",
            id="missing_publication_date",
        ),
    ],
)
def test_report_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the Report class does not accept invalid input."""
    # Given: Invalid input data for the Report class
    # When: Trying to create a Report instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Report.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_report_to_stix2_object_returns_valid_stix_object():
    """Test that Report.to_stix2_object returns a valid STIX Report."""
    # Given: A valid report
    input_data = {
        "name": "Test Report",
        "publication_date": datetime.now(tz=timezone.utc),
        "report_types": [report_type.value for report_type in octi_enums.ReportType],
        "reliability": octi_enums.Reliability.A.value,
        "description": "Test Report description",
        "labels": ["labelA", "labelB"],
        "objects": [fake_valid_organization_author()],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    report = octi.Report.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = report.to_stix2_object()

    # Then: A valid STIX Report is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Report)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.published == input_data.get("publication_date")
        and stix2_obj.report_types == input_data.get("report_types")
        and stix2_obj.x_opencti_reliability == input_data.get("reliability")
        and stix2_obj.labels == input_data.get("labels")
        and stix2_obj.object_refs == [obj.id for obj in input_data.get("objects")]
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Sector",
                "description": "Test Sector description",
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
                "sectors": [
                    industry_sector.value
                    for industry_sector in octi_enums.IndustrySector
                ],
                "reliability": octi_enums.Reliability.A.value,
                "aliases": ["Alias1", "Alias2"],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Sector",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_sector_class_should_accept_valid_input(input_data):
    """Test that the Sector class accepts valid input."""
    # Given: Valid sector input data
    # When: Creating an sector object
    sector = octi.Sector.model_validate(input_data)

    # Then: The sector object should be valid
    assert (  # noqa: S101
        sector.id is not None
        and sector.name == input_data.get("name")
        and sector.description == input_data.get("description")
        and sector.author == input_data.get("author")
        and sector.external_references == input_data.get("external_references")
        and sector.markings == input_data.get("markings")
        and sector.sectors == input_data.get("sectors")
        and sector.reliability == input_data.get("reliability")
        and sector.aliases == input_data.get("aliases")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Sector description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
    ],
)
def test_sector_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the Sector class does not accept invalid input."""
    # Given: Invalid input data for the Sector class
    # When: Trying to create an Sector instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Sector.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_sector_to_stix2_object_returns_valid_stix_object():
    """Test that Sector.to_stix2_object returns a valid STIX Identity."""
    # Given: A valid sector
    input_data = {
        "name": "Test Sector",
        "description": "Test Sector description",
        "sectors": [
            industry_sector.value for industry_sector in octi_enums.IndustrySector
        ],
        "reliability": octi_enums.Reliability.A.value,
        "aliases": ["Alias1", "Alias2"],
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    sector = octi.Sector.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = sector.to_stix2_object()

    # Then: A valid STIX Identity is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Identity)
        and stix2_obj.id is not None
        and stix2_obj.identity_class == octi_enums.IdentityClass.CLASS.value
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.sectors == input_data.get("sectors")
        and stix2_obj.x_opencti_reliability == input_data.get("reliability")
        and stix2_obj.x_opencti_aliases == input_data.get("aliases")
    )


@pytest.mark.parametrize(
    "input_data",
    [
        pytest.param(
            {
                "name": "Test Vulnerability",
                "description": "Test Vulnerability description",
                "aliases": ["alias1", "alias2"],
                "cvss_score": 0,
                "cvss_severity": octi_enums.CvssSeverity.CRITICAL.value,
                "cvss_attack_vector": "attack_vector",
                "cvss_integrity_impact": "integrity impact",
                "cvss_availability_impact": "availability impact",
                "cvss_confidentiality_impact": "confidentiality impact",
                "is_cisa_kev": False,
                "epss_score": 0,
                "epss_percentile": 0,
                "author": fake_valid_organization_author(),
                "external_references": [fake_external_reference()],
                "markings": [fake_valid_tlp_marking()],
            },
            id="full_valid_data",
        ),
        pytest.param(
            {
                "name": "Test Vulnerability",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            id="minimal_valid_data",
        ),
    ],
)
def test_vulnerability_class_should_accept_valid_input(input_data):
    """Test that the Vulnerability class accepts valid input."""
    # Given: Valid vulnerability input data
    # When: Creating an vulnerability object
    vulnerability = octi.Vulnerability.model_validate(input_data)

    # Then: The vulnerability object should be valid
    assert (  # noqa: S101
        vulnerability.id is not None
        and vulnerability.name == input_data.get("name")
        and vulnerability.description == input_data.get("description")
        and vulnerability.aliases == input_data.get("aliases")
        and vulnerability.cvss_score == input_data.get("cvss_score")
        and vulnerability.cvss_severity == input_data.get("cvss_severity")
        and vulnerability.cvss_attack_vector == input_data.get("cvss_attack_vector")
        and vulnerability.cvss_integrity_impact
        == input_data.get("cvss_integrity_impact")
        and vulnerability.cvss_availability_impact
        == input_data.get("cvss_availability_impact")
        and vulnerability.cvss_confidentiality_impact
        == input_data.get("cvss_confidentiality_impact")
        and vulnerability.is_cisa_kev == input_data.get("is_cisa_kev")
        and vulnerability.epss_score == input_data.get("epss_score")
        and vulnerability.epss_percentile == input_data.get("epss_percentile")
    )


@pytest.mark.parametrize(
    "input_data, error_field",
    [
        pytest.param(
            {
                "description": "Test Vulnerability description",
                "author": fake_valid_organization_author(),
                "markings": [fake_valid_tlp_marking()],
            },
            "name",
            id="missing_name",
        ),
    ],
)
def test_vulnerability_class_should_not_accept_invalid_input(input_data, error_field):
    """Test that the Vulnerability class does not accept invalid input."""
    # Given: Invalid input data for the Vulnerability class
    # When: Trying to create an Vulnerability instance
    # Then: A ValidationError should be raised
    with pytest.raises(ValidationError) as err:
        octi.Vulnerability.model_validate(input_data)
    assert str(error_field) in str(err)  # noqa: S101


def test_vulnerability_to_stix2_object_returns_valid_stix_object():
    """Test that Vulnerability.to_stix2_object returns a valid STIX Identity."""
    # Given: A valid vulnerability
    input_data = {
        "name": "Test Vulnerability",
        "description": "Test Vulnerability description",
        "aliases": ["alias1", "alias2"],
        "cvss_score": 0,
        "cvss_severity": octi_enums.CvssSeverity.CRITICAL.value,
        "cvss_attack_vector": "attack_vector",
        "cvss_integrity_impact": "integrity impact",
        "cvss_availability_impact": "availability impact",
        "cvss_confidentiality_impact": "confidentiality impact",
        "is_cisa_kev": False,
        "epss_score": 0,
        "epss_percentile": 0,
        "author": fake_valid_organization_author(),
        "external_references": [fake_external_reference()],
        "markings": [fake_valid_tlp_marking()],
    }
    vulnerability = octi.Vulnerability.model_validate(input_data)

    # When: calling to_stix2_object method
    stix2_obj = vulnerability.to_stix2_object()

    # Then: A valid STIX Identity is returned
    assert (  # noqa: S101
        isinstance(stix2_obj, stix2.Vulnerability)
        and stix2_obj.id is not None
        and stix2_obj.name == input_data.get("name")
        and stix2_obj.description == input_data.get("description")
        and stix2_obj.x_opencti_aliases == input_data.get("aliases")
        and stix2_obj.x_opencti_cvss_base_score == input_data.get("cvss_score")
        and stix2_obj.x_opencti_cvss_base_severity == input_data.get("cvss_severity")
        and stix2_obj.x_opencti_cvss_attack_vector
        == input_data.get("cvss_attack_vector")
        and stix2_obj.x_opencti_cvss_integrity_impact
        == input_data.get("cvss_integrity_impact")
        and stix2_obj.x_opencti_cvss_availability_impact
        == input_data.get("cvss_availability_impact")
        and stix2_obj.x_opencti_cvss_confidentiality_impact
        == input_data.get("cvss_confidentiality_impact")
        and stix2_obj.x_opencti_cisa_kev == input_data.get("is_cisa_kev")
        and stix2_obj.x_opencti_epss_score == input_data.get("epss_score")
        and stix2_obj.x_opencti_epss_percentile == input_data.get("epss_percentile")
    )
