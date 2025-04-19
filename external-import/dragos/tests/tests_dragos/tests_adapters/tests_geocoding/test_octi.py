"""Offer OpenCTI Geocoding Adapter tests."""

# isort:skip_file
# pragma: no cover

from unittest.mock import Mock

import pytest

from dragos.adapters.geocoding.octi import OctiGeocoding
from dragos.interfaces.geocoding import (
    City,
    Country,
    GeocodingRetrievalError,
    Position,
    Region,
)


# test each entity nominal case
@pytest.mark.parametrize(
    "api_response, entity_class",
    [
        pytest.param(
            [{"entity_type": "Country", "name": "test country"}], Country, id="Country"
        ),
        pytest.param(
            [{"entity_type": "Region", "name": "test region"}], Region, id="Region"
        ),
        pytest.param([{"entity_type": "City", "name": "test city"}], City, id="City"),
        pytest.param(
            [
                {
                    "entity_type": "Position",
                    "name": "test position",
                    "latitude": 0,
                    "longitude": 0,
                }
            ],
            Position,
            id="Position",
        ),
    ],
)
def test_supported_entity_is_correctly_found(api_response, entity_class):
    """Test that supported entities are correctly found."""
    # Given a geocoding instance
    client = Mock()
    client.stix_domain_object.list.return_value = api_response
    geocoding = OctiGeocoding(api_client=client)

    # When calling find_from_name
    entity = geocoding.find_from_name("")

    # Then the correct entity is returned
    assert isinstance(entity, entity_class)  # noqa: S101


@pytest.mark.parametrize(
    "api_response",
    [
        pytest.param([{}, {}], id="Too many results"),
        pytest.param([], id="No results"),
        pytest.param(
            [{"entity_type": "Administrative-Area"}], id="Administrative-Area"
        ),
    ],
)
def test_unability_to_match_returns_none(api_response):
    """Test that unability to match returns None."""
    # Given a geocoding instance
    client = Mock()
    client.stix_domain_object.list.return_value = api_response
    geocoding = OctiGeocoding(api_client=client)

    # When calling find_from_name
    entity = geocoding.find_from_name("")

    # Then None is returned
    assert entity is None  # noqa: S101


@pytest.mark.parametrize(
    "api_response",
    [
        pytest.param(
            [{"entity_type": "BLAH", "name": "test"}], id="Corrupted response"
        ),
        pytest.param([{"entity_type": "Country"}], id="Missing name"),
        pytest.param([{}], id="Empty response"),
    ],
)
def test_geocoding_retrieval_error_cases(api_response):
    """Test that GeocodingRetrievalError is raised in error cases."""
    # Given a geocoding instance with an issue
    client = Mock()
    client.stix_domain_object.list.return_value = api_response
    geocoding = OctiGeocoding(api_client=client)

    # When calling find_from_name
    # Then GeocodingRetrievalError is raised
    with pytest.raises(GeocodingRetrievalError):
        geocoding.find_from_name("")
