"""Tests for the Geocoding interface."""

import pytest
from dragos.interfaces.geocoding import (
    Area,
    City,
    Country,
    Geocoding,
    GeocodingRetrievalError,
    Position,
    Region,
)


class FakeGeocoding(Geocoding):
    """Fake implementation of _Geocoding for testing purposes."""

    def find_from_name(self, name: str):
        """Fake implementation of find_from_name."""
        if name == "Test Country":
            return Country(name=name)
        elif name == "Test Region":
            return Region(name=name)
        elif name == "Test Area":
            return Area(name=name)
        elif name == "Test City":
            return City(name=name)
        elif name == "Test Position":
            return Position(name=name)
        return None


def test_country_minimal_initialization():
    """Test that Country initializes correctly."""
    # Given valid data
    data = {"name": "Test Country"}

    # When initializing Country
    country = Country.model_validate(data)

    # Then it should initialize without errors
    assert country.name == "Test Country"  # noqa: S101


def test_region_minimal_initialization():
    """Test that Region initializes correctly."""
    # Given valid data
    data = {"name": "Test Region"}

    # When initializing Region
    region = Region.model_validate(data)

    # Then it should initialize without errors
    assert region.name == "Test Region"  # noqa: S101


def test_area_minimal_initialization():
    """Test that Area initializes correctly."""
    # Given valid data
    data = {"name": "Test Area"}

    # When initializing Area
    area = Area.model_validate(data)

    # Then it should initialize without errors
    assert area.name == "Test Area"  # noqa: S101


def test_city_minimal_initialization():
    """Test that City initializes correctly."""
    # Given valid data
    data = {"name": "Test City"}

    # When initializing City
    city = City.model_validate(data)

    # Then it should initialize without errors
    assert city.name == "Test City"  # noqa: S101


def test_position_minimal_initialization():
    """Test that Position initializes correctly."""
    # Given valid data
    data = {"name": "Test Position"}

    # When initializing Position
    position = Position.model_validate(data)

    # Then it should initialize without errors
    assert position.name == "Test Position"  # noqa: S101


def test_position_full_initialization():
    """Test Position initialization."""
    # Given  data
    data = {"name": "Test Position", "latitude": 0, "longitude": 0}

    # When initializing Position
    position = Position.model_validate(data)

    # Then it should initialize without errors
    assert position.name == "Test Position"  # noqa: S101
    assert position.latitude == 0  # noqa: S101
    assert position.longitude == 0  # noqa: S101


@pytest.mark.parametrize(
    "geolocation_type",
    [
        pytest.param(Country, id="Country"),
        pytest.param(Region, id="Region"),
        pytest.param(Area, id="Area"),
        pytest.param(City, id="City"),
        pytest.param(Position, id="Position"),
    ],
)
def test_geolocation_initialization_should_fail_with_geocoding_retrieval_error(
    geolocation_type,
):
    """Test that Geolocation initialization fails with GeocodingRetrievalError."""
    # Given invalid data
    data = {"whatever": "Test Geolocation"}

    # When initializing Geolocation
    with pytest.raises(GeocodingRetrievalError):
        geolocation_type.model_validate(data)


@pytest.mark.parametrize(
    "name,expected",
    [
        ("Test Country", Country),
        ("Test Region", Region),
        ("Test Area", Area),
        ("Test City", City),
        ("Test Position", Position),
        ("Unknown", type(None)),
    ],
)
def test_geocoding_find_from_name(name, expected):
    """Test that FakeGeocoding.find_from_name works correctly."""
    # Given a FakeGeocoding instance
    geocoding = FakeGeocoding()

    # When finding from name
    result = geocoding.find_from_name(name)

    # Then it should return the expected result
    assert isinstance(result, expected)  # noqa: S101
