"""Tests for `ShodanConnector._generate_stix_location`.

Geolocation is optional in the Shodan `host` response, so these tests pin
that a missing city or country no longer raises and no longer costs the
whole enrichment.

`ShodanConnector.__init__` builds a Shodan API client and an author, so it
is bypassed and only the attributes the method reads are stitched in.
"""

from types import SimpleNamespace

import pytest
from connector import ShodanConnector

_AUTHOR_ID = "identity--f0d2ba5a-4d1f-5a7f-8ba6-1a4b1a5b6c7d"
_OBSERVABLE_ID = "ipv4-addr--0c3a1b6e-5ec2-5a19-9b17-2d5ee3d1c0f1"

_FULL_LOCATION = {
    "city": "Paris",
    "country_name": "France",
    "country_code": "FR",
    "latitude": 48.8534,
    "longitude": 2.3488,
}


def _without(*fields):
    """A geolocation where some keys are missing, not just null.

    Shodan omits the field entirely for some hosts, so absent and null have
    to behave the same way.
    """
    return {k: v for k, v in _FULL_LOCATION.items() if k not in fields}


def _connector() -> ShodanConnector:
    conn = object.__new__(ShodanConnector)
    conn.shodan_identity = SimpleNamespace(id=_AUTHOR_ID)
    conn.stix_objects = []
    conn.stix_entity = {"id": _OBSERVABLE_ID}
    return conn


def _locations(conn):
    return [obj for obj in conn.stix_objects if obj["type"] == "location"]


def _relationships(conn):
    return [
        (obj["source_ref"], obj["target_ref"])
        for obj in conn.stix_objects
        if obj["type"] == "relationship"
    ]


def _location_type(location):
    return location["x_opencti_location_type"]


def test_city_and_country_are_both_built():
    conn = _connector()

    conn._generate_stix_location(_FULL_LOCATION)

    city, country = _locations(conn)
    assert (city["name"], _location_type(city)) == ("Paris", "City")
    assert (city["latitude"], city["longitude"]) == (48.8534, 2.3488)
    assert (country["name"], _location_type(country)) == ("France", "Country")
    assert country["x_opencti_aliases"] == ["FR"]
    assert _relationships(conn) == [
        (_OBSERVABLE_ID, city["id"]),
        (city["id"], country["id"]),
    ]


@pytest.mark.parametrize(
    "data",
    [
        {**_FULL_LOCATION, "city": None},
        {**_FULL_LOCATION, "city": ""},
        _without("city"),
    ],
    ids=["null", "empty", "absent"],
)
def test_a_missing_city_keeps_the_country(data):
    """The reported bug: Location.generate_id(None, "City") raised."""
    conn = _connector()

    conn._generate_stix_location(data)

    (country,) = _locations(conn)
    assert _location_type(country) == "Country"
    # The observable is attached to the country instead of being orphaned.
    assert _relationships(conn) == [(_OBSERVABLE_ID, country["id"])]


@pytest.mark.parametrize(
    "data",
    [
        {**_FULL_LOCATION, "country_name": None, "country_code": None},
        _without("country_name", "country_code"),
    ],
    ids=["null", "absent"],
)
def test_a_missing_country_keeps_the_city(data):
    conn = _connector()

    conn._generate_stix_location(data)

    (city,) = _locations(conn)
    assert _location_type(city) == "City"
    assert "country" not in city
    assert _relationships(conn) == [(_OBSERVABLE_ID, city["id"])]


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"city": None, "country_name": None},
        _without("city", "country_name"),
    ],
    ids=["no_geolocation_key", "null", "absent_with_coordinates"],
)
def test_no_location_at_all_produces_nothing(data):
    """No name means no id: the enrichment goes on without a Location."""
    conn = _connector()

    conn._generate_stix_location(data)

    assert conn.stix_objects == []


@pytest.mark.parametrize(
    "data",
    [{**_FULL_LOCATION, "country_code": None}, _without("country_code")],
    ids=["null", "absent"],
)
def test_a_missing_country_code_does_not_become_a_null_alias(data):
    conn = _connector()

    conn._generate_stix_location(data)

    country = _locations(conn)[1]
    assert "x_opencti_aliases" not in country


def test_a_single_coordinate_is_dropped():
    """stix2 rejects a latitude without a longitude, which used to raise."""
    conn = _connector()

    conn._generate_stix_location({**_FULL_LOCATION, "longitude": None})

    city = _locations(conn)[0]
    assert "latitude" not in city and "longitude" not in city
