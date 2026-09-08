"""Tests for `Utils.get_location_info`.

ET Intelligence returns country codes that are not always part of
ISO 3166-1, so pycountry has no entry for them. These tests pin that an
unresolvable code no longer raises: the Location is then built from the name
carried by the payload, or skipped by the caller when there is none.
"""

import pytest
from connector.services.utils import Utils


def _geolocation(**overrides):
    geolocation = {"country_code": "FR", "country": "France", "region": "IDF"}
    geolocation.update(overrides)
    return geolocation


# --------------------------------------------------------------------------
# A resolvable code is upgraded to its official name, as before
# --------------------------------------------------------------------------


def test_a_known_code_gives_the_official_name():
    result = Utils.get_location_info(_geolocation())

    assert result["country"] == "French Republic"
    assert result["region"] == "Île-de-France"


def test_a_known_code_without_an_official_name_keeps_the_payload_name():
    """Not every ISO country has an official_name in pycountry."""
    result = Utils.get_location_info(
        _geolocation(country_code="AW", country="Aruba", region=None)
    )

    assert result["country"] == "Aruba"


# --------------------------------------------------------------------------
# An unresolvable code no longer raises
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "country_code",
    ["XK", "EU", "AP", "A1", "A2", "ZZ", ""],
    ids=[
        "kosovo",
        "europe",
        "asia_pacific",
        "anon_proxy",
        "satellite",
        "junk",
        "empty",
    ],
)
def test_an_unresolvable_code_falls_back_on_the_payload_name(country_code):
    """The reported bug: pycountry returns None, `country_info.name` raised."""
    result = Utils.get_location_info(
        _geolocation(country_code=country_code, country="Kosovo", region=None)
    )

    assert result["country"] == "Kosovo"


def test_a_missing_code_does_not_raise_a_lookup_error():
    """pycountry.countries.get(alpha_2=None) raises, it does not return None."""
    result = Utils.get_location_info({"country": "Kosovo"})

    assert result["country"] == "Kosovo"


def test_no_country_at_all_leaves_the_field_empty():
    """The caller skips the Location on this one."""
    result = Utils.get_location_info({"country_code": "XK"})

    assert result["country"] is None


# --------------------------------------------------------------------------
# The region is derived from the code, which may be unresolvable too
# --------------------------------------------------------------------------


def test_an_unresolvable_subdivision_keeps_the_raw_region():
    result = Utils.get_location_info(_geolocation(region="ZZZ"))

    assert result["region"] == "ZZZ"


def test_a_region_without_a_country_code_keeps_the_raw_region():
    result = Utils.get_location_info({"country": "Kosovo", "region": "01"})

    assert result["region"] == "01"


def test_no_region_gives_none():
    result = Utils.get_location_info(_geolocation(region=None))

    assert result["region"] is None
