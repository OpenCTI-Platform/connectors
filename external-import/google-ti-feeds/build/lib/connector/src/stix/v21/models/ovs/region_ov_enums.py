"""The module contains the RegionOV enum class, which defines various geographical regions."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class RegionOV(BaseOV):
    """Region Enumeration."""

    AFRICA = "africa"
    EASTERN_AFRICA = "eastern-africa"
    MIDDLE_AFRICA = "middle-africa"
    NORTHERN_AFRICA = "northern-africa"
    SOUTHERN_AFRICA = "southern-africa"
    WESTERN_AFRICA = "western-africa"

    AMERICAS = "americas"
    LATIN_AMERICA_CARIBBEAN = "latin-america-caribbean"
    SOUTH_AMERICA = "south-america"
    CARIBBEAN = "caribbean"
    CENTRAL_AMERICA = "central-america"
    NORTHERN_AMERICA = "northern-america"

    ASIA = "asia"
    CENTRAL_ASIA = "central-asia"
    EASTERN_ASIA = "eastern-asia"
    SOUTHERN_ASIA = "southern-asia"
    SOUTH_EASTERN_ASIA = "south-eastern-asia"
    WESTERN_ASIA = "western-asia"

    EUROPE = "europe"
    EASTERN_EUROPE = "eastern-europe"
    NORTHERN_EUROPE = "northern-europe"
    SOUTHERN_EUROPE = "southern-europe"
    WESTERN_EUROPE = "western-europe"

    OCEANIA = "oceania"
    ANTARCTICA = "antarctica"
    AUSTRALIA_NEW_ZEALAND = "australia-new-zealand"
    MELANESIA = "melanesia"
    MICRONESIA = "micronesia"
    POLYNESIA = "polynesia"
