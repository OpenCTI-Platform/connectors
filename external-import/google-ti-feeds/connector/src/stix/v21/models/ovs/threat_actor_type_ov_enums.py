"""The module contains the ThreatActorTypeOV enum class."""

from enum import Enum


class ThreatActorTypeOV(str, Enum):
    """Threat Actor Type Enumeration."""

    ACTIVIST = "activist"
    COMPETITOR = "competitor"
    CRIME_SYNDICATE = "crime-syndicate"
    CRIMINAL = "criminal"
    HACKER = "hacker"
    INSIDER_ACCIDENTAL = "insider-accidental"
    INSIDER_DISGRUNTLED = "insider-disgruntled"
    NATION_STATE = "nation-state"
    SENSATIONALIST = "sensationalist"
    SPY = "spy"
    TERRORIST = "terrorist"
    UNKNOWN = "unknown"
