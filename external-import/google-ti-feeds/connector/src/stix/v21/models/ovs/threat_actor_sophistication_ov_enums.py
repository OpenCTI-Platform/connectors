"""The module defines the ThreatActorSophisticationOV enum class."""

from enum import Enum


class ThreatActorSophisticationOV(str, Enum):
    """Threat Actor Sophistication Enumeration."""

    NONE = "none"
    MINIMAL = "minimal"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"
    INNOVATOR = "innovator"
    STRATEGIC = "strategic"
