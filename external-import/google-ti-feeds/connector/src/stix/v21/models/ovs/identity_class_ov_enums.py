"""The module contains the IdentityClassOV enum class."""

from enum import Enum


class IdentityClassOV(str, Enum):
    """Identity Class Enumeration."""

    INDIVIDUAL = "individual"
    GROUP = "group"
    SYSTEM = "system"
    ORGANIZATION = "organization"
    CLASS_ = "class"
    UNKNOWN = "unknown"
