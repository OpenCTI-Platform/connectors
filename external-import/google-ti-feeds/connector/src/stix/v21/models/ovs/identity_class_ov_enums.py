"""The module contains the IdentityClassOV enum class."""

from connector.src.stix.v21.models.ovs.base_open_vocab import BaseOV


class IdentityClassOV(BaseOV):
    """Identity Class Enumeration."""

    INDIVIDUAL = "individual"
    GROUP = "group"
    SYSTEM = "system"
    ORGANIZATION = "organization"
    CLASS_ = "class"
    UNKNOWN = "unknown"
