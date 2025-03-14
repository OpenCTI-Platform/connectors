"""Offer common tools for use cases."""

import ipaddress
from typing import TYPE_CHECKING

from dragos.domain.models.octi import OrganizationAuthor, TLPMarking

if TYPE_CHECKING:
    from dragos.domain.models.octi.enums import TLPLevel


class UseCaseError(Exception):
    """Known errors wrapper for use cases."""


class BaseUseCase:
    """Base use case class."""

    def __init__(self, tlp_level: "TLPLevel"):
        """Initialize the use case."""
        self.tlp_marking = TLPMarking(level=tlp_level)
        self.author = OrganizationAuthor(
            name="Dragos",
            description="Dragos WorldView provides actionable information and recommendations on threats to operations technology (OT) environments.",
            contact_information="https://www.dragos.com/us/contact",
            organization_type="vendor",
            reliability=None,
            aliases=None,
            author=None,
            markings=None,
            external_references=None,
        )

    def _is_ipv4(self, value: str) -> bool:
        """Check if value is a valid IPv4 address."""
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    def _is_ipv6(self, value: str) -> bool:
        """Check if value is a valid IPv6 address."""
        try:
            ipaddress.IPv6Address(value)
            return True
        except ValueError:
            return False
