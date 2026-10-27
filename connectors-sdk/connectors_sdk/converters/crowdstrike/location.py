"""CrowdStrikeLocationConverter."""

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.crowdstrike.models import CrowdStrikeEntity
from connectors_sdk.models import BaseIdentifiedObject, Country, Region

UNKNOWN_SLUG = "unknown"


class CrowdStrikeLocationConverter(AbstractConverter[CrowdStrikeEntity]):
    """Convert a CrowdStrike location entity into a country or a region.

    CrowdStrike mixes countries and regions in the same lists: a 2-letter slug
    is a country code, a longer slug is a region.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor
        >>> converter = CrowdStrikeLocationConverter(
        ...     author=OrganizationAuthor(name="CrowdStrike"), markings=[]
        ... )
        >>> [obj.name for obj in converter.transform(CrowdStrikeEntity(slug="fr", value="France"))]
        ['France']

    """

    def transform(self, input: CrowdStrikeEntity) -> list[BaseIdentifiedObject]:
        """Convert a location entity.

        Args:
            input: The location entity.

        Returns:
            One country or region, or an empty list for an unknown location.
        """
        if input.slug is None or input.value is None or input.slug == UNKNOWN_SLUG:
            return []
        if len(input.slug) > 2:
            return [
                Region(name=input.value, author=self.author, markings=self.markings)
            ]
        return [
            Country(
                name=input.value,
                aliases=[input.slug.upper()],
                author=self.author,
                markings=self.markings,
            )
        ]
