"""CrowdStrikeSectorConverter."""

from connectors_sdk.converters.base import AbstractConverter
from connectors_sdk.converters.crowdstrike.models import CrowdStrikeEntity
from connectors_sdk.models import BaseIdentifiedObject, Sector


class CrowdStrikeSectorConverter(AbstractConverter[CrowdStrikeEntity]):
    """Convert a CrowdStrike industry entity into a sector.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor
        >>> converter = CrowdStrikeSectorConverter(
        ...     author=OrganizationAuthor(name="CrowdStrike"), markings=[]
        ... )
        >>> [obj.name for obj in converter.transform(CrowdStrikeEntity(value="Energy"))]
        ['Energy']

    """

    def transform(self, input: CrowdStrikeEntity) -> list[BaseIdentifiedObject]:
        """Convert an industry entity.

        Args:
            input: The industry entity.

        Returns:
            One sector, or an empty list when the entity has no value.
        """
        if not input.value:
            return []
        return [Sector(name=input.value, author=self.author, markings=self.markings)]
