"""Converts a GTI software toolkit's targeted industries to STIX Identity (sector) objects."""

from connector.src.custom.mappers.targeting_mappers import (
    BaseSectorMapper,
    entity_alias,
)
from connector.src.custom.models.gti.gti_software_toolkit_model import (
    GTISoftwareToolkitData,
)
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTISoftwareToolkitToSTIXIdentity(BaseSectorMapper):
    """Converts a GTI software toolkit's targeted industries to STIX Identity (sector) objects."""

    entity_label = "software toolkit"
    software_toolkit = entity_alias("The GTI software toolkit being converted.")

    def __init__(
        self,
        software_toolkit: GTISoftwareToolkitData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the mapper.

        Args:
            software_toolkit: The GTI software toolkit data to convert.
            organization: The organization identity object.
            tlp_marking: The TLP marking definition.

        """
        super().__init__(software_toolkit, organization, tlp_marking)
