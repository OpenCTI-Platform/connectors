"""Converts a GTI threat actor's targeted industries to STIX Identity (sector) objects."""

from connector.src.custom.mappers.targeting_mappers import (
    BaseSectorMapper,
    entity_alias,
)
from connector.src.custom.models.gti.gti_threat_actor_model import GTIThreatActorData
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIThreatActorToSTIXIdentity(BaseSectorMapper):
    """Converts a GTI threat actor's targeted industries to STIX Identity (sector) objects."""

    entity_label = "threat actor"
    threat_actor = entity_alias("The GTI threat actor being converted.")

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the mapper.

        Args:
            threat_actor: The GTI threat actor data to convert.
            organization: The organization identity object.
            tlp_marking: The TLP marking definition.

        """
        super().__init__(threat_actor, organization, tlp_marking)
