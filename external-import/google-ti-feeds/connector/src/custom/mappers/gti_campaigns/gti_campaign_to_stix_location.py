"""Converts a GTI campaign's country regions to STIX Location objects."""

from connector.src.custom.mappers.targeting_mappers import (
    BaseCountryMapper,
    entity_alias,
)
from connector.src.custom.models.gti.gti_campaign_model import GTICampaignData
from connectors_sdk.models import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTICampaignToSTIXLocation(BaseCountryMapper):
    """Converts a GTI campaign's country regions to STIX Location objects."""

    entity_label = "campaign"
    campaign = entity_alias("The GTI campaign being converted.")

    def __init__(
        self,
        campaign: GTICampaignData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the mapper.

        Args:
            campaign: The GTI campaign data to convert.
            organization: The organization identity object.
            tlp_marking: The TLP marking definition.

        """
        super().__init__(campaign, organization, tlp_marking)
