"""Campaign-specific converter for fetching and processing campaign data."""

import logging
from typing import Any

from connector.src.custom.convert_to_stix.convert_to_stix_base import BaseConvertToSTIX

LOG_PREFIX = "[ConvertToSTIXCampaign]"


class ConvertToSTIXCampaign(BaseConvertToSTIX):
    """Campaign-specific converter for fetching and processing campaign data."""

    def __init__(self, config: Any, logger: logging.Logger, tlp_level: str):
        """Initialize Campaign Converter."""
        super().__init__(config, logger, tlp_level)

    def convert_campaign_to_stix(self, campaign_data: Any) -> list[Any]:
        """Convert campaign to location, identity, and campaign STIX objects.

        Args:
            campaign_data: GTICampaignData object from fetcher

        Returns:
            list of STIX entities (location, identity, campaign)

        """
        try:
            converter = self.converter_factory.create_converter_by_name("campaign")
            stix_entities = converter.convert_single(campaign_data)

            if not isinstance(stix_entities, list):
                stix_entities = [stix_entities]

            self.logger.debug(
                "Converted campaign to STIX entities",
                {"prefix": LOG_PREFIX, "entity_count": len(stix_entities)},
            )
            return stix_entities

        except Exception as e:
            self.logger.error(
                "Failed to convert campaign to STIX",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return []
