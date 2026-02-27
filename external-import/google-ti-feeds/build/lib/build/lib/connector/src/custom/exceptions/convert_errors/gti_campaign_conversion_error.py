"""Exception for errors when converting GTI campaigns to STIX format."""

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTICampaignConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI campaign to STIX format."""

    def __init__(
        self,
        message: str,
        campaign_id: str | None = None,
        campaign_name: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            campaign_id: ID of the campaign that failed to convert
            campaign_name: Name of the campaign, if available

        """
        super().__init__(message, campaign_id, "Campaign")
        self.campaign_name = campaign_name

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if campaign_name:
                self.structured_data["campaign_name"] = campaign_name
        else:
            self.structured_data = {}
            if campaign_name:
                self.structured_data["campaign_name"] = campaign_name
