"""Exception for errors when converting GTI campaigns to STIX campaigns."""

from typing import Optional

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTICampaignConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI campaign to STIX format."""

    def __init__(
        self,
        message: str,
        campaign_id: Optional[str] = None,
        processing_stage: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            campaign_id: ID of the campaign that failed to convert
            processing_stage: The stage of processing where the error occurred

        """
        super().__init__(message, campaign_id, "Campaign")
        self.processing_stage = processing_stage

        if processing_stage:
            self.args = (f"{self.args[0]} (stage: {processing_stage})",)
