"""Exception for errors when fetching campaigns from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTICampaignFetchError(GTIApiError):
    """Exception raised when there's an error fetching campaigns from GTI API."""

    def __init__(
        self,
        message: str,
        campaign_id: str | None = None,
        endpoint: str | None = None,
        status_code: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            campaign_id: ID of the campaign that failed to fetch, if applicable
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        if campaign_id:
            error_msg = "Error fetching campaign: {message}"
        else:
            error_msg = "Error fetching campaigns: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.campaign_id = campaign_id

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if campaign_id:
                self.structured_data["campaign_id"] = campaign_id
        else:
            self.structured_data = {}
            if campaign_id:
                self.structured_data["campaign_id"] = campaign_id
