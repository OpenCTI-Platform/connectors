"""Exception for errors when fetching campaigns from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTICampaignFetchError(GTIApiError):
    """Exception raised when there's an error fetching campaigns from GTI API."""

    def __init__(
        self,
        message: str,
        campaign_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
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
            error_msg = f"Error fetching campaign {campaign_id}: {message}"
        else:
            error_msg = f"Error fetching campaigns: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.campaign_id = campaign_id
