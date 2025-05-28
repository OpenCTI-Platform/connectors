"""Exception for errors when fetching reports from Google Threat Intelligence API."""

from typing import Any, Dict, Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIReportFetchError(GTIApiError):
    """Exception raised when there's an error fetching reports from GTI API."""

    def __init__(
        self,
        message: str,
        report_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            report_id: ID of the report that failed to fetch, if applicable
            endpoint: API endpoint where the error occurred
            status_code: HTTP status code, if available
            details: Additional details about the error

        """
        if report_id:
            error_msg = f"Error fetching report {report_id}: {message}"
        else:
            error_msg = f"Error fetching reports: {message}"

        super().__init__(error_msg, status_code, endpoint, details)
        self.report_id = report_id
