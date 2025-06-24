"""Exception for pagination-related errors when fetching data from Google Threat Intelligence."""

from typing import Optional

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIPaginationError(GTIApiError):
    """Exception raised when there's an error with pagination while fetching data."""

    def __init__(
        self,
        message: str,
        endpoint: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
        status_code: Optional[int] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            endpoint: API endpoint where the error occurred
            page: Page number that caused the error
            page_size: Size of the page requested
            status_code: HTTP status code, if available

        """
        pagination_details = []
        if page is not None:
            pagination_details.append(f"page={page}")
        if page_size is not None:
            pagination_details.append(f"size={page_size}")

        pagination_info = ""
        if pagination_details:
            pagination_info = f" with {', '.join(pagination_details)}"

        error_msg = f"Pagination error{pagination_info}: {message}"

        super().__init__(error_msg, status_code, endpoint)
        self.page = page
        self.page_size = page_size
