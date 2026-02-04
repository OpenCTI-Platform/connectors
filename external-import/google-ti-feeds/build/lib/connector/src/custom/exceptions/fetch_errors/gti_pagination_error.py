"""Exception for pagination-related errors when fetching data from Google Threat Intelligence."""

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIPaginationError(GTIApiError):
    """Exception raised when there's an error with pagination while fetching data."""

    def __init__(
        self,
        message: str,
        endpoint: str | None = None,
        page: str | None = None,
        page_size: str | None = None,
        status_code: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            endpoint: API endpoint where the error occurred
            page: Page number that caused the error
            page_size: Size of the page requested
            status_code: HTTP status code, if available

        """
        error_msg = "Pagination error: {message}"

        super().__init__(error_msg, status_code, endpoint)
        self.page = page
        self.page_size = page_size

        if hasattr(self, "structured_data"):
            if page is not None:
                self.structured_data["page"] = page
            if page_size is not None:
                self.structured_data["page_size"] = page_size
        else:
            self.structured_data = {
                "original_message": message,
            }
            if page is not None:
                self.structured_data["page"] = page
            if page_size is not None:
                self.structured_data["page_size"] = page_size
