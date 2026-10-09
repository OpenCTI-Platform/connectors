"""Exception for errors when fetching IOC indicators from Google Threat Intelligence API."""

from typing import Any

from connector.src.custom.exceptions.fetch_errors.gti_api_error import GTIApiError


class GTIIndicatorFetchError(GTIApiError):
    """Exception raised when there's an error fetching IOC indicators from GTI API."""

    def __init__(
        self,
        message: str,
        package_id: str | None = None,
        endpoint: str | None = None,
        status_code: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        error_msg = f"Error fetching IOC indicator delta: {message}"
        super().__init__(error_msg, status_code, endpoint, details)
        self.package_id = package_id
        if hasattr(self, "structured_data"):
            if package_id:
                self.structured_data["package_id"] = package_id
        else:
            self.structured_data = {}
            if package_id:
                self.structured_data["package_id"] = package_id


class GTIIndicatorPackageUnavailableError(GTIIndicatorFetchError):
    """IOC delta package cannot be fetched yet but may be on a later run.

    Raised when the package is not published yet (HTTP 400), the API is rate
    limiting or failing (429, 5xx), or the request never completed. The caller
    must not mark the package as processed, so it is retried on the next run.
    """
