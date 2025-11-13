"""Exception for errors when parsing responses from Google Threat Intelligence API."""

from connector.src.custom.exceptions.gti_fetching_error import GTIFetchingError


class GTIParsingError(GTIFetchingError):
    """Exception raised when there's an error parsing API responses."""

    def __init__(
        self,
        message: str,
        endpoint: str | None = None,
        entity_type: str | None = None,
        data_sample: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            endpoint: API endpoint where the response was received
            entity_type: Type of entity being parsed (e.g., "report", "malware")
            data_sample: Sample of the data that failed to parse (truncated if large)

        """
        if entity_type and endpoint:
            error_msg = "Error parsing entity data from endpoint: {message}"
        elif entity_type:
            error_msg = "Error parsing entity data: {message}"
        elif endpoint:
            error_msg = "Error parsing response from endpoint: {message}"
        else:
            error_msg = f"Error parsing response: {message}"

        super().__init__(error_msg)
        self.endpoint = endpoint
        self.entity_type = entity_type

        if data_sample and isinstance(data_sample, str):
            if len(data_sample) > 200:
                self.data_sample = data_sample[:200] + "..."
            else:
                self.data_sample = data_sample
        else:
            self.data_sample = ""

        # Add structured data for logging
        self.structured_data = {
            "original_message": message,
        }
        if endpoint:
            self.structured_data["endpoint"] = endpoint
        if entity_type:
            self.structured_data["entity_type"] = entity_type
        if self.data_sample:
            self.structured_data["data_sample"] = self.data_sample
