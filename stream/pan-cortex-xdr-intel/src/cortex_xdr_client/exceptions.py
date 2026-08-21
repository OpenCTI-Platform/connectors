class CortexXdrClientError(Exception):
    """Base exception raised from CortexXdrClient."""

    pass


class CortexXdrRequestBodyError(CortexXdrClientError):
    """Exception raised when the request body is invalid."""

    pass


class CortexXdrApiError(CortexXdrClientError):
    """Exception raised when the Cortex XDR API returns an error."""

    pass
