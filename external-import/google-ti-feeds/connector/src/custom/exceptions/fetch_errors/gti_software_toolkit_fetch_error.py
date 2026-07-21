"""Exception for errors when fetching GTI software toolkits."""

from connector.src.custom.exceptions.gti_fetching_error import GTIFetchingError


class GTISoftwareToolkitFetchError(GTIFetchingError):
    """Exception raised when there's an error fetching GTI software toolkit data."""
