class CrowdstrikeAPIError(Exception):
    """Custom exception class for CrowdStrike API errors."""

    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code