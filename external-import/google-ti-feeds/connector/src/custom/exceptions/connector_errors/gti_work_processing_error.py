"""Exception for errors when processing work in the connector."""

from connector.src.custom.exceptions.gti_base_error import GTIBaseError


class GTIWorkProcessingError(GTIBaseError):
    """Exception raised when there's an error processing work in the connector."""

    def __init__(self, message: str, work_id: str = None, details: dict = None):
        """Initialize the exception.
        
        Args:
            message: Error message
            work_id: ID of the work that failed to process
            details: Additional details about the error
        """
        error_msg = message
        if work_id:
            error_msg = f"Error processing work {work_id}: {message}"
            
        super().__init__(error_msg)
        self.work_id = work_id
        self.details = details or {}