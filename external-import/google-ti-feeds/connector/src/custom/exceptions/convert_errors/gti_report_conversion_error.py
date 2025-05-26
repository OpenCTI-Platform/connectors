"""Exception for errors when converting GTI reports to STIX reports."""

from typing import Optional

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTIReportConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI report to STIX format."""

    def __init__(
        self,
        message: str,
        report_id: Optional[str] = None,
        processing_stage: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            report_id: ID of the report that failed to convert
            processing_stage: The stage of processing where the error occurred

        """
        super().__init__(message, report_id, "Report")
        self.processing_stage = processing_stage

        if processing_stage:
            self.args = (f"{self.args[0]} (stage: {processing_stage})",)
