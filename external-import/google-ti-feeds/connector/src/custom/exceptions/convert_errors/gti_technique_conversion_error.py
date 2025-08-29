"""Exception for errors when converting GTI attack techniques to STIX attack patterns."""

from typing import Optional

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTITechniqueConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI attack technique to STIX format."""

    def __init__(
        self,
        message: str,
        technique_id: Optional[str] = None,
        technique_name: Optional[str] = None,
        mitre_id: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            technique_id: ID of the attack technique that failed to convert
            technique_name: Name of the attack technique, if available
            mitre_id: MITRE ATT&CK ID, if available

        """
        super().__init__(message, technique_id, "AttackTechnique")
        self.technique_name = technique_name
        self.mitre_id = mitre_id

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if technique_name:
                self.structured_data["technique_name"] = technique_name
            if mitre_id:
                self.structured_data["mitre_id"] = mitre_id
        else:
            self.structured_data = {}
            if technique_name:
                self.structured_data["technique_name"] = technique_name
            if mitre_id:
                self.structured_data["mitre_id"] = mitre_id
