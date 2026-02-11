"""Exception for errors when converting GTI attack techniques to STIX attack patterns."""

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTITechniqueConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI attack technique to STIX format."""

    def __init__(
        self,
        message: str,
        technique_id: str | None = None,
        technique_name: str | None = None,
        mitre_id: str | None = None,
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
