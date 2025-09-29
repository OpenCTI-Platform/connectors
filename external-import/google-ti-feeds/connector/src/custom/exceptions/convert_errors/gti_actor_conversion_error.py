"""Exception for errors when converting GTI threat actors to STIX intrusion sets."""

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTIActorConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI threat actor to STIX format."""

    def __init__(
        self,
        message: str,
        actor_id: str | None = None,
        actor_name: str | None = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            actor_id: ID of the threat actor that failed to convert
            actor_name: Name of the threat actor, if available

        """
        super().__init__(message, actor_id, "ThreatActor")
        self.actor_name = actor_name

        # Add structured data for logging
        if hasattr(self, "structured_data"):
            if actor_name:
                self.structured_data["actor_name"] = actor_name
        else:
            self.structured_data = {}
            if actor_name:
                self.structured_data["actor_name"] = actor_name
