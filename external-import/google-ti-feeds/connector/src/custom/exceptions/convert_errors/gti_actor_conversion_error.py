"""Exception for errors when converting GTI threat actors to STIX intrusion sets."""

from typing import Optional

from connector.src.custom.exceptions.convert_errors.gti_entity_conversion_error import (
    GTIEntityConversionError,
)


class GTIActorConversionError(GTIEntityConversionError):
    """Exception raised when there's an error converting a GTI threat actor to STIX format."""

    def __init__(
        self,
        message: str,
        actor_id: Optional[str] = None,
        actor_name: Optional[str] = None,
    ):
        """Initialize the exception.

        Args:
            message: Error message
            actor_id: ID of the threat actor that failed to convert
            actor_name: Name of the threat actor, if available

        """
        super().__init__(message, actor_id, "ThreatActor")
        self.actor_name = actor_name

        if actor_name and not self.args[0].endswith(f"(name: {actor_name})"):
            self.args = (f"{self.args[0]} (name: {actor_name})",)
