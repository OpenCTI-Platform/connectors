"""Converter from Google SecOps data to STIX 2.1 objects."""

from connectors_sdk.models import OrganizationAuthor, TLPMarking
from connectors_sdk.models.enums import TLPLevel
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """Converts Google SecOps intelligence into STIX 2.1 objects.

    Attributes:
        helper: OpenCTI connector helper.
        author: STIX Identity representing the connector author.
        tlp_marking: STIX MarkingDefinition for the configured TLP level.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, tlp_level: str) -> None:
        """Initialise the converter.

        Args:
            helper: OpenCTI connector helper.
            tlp_level: TLP level applied to all created entities.
        """
        self.helper = helper
        self.author = OrganizationAuthor(name="Google SecOps").to_stix2_object()
        self.tlp_marking = TLPMarking(level=TLPLevel(tlp_level)).to_stix2_object()
