from typing import Any

from base_connector.converter import BaseConverter
from email_intel.models import EmailIntelMessage


class ConnectorConverter(BaseConverter[EmailIntelMessage, dict[str, Any]]):
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def to_stix(
        self, entity: EmailIntelMessage
    ) -> list[Any]:  # FIXME: Change to explicit stix entity types ?
        """
        Convert the data into STIX 2.1 objects by using default parent class object definition.
        """
        stix_objects: list[Any] = []  # FIXME: Change to explicit stix entity types

        # TODO: Add your code here to convert the data into STIX 2.1 objects

        return stix_objects
