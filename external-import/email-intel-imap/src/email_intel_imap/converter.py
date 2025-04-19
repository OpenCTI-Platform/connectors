from typing import Any

import stix2
from base_connector.converter import BaseConverter


class ConnectorConverter(BaseConverter[Any, dict[str, Any]]):
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    author_name: str = "Email Intel IMAP"
    author_description: str = "Email Intel IMAP Connector"

    def to_stix(self, entity: Any) -> list[stix2.Report]:
        """
        Convert the data into STIX 2.1 objects by using default parent class object definition.
        """
        return []
