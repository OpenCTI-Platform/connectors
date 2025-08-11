import pycti
import stix2
from pycti import OpenCTIConnectorHelper


class Converter:
    """
    Base class for all converters.

    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author_name: str,
        author_description: str,
    ) -> None:
        self.helper = helper
        self.author = self._create_author(
            name=author_name, description=author_description
        )

    @staticmethod
    def _create_author(name: str, description: str) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(name=name, identity_class="organization"),
            name=name,
            identity_class="organization",
            description=description,
        )
