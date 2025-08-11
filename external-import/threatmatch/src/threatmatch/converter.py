from typing import Any, Generator

import pycti
import stix2
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper


class ConnectorWarning(Exception):
    """Custom warning for connector operations."""


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

    def process(
        self, stix_object: dict[str, Any]
    ) -> Generator[dict[str, Any], None, None]:
        try:
            if "error" in stix_object:
                raise ConnectorWarning()
            if "created_by_ref" not in stix_object:
                stix_object["created_by_ref"] = self.author.id
            if "object_refs" in stix_object and stix_object["type"] not in [
                "report",
                "note",
                "opinion",
                "observed-data",
            ]:
                del stix_object["object_refs"]
            if "description" in stix_object and stix_object["description"]:
                stix_object["description"] = BeautifulSoup(
                    stix_object["description"], "html.parser"
                ).get_text()
            yield stix_object
        except Exception as e:
            self.helper.connector_logger.warning(
                "An error occurred while processing an entity, skipping...",
                {"error": str(e), "stix_object": stix_object},
            )
