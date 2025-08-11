from typing import Any, Generator, Literal

import pycti
import stix2
from bs4 import BeautifulSoup
from pycti import OpenCTIConnectorHelper


class ConnectorWarning(Exception):
    """Custom warning for connector operations."""


class InvalidTlpLevelError(Exception):
    """Custom error for invalid TLP levels."""


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
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ) -> None:
        self.helper = helper
        self.author = self._create_author(
            name=author_name, description=author_description
        )
        self.tlp_marking = self._create_tlp_marking(tlp_level=tlp_level)

    @staticmethod
    def _create_author(name: str, description: str) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(name=name, identity_class="organization"),
            name=name,
            identity_class="organization",
            description=description,
        )

    @staticmethod
    def _create_tlp_marking(
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ) -> stix2.MarkingDefinition:
        match tlp_level:
            case "white" | "clear":
                return stix2.TLP_WHITE
            case "green":
                return stix2.TLP_GREEN
            case "amber":
                return stix2.TLP_AMBER
            case "amber+strict":
                return stix2.MarkingDefinition(
                    id=pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                    definition_type="statement",
                    definition={"statement": "custom"},
                    custom_properties={
                        "x_opencti_definition_type": "TLP",
                        "x_opencti_definition": "TLP:AMBER+STRICT",
                    },
                )
            case "red":
                return stix2.TLP_RED
            case _:  # default
                raise InvalidTlpLevelError(f"Invalid TLP level: {tlp_level}")

    def process(
        self, stix_object: dict[str, Any]
    ) -> Generator[dict[str, Any], None, None]:
        try:
            if "error" in stix_object:
                raise ConnectorWarning()
            if "created_by_ref" not in stix_object:
                stix_object["created_by_ref"] = self.author.id
            if "object_marking_refs" not in stix_object:
                stix_object["object_marking_refs"] = [self.tlp_marking.id]

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
            if stix_object.get("relationship_type") == "associated_content":
                stix_object["relationship_type"] = "related-to"

            # Labels are not properly assigned in ThreatMatch
            stix_object.pop("labels", None)

            yield stix_object
        except Exception as e:
            self.helper.connector_logger.warning(
                "An error occurred while processing an entity, skipping...",
                {"error": str(e), "stix_object": stix_object},
            )
