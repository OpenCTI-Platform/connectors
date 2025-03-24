from typing import Literal

import pycti
import stix2


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper: pycti.OpenCTIConnectorHelper):
        self.helper = helper
        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking("white")

    def _create_author(
        self,
    ) -> stix2.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                name=self.helper.connect_name, identity_class="organization"
            ),
            name=self.helper.connect_name,
            identity_class="organization",
            description="Shodan is a search engine for Internet-connected devices.",
        )

    @staticmethod
    def _create_tlp_marking(
        level: Literal["white", "clear", "green", "amber", "amber+strict", "red"],
    ) -> stix2.MarkingDefinition:
        match level:
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
                raise ValueError(f"Invalid TLP level: {level}")
