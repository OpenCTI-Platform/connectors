import abc
from typing import Any, Generic, TypeVar

import pycti
import stix2
from base_connector.config import BaseConnectorConfig
from base_connector.errors import InvalidTlpLevelError
from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel

EntityType = TypeVar("EntityType")
StixType = TypeVar("StixType", bound=dict[str, Any])


class Author(BaseModel):
    name: str
    description: str


class BaseConverter(abc.ABC, Generic[EntityType, StixType]):
    """
    Base class for all converters.

    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    author_name: str
    author_description: str

    def __init__(
        self, helper: OpenCTIConnectorHelper, config: BaseConnectorConfig
    ) -> None:
        super().__init__()
        self.helper = helper
        self.config = config
        self.author = self._create_author()
        self.tlp_marking = self._create_tlp_marking()

    def _create_author(self) -> stix2.Identity:
        return stix2.Identity(
            id=pycti.Identity.generate_id(
                name=self.author_name, identity_class="organization"
            ),
            name=self.author_name,
            identity_class="organization",
            description=self.author_description,
        )

    def _create_tlp_marking(self) -> stix2.MarkingDefinition:
        match self.config.tlp_level:
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
                raise InvalidTlpLevelError(
                    f"Invalid TLP level: {self.config.tlp_level}"
                )

    @abc.abstractmethod
    def to_stix(self, entity: EntityType) -> list[StixType]:
        """Convert the data into STIX 2.1 objects."""
