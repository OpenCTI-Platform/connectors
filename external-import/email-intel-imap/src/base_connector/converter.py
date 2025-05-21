import abc
import datetime
from collections import OrderedDict
from typing import Any, Generator, Literal

import pycti
import stix2
from base_connector.errors import InvalidTlpLevelError
from base_connector.models import OpenCTIFile, ReportCustomProperties
from pycti import OpenCTIConnectorHelper
from stix2.properties import ListProperty, ReferenceProperty


class RFReport(stix2.Report):
    """Subclass of Report with 'object_refs' property set to required=False."""

    _properties = OrderedDict(
        stix2.Report._properties  # pylint: disable=protected-access
    )  # Copy the parent class properties
    _properties["object_refs"] = ListProperty(
        ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version="2.1"),
        required=False,
    )


class BaseConverter(abc.ABC):
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

    def _create_report(
        self,
        name: str,
        published: datetime.datetime,
        report_types: list[str],
        x_opencti_content: str,
        x_opencti_files: list[OpenCTIFile],
        description: str,
    ) -> stix2.Report:
        return RFReport(
            id=pycti.Report.generate_id(name=name, published=published),
            name=name,
            report_types=report_types,
            published=published,
            object_marking_refs=[self.tlp_marking],
            custom_properties=ReportCustomProperties(
                x_opencti_content=x_opencti_content,
                x_opencti_files=x_opencti_files,
            ).model_dump(),
            description=description,
        )

    @abc.abstractmethod
    def to_stix_objects(
        self, entity: Any
    ) -> Generator[stix2.v21._STIXBase21, None, None]:
        """Convert the data into STIX 2.1 objects."""
