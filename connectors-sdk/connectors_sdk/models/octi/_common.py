"""Offer common tools to for OpenCTI models."""

import codecs
from abc import ABC, abstractmethod
from typing import OrderedDict

import stix2.properties
from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.base_entity import BaseEntity
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.octi.enums import TLPLevel
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pydantic import Field
from stix2.v21 import TLP_AMBER, TLP_GREEN, TLP_RED, TLP_WHITE
from stix2.v21 import MarkingDefinition as Stix2MarkingDefinition


class AssociatedFileStix(stix2.v21._STIXBase21):  # type: ignore[misc]
    # As stix2 is untyped, subclassing one of its element is not handled by type checkers.
    # Note: This is a candidate for refactoring in the pycti package.
    """Stix like object for Associated File.

    Examples:
        >>> associated_file_stix = AssociatedFileStix(
        ...     name="example_file.txt",
        ...     data="VGhpcyBpcyBhbiBleGFtcGxlIGZpbGUgY29udGVudC4=",  # Base64 encoded content
        ...     mime_type="text/plain",
        ...     object_marking_refs=[stix2.TLP_WHITE.get("id")],
        ...     version="1.0"
        ... )

    """

    _properties = OrderedDict(
        [
            ("spec_version", stix2.properties.StringProperty(fixed="2.1")),
            ("name", stix2.properties.StringProperty()),
            ("data", stix2.properties.StringProperty(default=None)),
            ("mime_type", stix2.properties.StringProperty(default=None)),
            ("description", stix2.properties.StringProperty(default=None)),
            (
                "object_marking_refs",
                stix2.properties.ListProperty(
                    stix2.properties.ReferenceProperty(
                        valid_types="marking-definition", spec_version="2.1"
                    )
                ),
            ),
            ("version", stix2.properties.StringProperty(default=None)),
            ("no_import_flag", stix2.properties.BooleanProperty(default=False)),
        ]
    )


@MODEL_REGISTRY.register
class AssociatedFile(BaseEntity):
    """Represents a SDO's or SCO's corresponding file, such as a Report PDF or an Artifact binary.

    Examples:
        >>> associated_file = AssociatedFile(
        ...     name="example_file.txt",
        ...     description="An example file for demonstration purposes.",
        ...     content=b"qwerty",
        ...     mime_type="text/plain",
        ...     markings=[TLPMarking(level="white")],
        ...     )

    """

    name: str = Field(
        description="The name of the file.",
    )
    description: str | None = Field(
        default=None,
        description="Description of the file.",
    )
    content: bytes | None = Field(
        default=None,
        description="The file content.",
    )
    mime_type: str | None = Field(
        default=None,
        description="File mime type.",
    )
    markings: list["TLPMarking"] | None = Field(
        default=None,
        description="References for object marking.",
    )
    version: str | None = Field(
        default=None,
        description="Version of the file.",
    )

    def to_stix2_object(self) -> AssociatedFileStix:
        """Make stix-like object (not defined in stix spec nor lib).

        Returns:
            (AssociatedFileStix): A stix like object, defigning a file to upload into the OCTI platform

        """
        return AssociatedFileStix(
            name=self.name,
            description=self.description,
            data=(
                codecs.encode(self.content, "base64").decode("utf-8")
                if self.content
                else None
            ),
            mime_type=self.mime_type,
            object_marking_refs=(
                [marking.id for marking in self.markings or []]
                if self.markings
                else None
            ),
            version=self.version,
        )


@MODEL_REGISTRY.register
class Author(ABC, BaseIdentifiedEntity):
    """Represent an author.

    Author is an OpenCTI concept, a stix-like identity considered as the creator of a
    report or an entity.

    Warning:
        This class cannot be used directly, it must be subclassed.

    """

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object.

        Returns:
            (stix2.v21._STIXBase21): A stix object representing the author.

        """


@MODEL_REGISTRY.register
class TLPMarking(BaseIdentifiedEntity):
    """Represent a TLP marking definition."""

    level: TLPLevel = Field(description="The level of the TLP marking.")

    def to_stix2_object(self) -> Stix2MarkingDefinition:
        """Make stix object."""
        mapping = {
            "clear": Stix2MarkingDefinition(
                id=PyctiMarkingDefinition.generate_id("TLP", "TLP:CLEAR"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:CLEAR",
            ),
            "white": TLP_WHITE,
            "green": TLP_GREEN,
            "amber": TLP_AMBER,
            "amber+strict": Stix2MarkingDefinition(
                id=PyctiMarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                x_opencti_definition_type="TLP",
                x_opencti_definition="TLP:AMBER+STRICT",
            ),
            "red": TLP_RED,
        }
        return mapping[self.level]


@MODEL_REGISTRY.register
class ExternalReference(BaseEntity):
    """Represents an external reference to a source of information."""

    source_name: str = Field(
        description="The name of the source of the external reference.",
    )
    description: str | None = Field(
        default=None,
        description="Description of the external reference.",
    )
    url: str | None = Field(
        default=None,
        description="URL of the external reference.",
    )
    external_id: str | None = Field(
        default=None,
        description="An identifier for the external reference content.",
    )

    def to_stix2_object(self) -> stix2.v21.ExternalReference:
        """Make stix object."""
        return stix2.ExternalReference(
            source_name=self.source_name,
            description=self.description,
            url=self.url,
            external_id=self.external_id,
        )


# See https://docs.pydantic.dev/latest/errors/usage_errors/#class-not-fully-defined (consulted on 2025-06-10)
MODEL_REGISTRY.rebuild_all()


if __name__ == "__main__":  # pragma: no cover # Do not compute coverage on doctest
    import doctest

    doctest.testmod()
