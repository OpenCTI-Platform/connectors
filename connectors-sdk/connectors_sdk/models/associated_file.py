"""AssociatedFile."""

import codecs
from typing import OrderedDict

import stix2.properties
from connectors_sdk.models.base_object import BaseObject
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import Field


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


class AssociatedFile(BaseObject):
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
    markings: list[TLPMarking] | None = Field(
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
                [marking.id for marking in self.markings] if self.markings else None
            ),
            version=self.version,
        )
