"""BaseIdentifiedEntity."""

from __future__ import annotations

from abc import ABC
from typing import Any, Literal

from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.reference import Reference
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import AwareDatetime, Field


class BaseIdentifiedEntity(BaseIdentifiedObject, ABC):
    """Base class that can be identified thanks to a stix-like id."""

    author: BaseAuthorEntity | Reference | None = Field(
        default=None,
        description="The Author reporting this Observable.",
    )
    markings: list[TLPMarking | Reference] | None = Field(
        default=None,
        description="References for object marking.",
    )
    external_references: list[ExternalReference] | None = Field(
        default=None,
        description="External references of the observable.",
    )
    labels: list[str] | None = Field(
        default=None,
        description="Labels of the entity.",
    )
    created: AwareDatetime | None = Field(
        default=None,
        description="The time at which the object was originally created (STIX standard property).",
    )

    def _common_stix2_properties(self) -> dict[str, Any]:
        """Return the common STIX2 properties set."""
        return dict(  # noqa: C408 # No literal dict for maintainability
            created_by_ref=(self.author.id if self.author else None),
            object_marking_refs=(
                [marking.id for marking in self.markings]
                if self.markings is not None
                else None
            ),
            external_references=(
                [
                    external_ref.to_stix2_object()
                    for external_ref in self.external_references
                ]
                if self.external_references is not None
                else None
            ),
            labels=self.labels,
            created=self.created,
        )

    def _custom_stix2_properties(
        self,
        extension_id: str,
        extension_type: Literal["property-extension", "new-sco"] = "property-extension",
        **attributes: Any,
    ) -> dict[str, Any]:
        """Return OpenCTI attributes as the platform exports them.

        In a playbook, the platform merges the object sent by a connector with the
        previous step's object, which uses the export layout. pycti reads some
        attributes (like labels) from only one place, so the object must use the
        same layout, or the new values are lost. The x_opencti_* properties are
        the older format, kept for a deprecation period.

        Args:
            extension_id: The OpenCTI extension that holds the attributes
                (`STIX_EXT_OCTI`, or `STIX_EXT_OCTI_SCO` for observables).
            extension_type: How the object uses the extension (STIX 2.1):
                "property-extension" puts the attributes inside the extension.
                "new-sco" is for an observable type that the extension defines:
                the attributes are top-level properties, and the extension only
                gives its type.
            **attributes: The OpenCTI attributes, named as in the extension.

        Returns:
            The extension and the attributes, and the same attributes as
            deprecated x_opencti_* top-level properties.

        """
        attributes = self._without_empty_values(attributes)
        if extension_type == "property-extension":
            # The extension holds the properties.
            properties = {
                "extensions": {
                    extension_id: {"extension_type": extension_type, **attributes}
                }
            }
        else:
            # A new type: its properties are top-level properties,
            # and the extension only defines the type ("new-sco", "new-sdo" or "new-sro").
            properties = {
                "extensions": {
                    extension_id: {"extension_type": extension_type},
                },
                **attributes,
            }
        return {
            **properties,
            # Deprecated: the same attributes as x_opencti_* top-level properties,
            # kept for a deprecation period.
            **{f"x_opencti_{key}": value for key, value in attributes.items()},
        }

    @staticmethod
    def _merge_stix2_properties(*properties: dict[str, Any]) -> dict[str, Any]:
        """Merge STIX2 properties, and merge their extensions instead of replacing them."""
        merged: dict[str, Any] = {}
        extensions: dict[str, dict[str, Any]] = {}
        for stix2_properties in properties:
            for key, value in stix2_properties.items():
                if key == "extensions":
                    for extension_id, extension in value.items():
                        extensions[extension_id] = {
                            **extensions.get(extension_id, {}),
                            **extension,
                        }
                else:
                    merged[key] = value
        if extensions:
            merged["extensions"] = extensions
        return merged

    @staticmethod
    def _without_empty_values(properties: dict[str, Any]) -> dict[str, Any]:
        """Drop the None and [] values.

        stix2 keeps None and [] inside an extension, and in a playbook merge,
        a None would erase the value of the previous step.
        """
        return {
            key: value
            for key, value in properties.items()
            if value is not None and value != []
        }
