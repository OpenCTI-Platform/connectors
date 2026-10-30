"""BaseIdentifiedEntity."""

from __future__ import annotations

from abc import ABC
from typing import Any, Literal, overload

from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.enums import ExtensionDefinitionId, ExtensionType
from connectors_sdk.models.external_reference import ExternalReference
from connectors_sdk.models.reference import Reference
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import AwareDatetime, Field

# The x_opencti_* properties that have no extension counterpart (top level only).
_X_OPENCTI_TOP_LEVEL_ONLY_PROPERTIES = {
    "x_opencti_files",
    "x_opencti_create_indicator",
    "x_opencti_create_observables",
}
# The OpenCTI extension properties whose x_opencti_* copy has another name
_X_OPENCTI_RENAMED_PROPERTIES = {
    "cvss_vector": "x_opencti_cvss_vector_string",
    "cvss_v2_vector": "x_opencti_cvss_v2_vector_string",
    "cvss_v4_vector": "x_opencti_cvss_v4_vector_string",
}


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

    @overload
    def _custom_stix2_extensions(
        self,
        extension_id: ExtensionDefinitionId,
        extension_type: Literal[ExtensionType.PROPERTY_EXTENSION],
        properties: dict[str, Any],
    ) -> dict[str, Any]: ...

    @overload
    def _custom_stix2_extensions(
        self,
        extension_id: ExtensionDefinitionId,
        extension_type: Literal[
            ExtensionType.TOPLEVEL_PROPERTY_EXTENSION,
            ExtensionType.NEW_SDO,
            ExtensionType.NEW_SCO,
            ExtensionType.NEW_SRO,
        ],
    ) -> dict[str, Any]: ...

    def _custom_stix2_extensions(
        self,
        extension_id: ExtensionDefinitionId,
        extension_type: ExtensionType,
        properties: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return OpenCTI properties in an extension, as the platform exports them.

        In a playbook, the platform merges the object sent by a connector with the
        previous step's object, which uses the export layout. pycti reads some
        properties (like labels) from only one place, so the object must use the
        same layout, or the new values are lost.

        Args:
            extension_id: The extension that holds the properties
                (`OCTI`, or `OCTI_SCO` for observables).
            extension_type: How the object uses the extension. Only a
                "property-extension" holds properties. For the other types, the
                properties are at the top level of the object.
            properties: The OpenCTI properties, named as in the extension.
                Required for a "property-extension", refused for the other types.

        Returns:
            The STIX "extensions" property, as a dict to unpack or merge.

        Raises:
            ValueError: If `properties` is missing for a "property-extension",
                or given for another extension type.

        """
        if extension_type == ExtensionType.PROPERTY_EXTENSION:
            if properties is None:
                raise ValueError("A property-extension needs properties.")
            # Remove empty values as they're not removed by pycti nor
            # stix2 libs unlike top level properties
            properties = {
                key: value
                for key, value in properties.items()
                if value is not None and value != []
            }
            return {
                "extensions": {
                    extension_id: {
                        "extension_type": extension_type,
                        **properties,
                    }
                }
            }
        else:
            if properties is not None:
                raise ValueError(
                    f"A {extension_type} extension holds no properties: "
                    "they are top level properties."
                )
            return {"extensions": {extension_id: {"extension_type": extension_type}}}

    def _deprecated_x_opencti_properties(
        self, properties: dict[str, Any]
    ) -> dict[str, Any]:
        """Return OpenCTI properties as x_opencti_* top-level properties.

        This is the older format, kept for a deprecation period. This method must
        take exactly the same dict as `_custom_stix2_extensions` as argument.
        """
        return {f"x_opencti_{key}": value for key, value in properties.items()}

    @staticmethod
    def _merge_stix2_properties(*properties: dict[str, Any]) -> dict[str, Any]:
        """Merge STIX2 properties, so that "extensions" is given only once.

        The entries of the same extension are merged. A property given twice
        must have the same value: different values are a bug in the model.

        Raises:
            ValueError: If a property (at the top level or in an extension) is
                given twice with different values.

        """
        merged_properties: dict[str, Any] = {}
        merged_extensions: dict[str, dict[str, Any]] = {}

        for properties_dict in properties:
            for property_name, property_value in properties_dict.items():
                if property_name == "extensions":
                    for extension_id, extension_dict in property_value.items():
                        merged_extension = merged_extensions.setdefault(
                            extension_id, {}
                        )
                        for extension_key, extension_value in extension_dict.items():
                            if (
                                extension_key in merged_extension
                                and merged_extension[extension_key] != extension_value
                            ):
                                raise ValueError(
                                    f"Extension property '{extension_key}' of '{extension_id}' "
                                    "is given twice with different values."
                                )
                            merged_extension[extension_key] = extension_value
                elif (
                    property_name in merged_properties
                    and merged_properties[property_name] != property_value
                ):
                    raise ValueError(
                        f"STIX2 property '{property_name}' is given twice with different values."
                    )
                else:
                    merged_properties[property_name] = property_value

        if merged_extensions:
            merged_properties["extensions"] = merged_extensions

        BaseIdentifiedEntity._check_deprecated_x_opencti_properties(merged_properties)

        return merged_properties

    @staticmethod
    def _check_deprecated_x_opencti_properties(properties: dict[str, Any]) -> None:
        """Check that each OpenCTI property has the same value in both of its places.

        During the deprecation period, each OpenCTI property is written twice: in an
        OpenCTI extension, and as an x_opencti_* top-level property. This check
        protects against forgetting one of the two, or giving them different values.

        It checks the properties as the models build them, with the OpenCTI
        properties in a "property-extension". A custom observable moves them to the
        top level only after this check.

        Args:
            properties: The STIX2 properties of an object.

        Raises:
            ValueError: If a property of an OpenCTI extension and its x_opencti_*
                copy differ, or if an x_opencti_* property is not in an OpenCTI
                extension.

        """
        checked_x_opencti_names = set()

        # 1. Each property of an OpenCTI extension has its x_opencti_* copy,
        # with the same value.
        opencti_extension_properties = {
            name: value
            for extension_id, extension in (properties.get("extensions") or {}).items()
            if extension_id in list(ExtensionDefinitionId)
            for name, value in extension.items()
            if name != "extension_type"
        }
        for extension_name, extension_value in opencti_extension_properties.items():
            x_opencti_name = (
                _X_OPENCTI_RENAMED_PROPERTIES.get(extension_name)
                or f"x_opencti_{extension_name}"
            )
            x_opencti_value = properties.get(x_opencti_name)
            if x_opencti_value != extension_value:
                raise ValueError(
                    f"'{extension_name}' is `{extension_value}` in the OpenCTI extension, "
                    f"but '{x_opencti_name}' is `{x_opencti_value}`. "
                    "Both must have the same value."
                )
            checked_x_opencti_names.add(x_opencti_name)

        # 2. Each x_opencti_* property is also in an OpenCTI extension
        # (step 1 checked the ones found there, the others are missing).
        for property_name, property_value in properties.items():
            if not property_name.startswith("x_opencti_"):
                continue
            if property_name in _X_OPENCTI_TOP_LEVEL_ONLY_PROPERTIES:
                continue
            if property_name in checked_x_opencti_names:
                continue
            if property_value is None or property_value == []:
                # Dropped from the extension, and by stix2 at the top level.
                continue
            raise ValueError(
                f"'{property_name}' is `{property_value}`, but it is not in an "
                "OpenCTI extension."
            )
