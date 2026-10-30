"""Offer the base class for the observable types that OpenCTI adds to STIX."""

from abc import ABC
from typing import Any

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import ExtensionDefinitionId, ExtensionType


class BaseCustomObservableEntity(BaseObservableEntity, ABC):
    """Base class for OpenCTI custom observables (Hostname, Text...).

    STIX does not define these types: OpenCTI adds them, as "new-sco" types.
    For a new-sco type, the extension only declares the new type, and the
    OpenCTI properties are at the top level. stix2 builds custom observables the
    same way when they have an `extension_name`, and the platform exports them
    the same way.

    This class must be subclassed to create specific custom observable types.
    """

    def _common_stix2_properties(self) -> dict[str, Any]:
        """Factorize custom params, with the OpenCTI properties at the top level."""
        properties = super()._common_stix2_properties()

        # A custom observable is a new SCO: its properties are all at the top level,
        # and its extension only defines the type ("new-sco").
        # So move the properties from the extension to the top level.
        top_level_properties = properties.pop("extensions")[
            ExtensionDefinitionId.OCTI_SCO
        ]
        del top_level_properties["extension_type"]

        return {
            **properties,
            **top_level_properties,
            **self._custom_stix2_extensions(
                ExtensionDefinitionId.OCTI_SCO, extension_type=ExtensionType.NEW_SCO
            ),
        }
