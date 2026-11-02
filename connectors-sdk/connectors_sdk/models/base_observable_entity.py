"""Offer observations OpenCTI entities."""

from abc import ABC, abstractmethod
from typing import Any

from connectors_sdk.models.associated_file import AssociatedFile
from connectors_sdk.models.base_identified_entity import BaseIdentifiedEntity
from connectors_sdk.models.enums import ExtensionDefinitionId, ExtensionType
from pydantic import Field
from stix2.v21 import _Observable as _Stix2Observable


class BaseObservableEntity(BaseIdentifiedEntity, ABC):
    """Base class for OpenCTI Observables.

    This class must be subclassed to create specific observable types.
    """

    score: int | None = Field(
        default=None,
        description="Score of the observable.",
        ge=0,
        le=100,
    )
    description: str | None = Field(
        default=None,
        description="Description of the observable.",
    )

    associated_files: list[AssociatedFile] | None = Field(
        default=None,
        description="Associated files for the observable.",
    )
    create_indicator: bool | None = Field(
        default=None,
        description="If True, an indicator and a `based-on` relationship will be created for this observable. (Delegated to OpenCTI Platform).",
    )

    def _common_stix2_properties(self) -> dict[str, Any]:
        """Factorize custom params."""
        custom_properties = {
            "labels": self.labels,
            "description": self.description,
            "score": self.score,
            "created_by_ref": self.author.id if self.author else None,
            "external_references": [
                external_ref.to_stix2_object()
                for external_ref in self.external_references or []
            ],
        }

        return self._merge_stix2_properties(
            dict(  # noqa: C408 # No literal dict for maintainability
                allow_custom=True,
                object_marking_refs=(
                    [marking.id for marking in self.markings]
                    if self.markings is not None
                    else None
                ),
                # Not duplicated in the extension: pycti reads files from both places
                # and joins them, so each file would be uploaded twice.
                x_opencti_files=[
                    file.to_stix2_object() for file in self.associated_files or []
                ],
                # Top level only: pycti reads it only from the top level, never from the extension.
                x_opencti_create_indicator=self.create_indicator,
            ),
            self._custom_stix2_extensions(
                ExtensionDefinitionId.OCTI_SCO,
                extension_type=ExtensionType.PROPERTY_EXTENSION,
                properties=custom_properties,
            ),
            self._deprecated_x_opencti_properties(custom_properties),
        )

    @abstractmethod
    def to_stix2_object(self) -> _Stix2Observable:
        """Make stix object.

        Notes:
        - Observables do not need deterministic stix id generation. STIX python lib handles it.

        """
