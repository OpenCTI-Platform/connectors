"""Offer the base class for the observable types that OpenCTI adds to STIX."""

from abc import ABC
from typing import Any

from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from pycti import STIX_EXT_OCTI_SCO


class BaseCustomObservableEntity(BaseObservableEntity, ABC):
    """Base class for OpenCTI custom observables (Hostname, Text...).

    STIX does not define these types: OpenCTI adds them, as "new-sco" types.
    For a new-sco type, the extension only declares the new type, and the
    attributes are top-level properties. stix2 builds custom observables the
    same way when they have an `extension_name`, and the platform exports them
    the same way.

    This class must be subclassed to create specific custom observable types.
    """

    def _common_stix2_properties(self) -> dict[str, Any]:
        """Factorize custom params, with the OpenCTI attributes at the top level."""
        return {
            **super()._common_stix2_properties(),
            # Replaces the parent's "property-extension" with the "new-sco" layout.
            **self._custom_stix2_properties(
                STIX_EXT_OCTI_SCO,
                "new-sco",
                labels=self.labels,
                description=self.description,
                score=self.score,
                created_by_ref=self.author.id if self.author else None,
                external_references=[
                    external_ref.to_stix2_object()
                    for external_ref in self.external_references or []
                ],
            ),
        }
