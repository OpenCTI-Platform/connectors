"""BaseIdentifiedEntity."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING, Any

from connectors_sdk.models._model_registry import MODEL_REGISTRY
from connectors_sdk.models.base_entity import BaseEntity
from pydantic import (
    Field,
    PrivateAttr,
    computed_field,
    model_validator,
)

if TYPE_CHECKING:
    from connectors_sdk.models.octi._common import (
        Author,
        ExternalReference,
        TLPMarking,
    )


@MODEL_REGISTRY.register
class BaseIdentifiedEntity(BaseEntity):
    """Base class that can be identified thanks to a stix-like id."""

    _stix2_id: str | None = PrivateAttr(default=None)

    author: Author | None = Field(
        default=None,
        description="The Author reporting this Observable.",
    )

    markings: list[TLPMarking] | None = Field(
        default=None,
        description="References for object marking.",
    )

    external_references: list[ExternalReference] | None = Field(
        default=None,
        description="External references of the observable.",
    )

    def model_post_init(self, context__: Any) -> None:
        """Define the post initialization method, automatically called after __init__ in a pydantic model initialization.

        Notes:
            This allows a last modification of the pydantic Model before it is validated.

        Args:
            context__(Any): The pydantic context used by pydantic framework.

        References:
            https://docs.pydantic.dev/latest/api/base_model/#pydantic.BaseModel.model_parametrized_name [consulted on
                October 4th, 2024]

        """
        _ = context__  # Unused parameter, but required by pydantic
        if self._stix2_id is None:
            self._stix2_id = self.id

    @computed_field  # type: ignore[prop-decorator]
    # known issue : see https://docs.pydantic.dev/2.3/usage/computed_fields/ (consulted on 2025-06-06)
    @property
    def id(self) -> str:
        """Return the unique identifier of the entity."""
        stix_id: str = self.to_stix2_object().get("id", "")
        self._stix2_id = stix_id
        return stix_id

    @id.setter
    def id(self, value: str) -> None:
        """Prevent setting the id property."""
        raise AttributeError(
            f"The 'id' property is read-only and cannot be modified with {value}."
        )

    # https://github.com/pydantic/pydantic/discussions/10098
    @model_validator(mode="after")
    def _check_id(self) -> "BaseIdentifiedEntity":
        """Ensure the id is correctly set and alert if it has changed.

        Raises:
            ValueError: If the id is not set.
            UserWarning: If the id has changed since the last time it was set.

        Examples:
            >>> class Toto(BaseIdentifiedEntity):
            ...     # Example class that changes its id when value is changed.
            ...     titi: str
            ...     def to_stix2_object(self):
            ...         return stix2.v21.Identity(
            ...             id=f"identity--011fe1ae-7b92-4779-9eb5-7be2aeffb9e{self.titi}",
            ...             name="Test Identity",
            ...             identity_class="individual",
            ...         )
            >>> toto = Toto(titi="2")
            >>> toto.id
            'identity--011fe1ae-7b92-4779-9eb5-7be2aeffb9e2'
            >>> toto.titi = "1" # This will raise a warning
            >>> toto.id
            'identity--011fe1ae-7b92-4779-9eb5-7be2aeffb9e1'

        """
        if self._stix2_id is None or self._stix2_id == "":
            raise ValueError("The 'id' property must be set.")

        if self._stix2_id != self.id:
            # define message before the warning to avoid self._stix2_id has already changed in the main thread
            message = (
                f"The 'id' property has changed from to {self.id}. "
                "This may lead to unexpected behavior in the OpenCTI platform."
            )
            warnings.warn(
                message=message,
                category=UserWarning,
                stacklevel=2,
            )
        self._stix2_id = self.id  # Update the internal id to the current one
        return self
