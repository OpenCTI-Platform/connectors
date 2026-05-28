"""BaseIdentifiedObject."""

import warnings
from abc import ABC

import stix2
from connectors_sdk.models.base_object import BaseObject
from pydantic import (
    PrivateAttr,
    computed_field,
    model_validator,
)


class BaseIdentifiedObject(BaseObject, ABC):
    """Base class that can be identified thanks to a stix-like id."""

    _stix2_id: str | None = PrivateAttr(default=None)

    @computed_field  # type: ignore[prop-decorator]
    # Typing known issue : see https://docs.pydantic.dev/2.3/usage/computed_fields/ (consulted on 2025-06-06)
    @property
    def id(self) -> str:
        """Return the unique identifier of the entity.
        The value is computed from the STIX2 object representation of the entity, and then cached for future use.

        Notes:
            The decorator `@computed_field` is used to indicate that this property
            must be considered as a field by pydantic, and then included in the model **serialization** processes.
            This field is **not** validated by pydantic, neither during the model initialization, nor during the model update.
        """
        if self._stix2_id is None:
            stix_object: stix2.v21._STIXBase21 = self.to_stix2_object()
            stix_id = stix_object.get("id")

            # The 'id' property is required and must be a non-empty string for model validation
            if not (isinstance(stix_id, str) and stix_id.strip()):
                raise ValueError("The 'id' property can't be set.")

            self._stix2_id = stix_id

        return self._stix2_id

    # https://github.com/pydantic/pydantic/discussions/10098
    @model_validator(mode="after")
    def _compute_stix_id(self) -> "BaseIdentifiedObject":
        """Compute STIX ID on validation (instance creation or re-assignments).

        Raises:
            ValueError: If the id is not set.
            UserWarning: If the id has changed since the last time it was set.

        Examples:
            >>> class Toto(BaseIdentifiedObject):
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
        previous_stix2_id = self._stix2_id
        self._stix2_id = None  # Reset cached id
        current_stix2_id = self.id  # Compute and cache the new id

        if previous_stix2_id is None:
            # If the previous id was not set, just set it without warning
            return self

        if previous_stix2_id != current_stix2_id:
            # Warn on `_stix2_id` change after fields re-assignment
            warnings.warn(
                message=(
                    f"The 'id' property has changed from {previous_stix2_id} to {current_stix2_id}. "
                    "This may lead to unexpected behavior in the connector or the OpenCTI platform."
                ),
                category=UserWarning,
                stacklevel=2,
            )

        return self
