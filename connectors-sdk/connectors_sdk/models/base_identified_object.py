"""BaseIdentifiedObject."""

from __future__ import annotations

import warnings
from abc import ABC
from typing import Any

from connectors_sdk.models.base_object import BaseObject
from pydantic import (
    PrivateAttr,
    computed_field,
    model_validator,
)


class BaseIdentifiedObject(BaseObject, ABC):
    """Base class that can be identified thanks to a stix-like id."""

    _stix2_id: str | None = PrivateAttr(default=None)

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

    # https://github.com/pydantic/pydantic/discussions/10098
    @model_validator(mode="after")
    def _check_id(self) -> BaseIdentifiedObject:
        """Ensure the id is correctly set and alert if it has changed.

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
