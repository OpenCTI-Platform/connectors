"""BaseObject."""

from abc import ABC, abstractmethod
from typing import Any

import stix2.properties
from pydantic import BaseModel, ConfigDict


class BaseObject(BaseModel, ABC):
    """Represent Base Entity for OpenCTI models."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,  # ensure model is revalidate when setting properties
    )

    def __hash__(self) -> int:
        """Create a hash based on the model's json representation dynamically."""
        return hash(self.model_dump_json())

    def __eq__(self, other: Any) -> bool:
        """Implement comparison between similar object."""
        if not isinstance(other, self.__class__):
            raise NotImplementedError("Cannot compare objects from different type.")
        # Compare the attributes by converting them to a dictionary
        return self.model_dump_json() == other.model_dump_json()

    @property
    def properties_set(self) -> set[str]:
        """Return the set of explicitely set fields.
        Set properties must be included in the stix object output.
        """
        return self.model_fields_set

    @property
    def properties_unset(self) -> set[str]:
        """Return the set of unset properties.

        Unset properties must be excluded from the stix object output (no update, but no deletion either, contrary to an explicitely field set to None).
        """
        # lighter to make the diff rather than checking during set comprehension.
        return {str(k) for k in self.__pydantic_fields__.keys()} - self.properties_set

    @abstractmethod
    def to_stix2_object(self) -> stix2.v21._STIXBase21:
        """Make stix object (usually from stix2 python lib objects)."""
