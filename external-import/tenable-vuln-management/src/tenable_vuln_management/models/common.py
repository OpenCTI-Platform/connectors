"""
Offer common tools for connector's model.
"""

from pydantic import BaseModel, ConfigDict


class FrozenBaseModelWithoutExtra(BaseModel):
    """
    Represent a Pydantic BaseModel where non explicitly define fields are forbidden.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    def __hash__(self):
        """Create a hash based on the model's json representation dynamically."""
        return hash(self.model_dump_json())

    def __eq__(self, other: "FrozenBaseModelWithoutExtra"):
        """Implement comparison between similar object."""
        if not isinstance(other, self.__class__):
            raise NotImplementedError("Cannot compare objects from different type.")
        # Compare the attributes by converting them to a dictionary
        return self.model_dump_json() == other.model_dump_json()
