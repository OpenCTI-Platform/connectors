"""Reference."""

from pydantic import BaseModel, Field


class Reference(BaseModel):
    """Reference was created to easily transform an ID into an object without having
    to regenerate the object and therefore potentially a new ID.
    It is used in fields such as object_ref, author, source etc.
    Warning: This model must not be sent to OCTI. It is not a Stix2 model.
    """

    id: str = Field(
        description="The id of the entity.",
    )
