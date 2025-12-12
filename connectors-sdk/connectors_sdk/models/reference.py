"""Reference."""

from pydantic import BaseModel, Field


class Reference(BaseModel):
    """Represent a reference."""

    id: str = Field(
        description="The id of the entity.",
    )
