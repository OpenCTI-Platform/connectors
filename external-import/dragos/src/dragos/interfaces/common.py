"""Provide comon tools for Dragos interfaces."""

from pydantic import BaseModel, ConfigDict


class FrozenBaseModel(BaseModel):
    """Base class for frozen models. I.e Not alter-able after model_post_init."""

    model_config = ConfigDict(frozen=True)


class DataRetrievalError(Exception):
    """Error raised when data retrieval fails."""
