"""Base request model for API engine."""

from abc import ABC

from pydantic import BaseModel


class BaseRequestModel(ABC, BaseModel):
    """Base request model for API engine."""

    pass
