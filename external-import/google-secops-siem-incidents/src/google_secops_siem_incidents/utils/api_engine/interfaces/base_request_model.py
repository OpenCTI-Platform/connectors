"""Base request model interface."""

from abc import ABC

from pydantic import BaseModel


class BaseRequestModel(ABC, BaseModel):
    """Abstract pydantic request model."""
