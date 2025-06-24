"""The module defines the base class for v."""

from enum import Enum
from typing import Optional, Type, TypeVar

T = TypeVar("T", bound="BaseOV")


class BaseOV(str, Enum):
    """Account Type OV Enum."""

    @classmethod
    def _missing_(cls: Type[T], value: object) -> Optional[T]:
        """Return any string, it's a way to make OpenVocab really open."""
        if isinstance(value, str):
            new_member = str.__new__(cls, value)
            new_member._name_ = value.upper().replace(" ", "_")
            new_member._value_ = value
            return new_member
        return None
