"""Define the interface for Dragos Product."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable, Literal

from dragos.interfaces.common import FrozenBaseModel
from pydantic import AwareDatetime, Field

if TYPE_CHECKING:
    import datetime


class Tag(ABC, FrozenBaseModel):
    """Interface for Dragos Tag."""

    # Not an enum, use cases should handle the values and logs accordingly
    type: str = Field(..., description="The Dragos Tag type.", min_length=1)
    value: str = Field(..., description="The Dragos Tag value.", min_length=1)

    def __init__(self) -> None:
        """Initialize the Tag."""
        FrozenBaseModel.__init__(self, type=self._type, value=self._value)

    @property
    @abstractmethod
    def _type(self) -> str:
        pass

    @property
    @abstractmethod
    def _value(self) -> str:
        pass


class Indicator(ABC, FrozenBaseModel):
    """Interface for Dragos Indicator."""

    value: str = Field(..., description="The Dragos Indicator value.", min_length=1)
    type: Literal[
        "ip",
        "domain",
        "sha1",
        "sha256",
        "url",  # indicator types are supposed to be known !
    ] = Field(
        ...,
        description="The Dragos Indicator type.",
    )
    first_seen: AwareDatetime = Field(
        ..., description="The Dragos Indicator first seen date."
    )
    last_seen: AwareDatetime = Field(
        ..., description="The Dragos Indicator last seen date."
    )
    # Unused : kill_chain, confidence, severity, attack_techniques, products

    def __init__(self) -> None:
        """Initialize the Indicator."""
        FrozenBaseModel.__init__(
            self,
            value=self._value,
            type=self._type,
            first_seen=self._first_seen,
            last_seen=self._last_seen,
        )

    @property
    @abstractmethod
    def _value(self) -> str:
        pass

    @property
    @abstractmethod
    def _type(self) -> str:
        pass

    @property
    @abstractmethod
    def _first_seen(self) -> "datetime.datetime":
        pass

    @property
    @abstractmethod
    def _last_seen(self) -> "datetime.datetime":
        pass


class Report(ABC, FrozenBaseModel):
    """Interface for Dragos Report."""

    serial: str = Field(..., description="The Dragos Report ID.", min_length=1)
    title: str = Field(..., description="The Dragos Report title.", min_length=1)
    created_at: AwareDatetime = Field(
        ..., description="The Dragos Report creation date."
    )
    updated_at: AwareDatetime = Field(
        ..., description="The Dragos Report last update date."
    )
    summary: str = Field(..., description="The Dragos Report executive_summary.")

    related_tags: Iterable[Tag] = Field(
        ..., description="The Dragos Report related tags."
    )
    related_indicators: Iterable[Indicator] = Field(
        ..., description="The Dragos Report related indicators."
    )

    def __init__(self) -> None:
        """Initialize the Report."""
        FrozenBaseModel.__init__(
            self,
            serial=self._serial,
            title=self._title,
            created_at=self._created_at,
            updated_at=self._updated_at,
            summary=self._summary,
            related_tags=self._related_tags,
            related_indicators=self._related_indicators,
        )

    @property
    @abstractmethod
    def _serial(self) -> str:
        pass

    @property
    @abstractmethod
    def _title(self) -> str:
        pass

    @property
    @abstractmethod
    def _created_at(self) -> "datetime.datetime":
        pass

    @property
    @abstractmethod
    def _updated_at(self) -> "datetime.datetime":
        pass

    @property
    @abstractmethod
    def _summary(self) -> str:
        pass

    @property
    @abstractmethod
    def _related_tags(self) -> Iterable[Tag]:
        pass

    @property
    @abstractmethod
    def _related_indicators(self) -> Iterable[Indicator]:
        pass


class Reports(ABC):
    """Interface for Dragos Reports Retrieval."""

    @abstractmethod
    def list(self, since: AwareDatetime) -> Iterable[Report]:
        """List all Dragos reports."""
        pass
