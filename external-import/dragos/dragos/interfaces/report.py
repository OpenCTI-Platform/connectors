"""Define the interface for Dragos Product."""

from abc import ABC, abstractmethod
from typing import Annotated, Generator, Literal, Optional

from dragos.interfaces.common import DataRetrievalError, FrozenBaseModel
from pydantic import (
    AfterValidator,
    AwareDatetime,
    Field,
    ValidationError,
    ValidationInfo,
)


class ReportRetrievalError(DataRetrievalError):
    """Error raised when data retrieval fails."""


def _validate_pdf_bytes(value: bytes, info: ValidationInfo) -> bytes:
    """Raise a ValueError if byte array is not a PDF.

    References:
        * ISO 32000-1

    """
    if value[:4] != b"%PDF":
        raise ValueError("Invalid PDF file")
    return value


PDFBytes = Annotated[bytes, AfterValidator(_validate_pdf_bytes)]


class Tag(FrozenBaseModel):
    """Interface for Dragos Tag."""

    # Not an enum, use cases should handle the values and logs accordingly
    type: str = Field(..., description="The Dragos Tag type.", min_length=1)
    value: str = Field(..., description="The Dragos Tag value.", min_length=1)

    def __init__(self) -> None:
        """Initialize the Tag."""
        try:
            FrozenBaseModel.__init__(self, type=self._type, value=self._value)
        except ValidationError as e:
            raise ReportRetrievalError("Failed to retrieve Tag") from e

    @property
    @abstractmethod
    def _type(self) -> str:
        pass

    @property
    @abstractmethod
    def _value(self) -> str:
        pass


class Indicator(FrozenBaseModel):
    """Interface for Dragos Indicator."""

    value: str = Field(..., description="The Dragos Indicator value.", min_length=1)
    type: Literal[
        "md5",
        "sha1",
        "sha256",
        "ip",
        "domain",
        "artifact",
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
        try:
            FrozenBaseModel.__init__(
                self,
                value=self._value,
                type=self._type,
                first_seen=self._first_seen,
                last_seen=self._last_seen,
            )
        except ValidationError as e:
            raise ReportRetrievalError("Failed to retrieve Indicator") from e

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
    def _first_seen(self) -> str:
        pass

    @property
    @abstractmethod
    def _last_seen(self) -> str:
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

    pdf: Optional[PDFBytes] = Field(
        None, description="The Dragos Report PDF file.", min_length=1
    )

    related_tags: Generator[Tag, None, None] = Field(
        ..., description="The Dragos Report related tags."
    )
    related_indicators: Generator[Indicator, None, None] = Field(
        ..., description="The Dragos Report related indicators."
    )

    def __init__(self) -> None:
        """Initialize the Report."""
        try:
            FrozenBaseModel.__init__(
                self,
                serial=self._serial,
                title=self._title,
                created_at=self._created_at,
                updated_at=self._updated_at,
                summary=self._summary,
                related_tags=self._related_tags,
                related_indicators=self._related_indicators,
                pdf=self._pdf,
            )
        except ValidationError as e:
            raise ReportRetrievalError("Failed to retrieve Report") from e

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
    def _created_at(self) -> str:
        pass

    @property
    @abstractmethod
    def _updated_at(self) -> str:
        pass

    @property
    @abstractmethod
    def _summary(self) -> str:
        pass

    @property
    @abstractmethod
    def _pdf(self) -> Optional[bytes]:
        pass

    @property
    @abstractmethod
    def _related_tags(self) -> Generator[Tag, None, None]:
        pass

    @property
    @abstractmethod
    def _related_indicators(self) -> Generator[Indicator, None, None]:
        pass


class Reports(ABC):
    """Interface for Dragos Reports Retrieval."""

    @abstractmethod
    def iter(self, since: AwareDatetime) -> Generator[Report, None, None]:
        """List all Dragos reports."""
