"""AbstractConverter."""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.tlp_marking import TLPMarking
from pydantic import BaseModel

InputT = TypeVar("InputT", bound=BaseModel)

CONVERTER_NAME_SUFFIX = "Converter"


class AbstractConverter(ABC, Generic[InputT]):
    """Convert one provider payload into OpenCTI objects.

    A converter is named ``<Provider><Payload>Converter`` and declares the
    Pydantic model it accepts as its type parameter. It has no side effects:
    no network call, no state, nothing sent to OpenCTI.

    Values that are constant for a run (author, markings, provider settings)
    are given to the constructor. Values that change per item belong to the
    input model.

    The author and the marking objects are referenced by the produced objects
    but never returned by ``transform``: the caller adds them once per bundle.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor, Sector
        >>> class SectorPayload(BaseModel):
        ...     name: str
        >>> class ExampleSectorConverter(AbstractConverter[SectorPayload]):
        ...     def transform(self, input: SectorPayload) -> list[BaseIdentifiedObject]:
        ...         return [Sector(name=input.name, author=self.author, markings=self.markings)]
        >>> converter = ExampleSectorConverter(
        ...     author=OrganizationAuthor(name="Example"),
        ...     markings=[TLPMarking(level="green")],
        ... )
        >>> [obj.name for obj in converter.transform(SectorPayload(name="Energy"))]
        ['Energy']

    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Reject a concrete converter whose name does not end with ``Converter``.

        Raises:
            TypeError: If a concrete subclass is wrongly named.
        """
        super().__init_subclass__(**kwargs)
        # ABCMeta computes `__abstractmethods__` after `__init_subclass__` runs,
        # so abstractness has to be computed here.
        is_abstract = any(
            getattr(getattr(cls, name, None), "__isabstractmethod__", False)
            for name in dir(cls)
        )
        if not is_abstract and not cls.__name__.endswith(CONVERTER_NAME_SUFFIX):
            raise TypeError(
                f"Converter class '{cls.__name__}' must be named "
                f"'<Provider><Payload>{CONVERTER_NAME_SUFFIX}'."
            )

    def __init__(self, author: BaseAuthorEntity, markings: list[TLPMarking]) -> None:
        """Initialize the converter with the per-run context.

        Args:
            author: The author referenced by every produced object.
            markings: The markings referenced by every produced object.
        """
        self.author = author
        self.markings = markings

    @abstractmethod
    def transform(self, input: InputT) -> list[BaseIdentifiedObject]:
        """Convert one provider payload into OpenCTI objects.

        Args:
            input: The validated provider payload.

        Returns:
            The produced objects, without the author and marking objects.
            An empty list when nothing maps to an OpenCTI object.

        Raises:
            ConversionError: If the input cannot be converted.
        """
