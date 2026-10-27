"""AbstractAdditionalStixProvider."""

from abc import ABC, abstractmethod
from collections.abc import Hashable, Iterable
from typing import Any, Generic, TypeVar

from connectors_sdk.models.base_author_entity import BaseAuthorEntity
from connectors_sdk.models.base_identified_object import BaseIdentifiedObject
from connectors_sdk.models.tlp_marking import TLPMarking

KeyT = TypeVar("KeyT", bound=Hashable)

PROVIDER_NAME_SUFFIX = "AdditionalStixProvider"


class AbstractAdditionalStixProvider(ABC, Generic[KeyT]):
    """Fetch additional data for ids from a source and return it as OpenCTI objects.

    A provider is named ``<Provider><Payload>AdditionalStixProvider``. It may call
    the network; converting the fetched data should be delegated to a pure
    converter. Subclasses implement ``_fetch`` only:

    - a list of objects: the source has data for the id;
    - ``None``: the source has nothing for the id;
    - ``DataRetrievalError`` raised: the source failed. It is never cached.

    The author and markings are referenced by the returned objects but never
    returned: the caller adds them once per bundle.

    With ``cache=True``, each id is fetched at most once, ``None`` results
    included, until ``clear_cache()`` is called. Call it at the start of each
    run when the provider instance lives across runs.

    Examples:
        >>> from connectors_sdk.models import OrganizationAuthor, Sector
        >>> class ExampleSectorAdditionalStixProvider(AbstractAdditionalStixProvider[str]):
        ...     def _fetch(self, id: str) -> list[BaseIdentifiedObject] | None:
        ...         if id != "energy":
        ...             return None
        ...         return [Sector(name="Energy", author=self.author, markings=self.markings)]
        >>> provider = ExampleSectorAdditionalStixProvider(
        ...     author=OrganizationAuthor(name="Example"), markings=[]
        ... )
        >>> provider.get("unknown") is None
        True
        >>> list(provider.get_many(["energy", "unknown"]))
        ['energy']

    """

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Reject a concrete provider whose name does not end with ``AdditionalStixProvider``.

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
        if not is_abstract and not cls.__name__.endswith(PROVIDER_NAME_SUFFIX):
            raise TypeError(
                f"Additional STIX provider class '{cls.__name__}' must be named "
                f"'<Provider><Payload>{PROVIDER_NAME_SUFFIX}'."
            )

    def __init__(
        self,
        author: BaseAuthorEntity,
        markings: list[TLPMarking],
        cache: bool = False,
    ) -> None:
        """Initialize the provider with the per-run context.

        Args:
            author: The author referenced by every returned object.
            markings: The markings referenced by every returned object.
            cache: Fetch each id at most once until ``clear_cache()`` is called.
        """
        self.author = author
        self.markings = markings
        self.cache = cache
        self._cache: dict[KeyT, list[BaseIdentifiedObject] | None] = {}

    def get(self, id: KeyT) -> list[BaseIdentifiedObject] | None:
        """Return the objects the source holds for one id.

        Args:
            id: The id to look up.

        Returns:
            The objects, or ``None`` when the source has nothing for the id.

        Raises:
            DataRetrievalError: If the source fails.
        """
        if self.cache and id in self._cache:
            return self._cache[id]
        result = self._fetch(id)
        if self.cache:
            self._cache[id] = result
        return result

    def get_many(self, ids: Iterable[KeyT]) -> dict[KeyT, list[BaseIdentifiedObject]]:
        """Return the objects the source holds for several ids, grouped by id.

        Each distinct id is fetched once; ids the source has nothing for are left out.

        Args:
            ids: The ids to look up.

        Returns:
            The objects of each id the source has data for.

        Raises:
            DataRetrievalError: If the source fails for any id.
        """
        results: dict[KeyT, list[BaseIdentifiedObject]] = {}
        for id in dict.fromkeys(ids):
            objects = self.get(id)
            if objects is not None:
                results[id] = objects
        return results

    def clear_cache(self) -> None:
        """Forget every cached result."""
        self._cache.clear()

    @abstractmethod
    def _fetch(self, id: KeyT) -> list[BaseIdentifiedObject] | None:
        """Fetch the data of one id from the source and convert it.

        Args:
            id: The id to look up.

        Returns:
            The objects, or ``None`` when the source has nothing for the id.

        Raises:
            DataRetrievalError: If the source fails.
        """
