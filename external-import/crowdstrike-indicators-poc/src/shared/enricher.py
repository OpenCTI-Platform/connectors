"""Enrichment contract shared by every connector source."""

from abc import ABC, abstractmethod

from pydantic import BaseModel


class AbstractEnricher[T: BaseModel](ABC):
    """Look up the validated item a source holds for a key, with a cache.

    Contract every implementation honours:

    * :meth:`extract` returns an instance of ``T``, already validated, or
      ``None`` when the source holds no item for the key. ``None`` never
      reports an error: errors are raised.
    * The result of every lookup that did not raise is cached under its key,
      ``None`` included. A cached key is answered without contacting the
      source.
    * A lookup that raises caches nothing: the next lookup of that key
      contacts the source again.
    * :meth:`reset_cache` empties the cache.

    Implementations only provide :meth:`_fetch`, the uncached lookup.
    """

    def __init__(self) -> None:
        self._cache: dict[str, T | None] = {}

    def extract(self, key: str) -> T | None:
        """Return the item for ``key``, from the cache when it holds one."""
        if key in self._cache:
            return self._cache[key]
        item = self._fetch(key)
        self._cache[key] = item
        return item

    def reset_cache(self) -> None:
        """Forget every cached result, found items and misses alike."""
        self._cache.clear()

    @abstractmethod
    def _fetch(self, key: str) -> T | None:
        """Look ``key`` up in the source, without the cache.

        :raises Exception: when the source fails; nothing is cached then.
        """
