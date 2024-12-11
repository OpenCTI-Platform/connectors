"""Provide utility functions for the Tenable Security Center integration."""

from abc import ABC, abstractmethod
from logging import Logger
from threading import Lock
from typing import Any, Optional

# pycti does not currently provide explicitely AppLogger Class (6.4.0)
# See : from pycti.utils.opencti_logger.logger
# we define it abstract here,
# the logger implementation will be passed in the code using pycti logger(...) result


class AppLogger(ABC):
    """Define the AppLogger abstract class."""

    @abstractmethod
    def __init__(self, name: str):
        """Initialize the logger."""
        self.local_logger: Logger

    @abstractmethod
    def debug(self, message: str, meta: Optional[dict[str, Any]] = None) -> None:
        """Log a debug message."""

    @abstractmethod
    def info(self, message: str, meta: Optional[dict[str, Any]] = None) -> None:
        """Log an info message."""

    @abstractmethod
    def warning(self, message: str, meta: Optional[dict[str, Any]] = None) -> None:
        """Log a warning message."""

    @abstractmethod
    def error(self, message: str, meta: Optional[dict[str, Any]] = None) -> None:
        """Log an error message."""


class IdsCache:
    """Cache that can be manually reset."""

    def __init__(self, max_size: int):
        """Initialize the cache."""
        self.max_size = max_size
        self.lock = Lock()
        self.items: list[str] = []
        self._set: set[str] = set()

    def _add(self, ids: list[str]) -> list[str]:
        """Add objects to the cache, returns new only."""
        new_ids = set(ids) - self._set
        if new_ids:
            self.items.extend(new_ids)
            self._set.update(new_ids)
        return list(new_ids)

    def _purge(self) -> None:
        """Purge the excess from cache."""
        size = len(self.items)
        if size > self.max_size:
            excess = size - self.max_size
            for _ in range(excess):
                removed_id = self.items.pop(0)
                self._set.remove(removed_id)

    def add(self, ids: list[str]) -> list[str]:
        """Add objects to the cache, return new ones only."""
        with self.lock:
            additions = self._add(ids)
            self._purge()
            return additions

    def reset(self) -> None:
        """Reset the cache."""
        with self.lock:
            self.items.clear()
            self._set.clear()
