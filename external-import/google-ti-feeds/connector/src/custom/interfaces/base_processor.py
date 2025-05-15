"""The module defines a base processor interface for processing tasks asynchronously."""

from typing import Protocol


class BaseProcessor(Protocol):
    """Base interface for processors."""

    async def process(self) -> None:
        """Process the task asynchronously."""
        ...
