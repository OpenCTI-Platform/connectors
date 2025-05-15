"""The module defines a base fetcher interface for fetching data asynchronously."""

from typing import Protocol


class BaseFetcher(Protocol):
    """Base fetcher interface for fetching data asynchronously."""

    async def fetch(self) -> None:
        """Fetch data asynchronously."""
        ...
