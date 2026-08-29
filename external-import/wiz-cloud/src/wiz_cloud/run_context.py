"""Run-scoped context shared between processors.

The issues processor records the cloud assets it imported; the
vulnerabilities processor reads them back to know what to scan. The context
lives for one run only and is never persisted, because the scope is "assets
seen this run", not an incremental window.
"""

from collections.abc import Iterator


class WizRunContext:
    """Asset ids referenced by the issues imported during the current run."""

    def __init__(self) -> None:
        self._asset_ids: set[str] = set()

    def add_asset(self, asset_id: str) -> None:
        """Record an asset seen while converting an issue.

        Args:
            asset_id: The entitySnapshot id of the cloud resource.
        """
        self._asset_ids.add(asset_id)

    @property
    def asset_ids(self) -> list[str]:
        """Return the asset ids, sorted so batching is deterministic.

        Returns:
            Sorted list of unique asset ids.
        """
        return sorted(self._asset_ids)

    def __bool__(self) -> bool:
        """Return whether any asset was recorded.

        Returns:
            True when at least one asset id is held.
        """
        return bool(self._asset_ids)


def batched(items: list[str], size: int) -> Iterator[list[str]]:
    """Split a list into chunks of at most ``size`` items.

    Args:
        items: Items to split.
        size: Maximum number of items per chunk.

    Yields:
        Lists of at most ``size`` items, in order.
    """
    for start in range(0, len(items), size):
        yield items[start : start + size]
