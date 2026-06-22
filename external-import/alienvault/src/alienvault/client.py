"""OpenCTI AlienVault client module."""

from __future__ import annotations

from datetime import datetime
from typing import Iterator, List, Optional

from alienvault.models import Pulse
from OTXv2 import OTXv2
from pydantic.v1 import HttpUrl, parse_obj_as

__all__ = [
    "AlienVaultClient",
]


class AlienVaultClient:
    """AlienVault client."""

    def __init__(self, base_url: HttpUrl, api_key: str) -> None:
        """
        Initializer.
        :param base_url: Base API url.
        :param api_key: API key.
        """
        server = str(base_url).strip("/")

        self.otx = OTXv2(api_key, server=server)

    def get_pulses_subscribed(
        self,
        modified_since: datetime,
        limit: int = 20,
    ) -> List[Pulse]:
        """
        Get any subscribed pulses.
        :param modified_since: Filter by results modified since this date.
        :param limit: Return limit.
        :return: A list of pulses.
        """
        pulse_data = self.otx.getsince(timestamp=modified_since, limit=limit)
        pulses = parse_obj_as(List[Pulse], pulse_data)

        return pulses

    def count_pulses_subscribed(
        self,
        modified_since: datetime,
    ) -> Optional[int]:
        """
        Best-effort total number of subscribed pulses modified since a date.

        The OTX subscribed-pulses endpoint is paginated and its response carries
        a top-level ``count`` (total matching results). Reading it with a single
        ``limit=1`` request lets the caller show a real ``X/total`` progress bar
        before the full feed has been downloaded. Returns ``None`` if the SDK or
        endpoint shape differs, so a count probe can never fail the run.
        :param modified_since: Filter by results modified since this date.
        :return: Total pulse count, or ``None`` if it could not be determined.
        """
        try:
            url = self.otx.create_url(
                "/api/v1/pulses/subscribed",
                limit=1,
                modified_since=modified_since.isoformat(),
            )
            page = self.otx.get(url)
        except Exception:  # noqa: BLE001 - never break ingestion over a count probe
            return None

        if isinstance(page, dict) and isinstance(page.get("count"), int):
            return page["count"]
        return None

    def iter_pulses_subscribed(
        self,
        modified_since: datetime,
        limit: int = 20,
    ) -> Iterator[Pulse]:
        """
        Stream subscribed pulses one at a time as the OTX feed is paginated.

        Unlike :meth:`get_pulses_subscribed`, which blocks until the whole feed
        has been downloaded, this yields each pulse as soon as its page is
        fetched — letting the caller report progress during a long backfill.
        :param modified_since: Filter by results modified since this date.
        :param limit: Page size.
        :return: An iterator of pulses.
        """
        # `getsince_iter` is a generator over the paginated feed. Fall back to
        # the blocking call on SDK versions that lack it.
        iterator = getattr(self.otx, "getsince_iter", None)
        if iterator is None:
            for pulse_data in self.otx.getsince(
                timestamp=modified_since, limit=limit
            ):
                yield parse_obj_as(Pulse, pulse_data)
            return

        for pulse_data in iterator(timestamp=modified_since, limit=limit):
            yield parse_obj_as(Pulse, pulse_data)
