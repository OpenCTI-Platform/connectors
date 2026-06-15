"""TAXII 2.1 client for the CTM360 ThreatCover feed."""

from __future__ import annotations

from typing import Optional

from taxii2client.common import TokenAuth
from taxii2client.exceptions import TAXIIServiceException
from taxii2client.v21 import Collection


class Ctm360ThreatcoverAPIError(Exception):
    """Custom exception for CTM360 ThreatCover TAXII errors."""


class Ctm360ThreatcoverClient:
    """Thin client around a CTM360 ThreatCover TAXII 2.1 collection."""

    def __init__(
        self,
        helper,
        api_root_url: str,
        api_token: str,
        collection_id: str,
        verify_ssl: bool = True,
    ) -> None:
        """
        Initialize the CTM360 ThreatCover TAXII client.

        :param helper: The OpenCTI connector helper (used for logging).
        :param api_root_url: The TAXII 2.1 API root URL.
        :param api_token: The CTM360 ThreatCover API token (TAXII Authorization).
        :param collection_id: The id of the collection to poll.
        :param verify_ssl: Whether to verify the TLS certificate.
        """
        self.helper = helper
        root = str(api_root_url).rstrip("/")
        self.collection_url = f"{root}/collections/{collection_id}/"
        self.collection = Collection(
            self.collection_url,
            auth=TokenAuth(api_token),
            verify=verify_ssl,
        )

    def ping(self) -> str:
        """Verify the collection is reachable by loading its metadata."""
        try:
            return self.collection.title
        except TAXIIServiceException as err:
            raise Ctm360ThreatcoverAPIError(
                f"CTM360 ThreatCover TAXII collection unreachable: {err}"
            ) from err

    def get_objects(self, added_after: Optional[str] = None) -> list:
        """
        Poll the collection and return all STIX objects (handling pagination).

        :param added_after: Only return objects added after this RFC3339 timestamp.
        """
        objects: list = []
        filters: dict = {}
        if added_after:
            filters["added_after"] = added_after

        try:
            response = self.collection.get_objects(**filters)
        except TAXIIServiceException as err:
            raise Ctm360ThreatcoverAPIError(
                f"Failed to poll CTM360 ThreatCover collection: {err}"
            ) from err

        while response:
            objects.extend(response.get("objects", []) or [])
            if not response.get("more"):
                break
            next_id = response.get("next")
            if not next_id:
                break
            try:
                # When paging with `next`, the cursor already encodes the query,
                # so `added_after` must not be sent again.
                response = self.collection.get_objects(next=next_id)
            except TAXIIServiceException as err:
                raise Ctm360ThreatcoverAPIError(
                    f"Failed to page CTM360 ThreatCover collection: {err}"
                ) from err
        return objects
