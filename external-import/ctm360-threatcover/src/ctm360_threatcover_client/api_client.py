"""
TAXII 2.x client for the CTM360 ThreatCover feed.

Modeled on the generic OpenCTI ``taxii2`` connector (``client_taxii.Taxii2``): it uses
TAXII server discovery with token / API-key / basic authentication and the same
``more`` / ``next`` pagination, scoped to a single configured collection.
"""

from __future__ import annotations

from typing import Optional

import taxii2client.v20 as tx20
import taxii2client.v21 as tx21
from requests.auth import AuthBase, HTTPBasicAuth
from taxii2client.common import TokenAuth
from taxii2client.exceptions import TAXIIServiceException


class Ctm360ThreatcoverAPIError(Exception):
    """Custom exception for CTM360 ThreatCover TAXII errors."""


class ApiKeyAuth(AuthBase):
    """Authenticate against a TAXII server with a custom API-key header."""

    def __init__(self, header: str, value: str) -> None:
        self.header = header
        self.value = value

    def __call__(self, request):
        request.headers[self.header] = f"{self.value}"
        return request


class Ctm360ThreatcoverClient:
    """Thin client around a CTM360 ThreatCover TAXII server/collection."""

    def __init__(
        self,
        helper,
        discovery_url: str,
        collection: str,
        *,
        v21: bool = True,
        use_token: bool = True,
        token: Optional[str] = None,
        use_apikey: bool = False,
        apikey_key: Optional[str] = None,
        apikey_value: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        cert_path: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> None:
        self.helper = helper
        self.collection_name = collection

        auth = self._build_auth(
            use_token=use_token,
            token=token,
            use_apikey=use_apikey,
            apikey_key=apikey_key,
            apikey_value=apikey_value,
            username=username,
            password=password,
        )
        server_cls = tx21.Server if v21 else tx20.Server
        self._server = server_cls(
            str(discovery_url),
            auth=auth,
            verify=verify_ssl,
            cert=cert_path or None,
        )
        self._collection = None

    @staticmethod
    def _build_auth(
        *,
        use_token,
        token,
        use_apikey,
        apikey_key,
        apikey_value,
        username,
        password,
    ):
        if use_token:
            if not token:
                raise Ctm360ThreatcoverAPIError(
                    "Token authentication selected but no token provided"
                )
            return TokenAuth(token)
        if use_apikey:
            if not apikey_key or not apikey_value:
                raise Ctm360ThreatcoverAPIError(
                    "API-key authentication selected but key/value missing"
                )
            return ApiKeyAuth(apikey_key, apikey_value)
        if not username or not password:
            raise Ctm360ThreatcoverAPIError(
                "No authentication configured (set a token, an API key, or basic credentials)"
            )
        return HTTPBasicAuth(username, password)

    def _resolve_collection(self):
        if self._collection is not None:
            return self._collection
        for root in self._server.api_roots:
            for collection in root.collections:
                if (
                    collection.id == self.collection_name
                    or collection.title == self.collection_name
                ):
                    self._collection = collection
                    return collection
        raise Ctm360ThreatcoverAPIError(
            f"Collection '{self.collection_name}' not found on the TAXII server"
        )

    def ping(self) -> None:
        """Verify the server is reachable and the collection exists."""
        try:
            self._resolve_collection()
        except TAXIIServiceException as err:
            raise Ctm360ThreatcoverAPIError(
                f"CTM360 ThreatCover TAXII server unreachable: {err}"
            ) from err

    def get_objects(self, added_after: Optional[str] = None) -> list:
        """
        Poll the configured collection and return all STIX objects.

        :param added_after: Only return objects added after this RFC3339 timestamp.
        """
        try:
            collection = self._resolve_collection()
        except TAXIIServiceException as err:
            raise Ctm360ThreatcoverAPIError(
                f"Failed to resolve CTM360 ThreatCover collection: {err}"
            ) from err

        filters: dict = {}
        if added_after:
            filters["added_after"] = added_after

        objects: list = []
        try:
            response = collection.get_objects(**filters)
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
                # more=True but no cursor: raise instead of silently returning a
                # partial page. Returning here would let the connector advance
                # added_after and permanently skip the remaining objects.
                raise Ctm360ThreatcoverAPIError(
                    "CTM360 ThreatCover TAXII page reported more=true without a next "
                    "cursor; aborting to avoid skipping data"
                )
            try:
                # When paging with `next`, the cursor already encodes the query.
                response = collection.get_objects(next=next_id)
            except TAXIIServiceException as err:
                raise Ctm360ThreatcoverAPIError(
                    f"Failed to page CTM360 ThreatCover collection: {err}"
                ) from err
        return objects
