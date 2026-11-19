# -*- coding: utf-8 -*-
"""OpenCTI Malpedia client module."""

from typing import Any

from connectors_sdk import ApiClientError, BaseClientApi


class MalpediaClient(BaseClientApi):
    """Malpedia API client.

    The client does not catch errors. HTTP errors raise the connectors-sdk
    client errors (`ApiForbiddenError`, `ApiNotFoundError`, ...). Network errors
    raise `requests.RequestException`. The connector decides what to do with them.

    Malpedia answers authentication errors with 403, not 401.
    """

    API_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    def __init__(self, api_key: str | None = None) -> None:
        """Initialize Malpedia API client."""
        self._api_key = api_key or None
        super().__init__(self.API_URL, timeout=30)

    @property
    def unauthenticated(self) -> bool:
        """Tell whether the client runs without an API key."""
        return self._api_key is None

    @property
    def session_headers(self) -> dict[str, str]:
        """Send the API key, if any, with every request."""
        if self._api_key is None:
            return {}
        return {"Authorization": f"apitoken {self._api_key}"}

    def check_api_key(self) -> None:
        """Check that Malpedia accepts the API key.

        Raises:
            ApiForbiddenError: Malpedia rejects the API key.
            ApiClientError: Malpedia sends an unexpected answer.
        """
        response = self._get("check/apikey")
        detail = response.get("detail", "") if isinstance(response, dict) else ""
        if "Valid token" not in detail:
            raise ApiClientError(
                "Unexpected answer from Malpedia to the API key check",
                status_code=200,
                response_body=response,
            )

    def get_version(self) -> int:
        """Get the current Malpedia version (commit number)."""
        return int(self._get("get/version")["version"])

    def get_families(self) -> dict[str, Any]:
        """Get the metadata of all families, by family ID."""
        return self._get("get/families")

    def get_yara_rules(self, family_id: str) -> dict[str, Any]:
        """Get the YARA rules of a family, grouped by TLP level."""
        return self._get(f"get/yara/{family_id}")

    def get_samples(self, family_id: str) -> list[dict[str, Any]]:
        """Get the samples of a family. Needs an API key."""
        return self._get(f"list/samples/{family_id}")

    def get_actor(self, actor_id: str) -> dict[str, Any]:
        """Get the metadata of an actor."""
        return self._get(f"get/actor/{actor_id}")
