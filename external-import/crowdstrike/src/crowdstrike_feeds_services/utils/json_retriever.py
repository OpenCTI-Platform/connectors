"""Retrieval of a JSON document from a fixed URL."""

from typing import Any

import requests

USER_AGENT = "opencti-crowdstrike-connector"


class JsonRetrievalError(Exception):
    """Raised when a JSON document cannot be retrieved."""


class JsonRetriever:
    """Retrieve a JSON document from a fixed URL.

    The retrieval succeeds only when the server answers HTTP 200 with a valid JSON payload.
    What the document contains is left to the caller.
    """

    def __init__(self, url: str, timeout_seconds: int = 30):
        self.url = url
        self.timeout_seconds = timeout_seconds

    def retrieve(self) -> Any:
        """Return the decoded JSON document.

        Raises:
            JsonRetrievalError: the request failed, the status is not 200, or the payload is not valid JSON.
        """
        try:
            response = requests.get(
                self.url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as e:
            raise JsonRetrievalError(f"Request to {self.url} failed: {e}") from e

        if response.status_code != 200:
            raise JsonRetrievalError(
                f"Request to {self.url} answered HTTP {response.status_code}"
            )

        try:
            return response.json()
        except ValueError as e:
            raise JsonRetrievalError(
                f"Response from {self.url} is not valid JSON: {e}"
            ) from e
