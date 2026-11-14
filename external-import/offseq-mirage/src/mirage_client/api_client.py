"""HTTP client for the public Mirage Feed STIX bundle (no authentication)."""

from typing import Any

from connectors_sdk import BaseClientApi

USER_AGENT = "opencti-offseq-mirage-connector/1.0 (+https://feeds.offseq.com)"


class MirageFeedClient(BaseClientApi):
    def __init__(self, feed_url: str) -> None:
        super().__init__(base_url=feed_url, timeout=120, max_retries=3)
        self._feed_url = feed_url

    @property
    def session_headers(self) -> dict[str, str]:
        return {"Accept": "application/json", "User-Agent": USER_AGENT}

    def get_bundle(self) -> dict[str, Any]:
        return self._get(self._feed_url)
