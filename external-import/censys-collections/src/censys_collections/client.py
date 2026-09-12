from collections.abc import Generator

from censys_platform import (
    SDK,
    Collection,
    SearchQueryHit,
    SearchQueryInputBody,
)
from censys_platform.utils.retries import BackoffStrategy, RetryConfig

# Retry transient network errors (including read timeouts) and 429/5xx
# responses with exponential backoff before giving up on a request.
_RETRY_CONFIG = RetryConfig(
    strategy="backoff",
    backoff=BackoffStrategy(
        initial_interval=500,
        max_interval=10_000,
        exponent=1.5,
        max_elapsed_time=120_000,
    ),
    retry_connection_errors=True,
)


class Client:
    """Thin wrapper around the Censys SDK for collections ingestion."""

    def __init__(
        self,
        organisation_id: str,
        token: str,
        request_timeout_seconds: int = 60,
    ) -> None:
        self.organisation_id = organisation_id
        self.token = token
        self._timeout_ms = request_timeout_seconds * 1000

    def _new_sdk(self) -> SDK:
        return SDK(
            organization_id=self.organisation_id,
            personal_access_token=self.token,
            timeout_ms=self._timeout_ms,
            retry_config=_RETRY_CONFIG,
        )

    def list_collections(self) -> Generator[Collection, None, None]:
        """Yield every collection visible to the configured organisation."""
        with self._new_sdk() as sdk:
            page_token: str | None = None
            while True:
                response = sdk.collections.list(
                    organization_id=self.organisation_id,
                    page_token=page_token,
                )
                result = response.result.result
                if result is None:
                    break
                if isinstance(result.collections, list):
                    yield from result.collections
                next_page_token = result.next_page_token
                if not next_page_token:
                    break
                page_token = next_page_token

    def fetch_collection_hits(
        self, collection_id: str
    ) -> Generator[SearchQueryHit, None, None]:
        """Yield every asset hit in *collection_id*, paginating automatically."""
        with self._new_sdk() as sdk:
            page_token: str | None = None
            while True:
                body = SearchQueryInputBody(
                    query="",
                    page_token=page_token,
                )
                response = sdk.collections.search(
                    collection_uid=collection_id,
                    search_query_input_body=body,
                    organization_id=self.organisation_id,
                )
                result = response.result.result
                if result is None:
                    break
                if isinstance(result.hits, list):
                    yield from result.hits
                next_page_token = result.next_page_token
                if not next_page_token:
                    break
                page_token = next_page_token
