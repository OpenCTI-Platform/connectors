import asyncio
import logging
from typing import Any

from azure.identity.aio import ClientSecretCredential
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph import GraphServiceClient
from msgraph.generated.models.security.article import Article
from msgraph.generated.security.threat_intelligence.articles.articles_request_builder import (
    ArticlesRequestBuilder,
)

logger = logging.getLogger(__name__)


class ConnectorClient:

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> None:
        # Azure credential (aio flavour → must be closed)
        self._credentials = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        # Root Graph client
        self.client = GraphServiceClient(credentials=self._credentials)

    async def __aenter__(self) -> "ConnectorClient":
        """Opens Azure credential with async context manager."""
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        """Closes the underlying Azure credential when the ConnectorClient is used as an async context manager."""
        await self._credentials.close()

    async def _fetch_articles(self, page_size: int = 50) -> list[Article]:
        query_parameters = (
            ArticlesRequestBuilder.ArticlesRequestBuilderGetQueryParameters(
                top=page_size,
            )
        )

        page = await self.client.security.threat_intelligence.articles.get(
            request_configuration=RequestConfiguration(
                query_parameters=query_parameters
            )
        )
        articles = []
        while page:
            for article in page.value or []:
                articles.append(article)

            if not page.odata_next_link:
                break
            page = await self.client.security.threat_intelligence.with_url(
                raw_url=page.odata_next_link
            ).get()
        return articles

    def fetch_articles(self, page_size: int = 50) -> list[Article]:
        """
        This method wraps an asynchronous call to the Microsoft Graph API.

        Due to limitations in `asyncio.run()` when used in environments where an event loop
        may already be running (e.g., in web servers, background tasks, or notebooks),
        this implementation uses a safer event loop retrieval strategy. For more details, see:
        https://github.com/microsoftgraph/msgraph-sdk-python/issues/366
        """

        async def _run() -> list[Article]:
            async with self:  # Ensure the client is closed after use
                return await self._fetch_articles(page_size)

        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(_run())
        except RuntimeError as e:
            if "There is no current event loop in thread" in str(e):
                return asyncio.run(_run())
            raise
