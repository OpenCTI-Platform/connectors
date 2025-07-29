"""connector_client.py – DRY Graph Threat‑Intel helper
====================================================

`ConnectorClient` now *factors out* the repeated async logic (fetch page,
optionally follow `@odata.nextLink`, turn into list) into reusable helpers:

* `_fetch_collection()` – generic async worker used by every endpoint.
* `_collection_sync()` – one‑liner wrapper that passes the coroutine to
  the event‑loop via `run_sync()`.

With that, **each new sync method is just a builder + a single call** –
no more inline `_impl` duplication.
"""

import asyncio
from typing import Any, Callable, Coroutine, TypeVar

from azure.identity import DefaultAzureCredential
from msgraph import GraphServiceClient

__all__ = ["ConnectorClient"]

T = TypeVar("T")


class ConnectorClient:
    """Synchronous‑first helper for Microsoft Defender Threat Intelligence."""

    # ------------------------------------------------------------------
    # Construction & core utilities
    # ------------------------------------------------------------------
    def __init__(
        self,
        *,
        credential: TokenCredential | None = None,
        scopes: list[str] | None = None,
    ) -> None:
        self._credential = credential or DefaultAzureCredential(
            exclude_interactive_browser_credential=False
        )
        self._scopes: list[str] = scopes or ["https://graph.microsoft.com/.default"]
        self._client: GraphServiceClient | None = None  # lazy

    @property
    def client(self) -> GraphServiceClient:  # pragma: no cover – tiny getter
        if self._client is None:
            self._client = GraphServiceClient(
                credential=self._credential,
                scopes=self._scopes,
            )
        return self._client

    def run_sync(self, coro_factory: Callable[[], Coroutine[Any, Any, T]]) -> T:
        """Bridge async → sync by running *coro_factory()* in a fresh loop."""

        return asyncio.run(coro_factory())

    # ------------------------------------------------------------------
    # Async building blocks (re‑used by every endpoint) -----------------
    # ------------------------------------------------------------------
    async def _paged(self, first_page) -> list[dict[str, Any]]:
        """Collect all pages starting at *first_page* via *@odata.nextLink*."""

        results: list[dict[str, Any]] = []
        page = first_page
        while page:
            items = getattr(page, "value", None) or page.get("value", [])  # type: ignore[attr-defined]
            results.extend(items)

            next_link = getattr(page, "odata_next_link", None) or page.get("@odata.nextLink")  # type: ignore[attr-defined]
            if not next_link:
                break
            page = await self.client.with_url(next_link).get()
        return results

    async def _fetch_collection(
        self,
        builder,
        *,
        query_parameters: dict[str, Any] | None,
        all_pages: bool,
    ) -> list[dict[str, Any]]:
        """Generic *get()* wrapper shared by all collection endpoints."""

        first_page = await builder.get(query_parameters=query_parameters)  # type: ignore[arg-type]
        if not all_pages:
            return getattr(first_page, "value", None) or first_page.get("value", [])
        return await self._paged(first_page)

    def _collection_sync(
        self,
        builder,
        *,
        query_parameters: dict[str, Any] | None = None,
        all_pages: bool = True,
    ) -> list[dict[str, Any]]:
        """Run :meth:`_fetch_collection` synchronously and return list."""

        return self.run_sync(
            lambda: self._fetch_collection(
                builder,
                query_parameters=query_parameters,
                all_pages=all_pages,
            )
        )

    # ------------------------------------------------------------------
    # Public synchronous helpers ---------------------------------------
    # ------------------------------------------------------------------
    def get_articles(
        self,
        count: bool = False,
        expand : str | None = None,
        filter: str | None = None,
        orderby: str | None = None,
        search: str | None = None,
        select: list[str] | None = None,
        skip: int | None = None,
        top: int = 50,
        query_parameters: dict[str, Any] | None = None,
        all_pages: bool = True,
    ) -> list[dict[str, Any]]:
        """Return Threat‑Intel **articles** (sync)."""

        return self._collection_sync(
            builder=self.client.security.threat_intelligence.articles,
            query_parameters={
                "top": top,
                query_parameters
            },
            all_pages=all_pages,
        )

    def get_article_indicators(
        self,
        article_id: str,
        *,
        query_parameters: dict[str, Any] | None = None,
        all_pages: bool = True,
    ) -> list[dict[str, Any]]:
        """Return Indicators (**IOCs**) linked to *article_id* (sync)."""

        builder = self.client.security.threat_intelligence.articles.by_article_id(  # type: ignore[attr-defined]
            article_id
        ).indicators
        return self._collection_sync(
            builder, query_parameters=query_parameters, all_pages=all_pages
        )

    # ------------------------------------------------------------------
    # Template for future endpoints ------------------------------------
    # ------------------------------------------------------------------
    def get_profiles(self, **kwargs):  # placeholder / example
        raise NotImplementedError
