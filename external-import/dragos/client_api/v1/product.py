# isort:skip_file
"""Offer Client to reach the Dragos Worldview API product endpoint."""
import asyncio
from datetime import datetime, timezone
from io import BytesIO
from typing import AsyncIterator, Iterator, Literal, Optional

from pydantic import AwareDatetime, Field, HttpUrl

from client_api.v1.common import BaseAPIV1BulkResponse, BaseClientAPIV1, ResponseModel
from client_api.warning import PermissiveLiteral


class TagResponse(ResponseModel):
    """Response model for the Dragos Worldview API."""

    text: str = Field(..., description="The tag text value.")
    tag_type: Optional[str] = Field(
        None,
        description="The category of the tag. Warning: This field may not be returned.",
    )


class ProductResponse(ResponseModel):
    """Response model for the Dragos Worldview API."""

    tlp_level: PermissiveLiteral[Literal["white", "green", "amber", "red"]] = Field(
        ..., description="Traffic Light Protocol (TLP) level of the report."
    )
    title: str = Field(..., description="Title of the product.")
    executive_summary: str = Field(
        ..., description="Executive summary of the report, formatted with html."
    )
    updated_at: AwareDatetime = Field(
        ..., description="Timestamp when the product was last updated."
    )
    threat_level: int = Field(..., description="Threat level of the report.")
    serial: str = Field(..., description="Unique serial identifier for the product.")
    ioc_count: int = Field(
        ..., description="Number of Indicators of Compromise (IOC) in the report."
    )
    tags: list[TagResponse] = Field(..., description="List of associated tags.")
    release_date: AwareDatetime = Field(
        ..., description="Timestamp when the product was released."
    )
    type: str = Field(..., description="Type of the product.")
    report_link: HttpUrl = Field(..., description="URL to the pdf report.")
    ioc_csv_link: Optional[HttpUrl] = Field(
        None, description="Optional URL to download the IOCs in CSV format."
    )
    ioc_stix2_link: Optional[HttpUrl] = Field(
        None, description="Optional URL to download the IOCs in STIX 2 format."
    )
    slides_link: Optional[HttpUrl] = Field(
        None, description="Optional URL to download the slides."
    )


class ProductsResponse(BaseAPIV1BulkResponse):
    """Response model for the Dragos Worldview API."""

    products: list[ProductResponse] = Field(
        ..., description="List of products returned in the API response."
    )


class ProductClientAPIV1(BaseClientAPIV1):
    """Client API for the Dragos Worldview API endpoint."""

    @staticmethod
    def _validate_params_get_1_page(
        page: int,
        page_size: int,
        updated_after: Optional[AwareDatetime],
        released_after: Optional[AwareDatetime],
    ) -> None:
        """Validate the parameters for the get_page method.

        Raises:
            ValueError: If the parameters are invalid.

        """
        if page < 1:
            raise ValueError("Page number must be greater than 0.")
        if not (1 <= page_size <= 500):
            raise ValueError("Page size must be between 1 and 500.")
        now_utc = datetime.now(timezone.utc)
        if updated_after and updated_after > now_utc:
            raise ValueError("updated_after timestamp must be in the past.")
        if released_after and released_after > now_utc:
            raise ValueError("released_after timestamp must be in the past.")

    async def _get_1_page(
        self,
        page: int = 1,
        page_size: int = 50,
        sort_by: Literal["release_date", "updated_at", "title"] = "release_date",
        sort_desc: bool = False,
        updated_after: Optional[AwareDatetime] = None,
        released_after: Optional[AwareDatetime] = None,
        serials: Optional[list[str]] = None,
        indicator: Optional[str] = None,
    ) -> ProductsResponse:
        """Get a page of products from the Dragos Worldview API.

        Args:
            page (int): Page number.
            page_size (int): Page size (default 50, must be less than 501).
            sort_by (str): Sort returned products. Default to `release_date`.
            sort_desc (bool): Page desc. Default to False.
            updated_after (Optional[AwareDatetime]): To filter to recently updated products.
            released_after (Optional[str]): To filter to recently released products.
            serials (Optional[list[str]]): Filter reports from an array of serials.
            indicator (Optional[str]): Filter reports related to a given indicator (exact match only).

        Returns:
            ProductsResponse: The response from the API.

        """
        ProductClientAPIV1._validate_params_get_1_page(
            page=page,
            page_size=page_size,
            updated_after=updated_after,
            released_after=released_after,
        )
        url = BaseClientAPIV1.format_get_query(
            self,
            path="products",
            params=dict(  # noqa C408
                page=page,
                page_size=page_size,
                sort_by=sort_by,
                sort_desc=sort_desc,
                updated_after=updated_after.isoformat() if updated_after else None,
                released_after=released_after.isoformat() if released_after else None,
                serials=serials if serials else None,
                indicator=indicator if indicator else None,
            ),
        )
        return await BaseClientAPIV1.get(  # type: ignore[return-value]
            self, query_url=url, response_model=ProductsResponse
        )

    async def get_all_products(
        self,
        page_size: int = 50,
        updated_after: Optional[AwareDatetime] = None,
        released_after: Optional[AwareDatetime] = None,
        serials: Optional[list[str]] = None,
        indicator: Optional[str] = None,
    ) -> ProductsResponse:
        """Get products from the Dragos Worldview API in bulk.

        Args:
            page_size (int): Page size (default 50, must be less than 501).
            updated_after (Optional[AwareDatetime]): To filter to recently updated products.
            released_after (Optional[str]): To filter to recently released products.
            serials (Optional[list[str]]): Filter reports from an array of serials.
            indicator (Optional[str]): Filter reports related to a given indicator (exact match only).

        Returns:
            ProductsResponse: The response from the API.

        Examples:
            >>> from datetime import datetime, timedelta, timezone
            >>> from yarl import URL
            >>> from pydantic import SecretStr
            >>> client = ProductClientAPIV1(
            ...     base_url=URL("https://portal.dragos.com"),
            ...     token=SecretStr("ChangeMe"),
            ...     secret=SecretStr("ChangeMe"),
            ...     timeout=timedelta(seconds=10),
            ...     retry=3,
            ...     backoff=timedelta(seconds=5),
            ... )
            >>> products = asyncio.run(
            ...     client.get_all_products(
            ...         updated_after=datetime.now(timezone.utc) - timedelta(days=1)
            ...     )
            ... )
            >>> print(products)

        """
        # first page of products
        products: ProductsResponse = await self._get_1_page(
            page=1,
            page_size=page_size,
            updated_after=updated_after,
            released_after=released_after,
            serials=serials,
            indicator=indicator,
        )

        # get the remaining pages if relevant
        if products.total_pages > 1:
            tasks = [
                self._get_1_page(
                    page=page,
                    page_size=page_size,
                    updated_after=updated_after,
                    released_after=released_after,
                    serials=serials,
                    indicator=indicator,
                )
                for page in range(2, products.total_pages + 1)
            ]
            pages_data = await asyncio.gather(*tasks)
            for page_data in pages_data:
                products.products.extend(page_data.products)
        return products

    def _make_product_iterator(
        self,
        page_size: int = 50,
        updated_after: Optional[AwareDatetime] = None,
        released_after: Optional[AwareDatetime] = None,
        serials: Optional[list[str]] = None,
        indicator: Optional[str] = None,
    ) -> AsyncIterator[ProductResponse]:
        class _AsyncIterator(AsyncIterator[ProductResponse]):
            """Async iterator for the products."""

            def __init__(
                _self: "_AsyncIterator",  # noqa: N805
                # _self is to differentaite from self
            ) -> None:
                _self.current_page = 0
                _self.items: list[ProductResponse] = []  # page cache
                _self.index_in_items = 0
                _self.total_pages: Optional[int] = (
                    None  # will be updated after 1st call
                )

            def __aiter__(_self) -> "_AsyncIterator":  # noqa: N805
                return _self

            async def __anext__(_self) -> ProductResponse:  # noqa: N805
                # Load next page if needed
                if _self.index_in_items >= len(_self.items):
                    # not using directly page_size because last page might contain less items
                    if (
                        _self.total_pages is not None
                        and _self.current_page > _self.total_pages
                    ):
                        raise StopAsyncIteration
                    _self.page_response = await self._get_1_page(
                        page=_self.current_page + 1,
                        page_size=page_size,
                        updated_after=updated_after,
                        released_after=released_after,
                        serials=serials,
                        indicator=indicator,
                    )
                    _self.current_page += 1
                    _self.index_in_items = 0
                    _self.total_pages = _self.page_response.total_pages
                    _self.items = _self.page_response.products

                if len(_self.items) == 0:
                    raise StopAsyncIteration

                item = _self.items[_self.index_in_items]
                _self.index_in_items += 1
                return item

        return _AsyncIterator()

    def iter_products(
        self,
        page_size: int = 50,
        updated_after: Optional[AwareDatetime] = None,
        released_after: Optional[AwareDatetime] = None,
        serials: Optional[list[str]] = None,
        indicator: Optional[str] = None,
    ) -> AsyncIterator[ProductResponse]:
        """Get products from the Dragos Worldview API with an async generator.

        Args:
            page_size (int): Page size (default 50, must be less than 501).
            updated_after (Optional[AwareDatetime]): To filter to recently updated products.
            released_after (Optional[str]): To filter to recently released products.
            serials (Optional[list[str]]): Filter reports from an array of serials.
            indicator (Optional[str]): Filter reports related to a given indicator (exact match only).

        Yields:
            ProductsResponse: The response from the API.


        Examples:
            >>> from datetime import datetime, timedelta, timezone
            >>> from yarl import URL
            >>> from pydantic import SecretStr
            >>> client = ProductClientAPIV1(
            ...     base_url=URL("https://portal.dragos.com"),
            ...     token=SecretStr("ChangeMe"),
            ...     secret=SecretStr("ChangeMe"),
            ...     timeout=timedelta(seconds=10),
            ...     retry=3,
            ...     backoff=timedelta(seconds=5),
            ... )
            >>> async def main():
            ...     async for product in client.iter_products(
            ...         updated_after=datetime.now(timezone.utc) - timedelta(days=1)
            ...     ):
            ...         print(product)
            >>> asyncio.run(main())

        """
        return self._make_product_iterator(
            page_size=page_size,
            updated_after=updated_after,
            released_after=released_after,
            serials=serials,
            indicator=indicator,
        )

    async def get_product(self, serial: str) -> ProductResponse:
        """Get a product from the Dragos Worldview API.

        Args:
            serial (str): The serial number of the product.

        Returns:
            ProductResponse: The response from the API.

        Examples:
            >>> from datetime import timedelta
            >>> from yarl import URL
            >>> from pydantic import SecretStr
            >>> client = ProductClientAPIV1(
            ...     base_url=URL("https://portal.dragos.com"),
            ...     token=SecretStr("ChangeMe"),
            ...     secret=SecretStr("ChangeMe"),
            ...     timeout=timedelta(seconds=10),
            ...     retry=3,
            ...     backoff=timedelta(seconds=5),
            ...     page_size=50,
            ... )
            >>> product = asyncio.run(client.get_product("DOM-2024-08"))
            >>> print(product)

        """
        url = BaseClientAPIV1.format_get_query(self, path=f"products/{serial}")
        return await BaseClientAPIV1.get(  # type: ignore[return-value]
            self, query_url=url, response_model=ProductResponse
        )

    async def get_product_pdf(self, serial: str) -> BytesIO:
        """Get the PDF report for a product.

        Args:
            serial (str): The serial number of the product.

        Returns:
            bytes: The PDF report.

        Examples:
            >>> from datetime import timedelta
            >>> from yarl import URL
            >>> from pydantic import SecretStr
            >>> client = ProductClientAPIV1(
            ...     base_url=URL("https://portal.dragos.com"),
            ...     token=SecretStr("ChangeMe"),
            ...     secret=SecretStr("ChangeMe"),
            ...     timeout=timedelta(seconds=10),
            ...     retry=3,
            ...     backoff=timedelta(seconds=5),
            ...     page_size=50,
            ... )
            >>> pdf_bytes = asyncio.run(client.get_product_pdf("DOM-2024-08"))
            >>> with open("DOM-2024-08.pdf", "wb") as f:
            ...     f.write(pdf_bytes.getbuffer())

        """
        url = BaseClientAPIV1.format_get_query(self, path=f"products/{serial}/report")
        # We use _get_retry here because there is no response model for the PDF report.
        resp = await BaseClientAPIV1._get_retry(self, query_url=url)
        pdf_bytes = resp._body
        return BytesIO(pdf_bytes)  # type: ignore[arg-type]

    def sync_iter_products(
        self,
        page_size: int = 50,
        updated_after: Optional[AwareDatetime] = None,
        released_after: Optional[AwareDatetime] = None,
        serials: Optional[list[str]] = None,
        indicator: Optional[str] = None,
    ) -> Iterator[ProductResponse]:
        """Make a synchronous iterator to retrieve products.

        Args:
            page_size (int): Page size (default 50, must be less than 501).
            updated_after (Optional[AwareDatetime]): To filter to recently updated products.
            released_after (Optional[AwareDatetime]): To filter to recently released products.
            serials (Optional[list[str]]): Filter reports from an array of serials.
            indicator (Optional[str]): Filter reports related to a given indicator (exact match only).

        Yields:
            ProductResponse: The response from the API.

        See Also:
            iter_products: Asynchronous version of this method.

        Examples:
        >>> from yarl import URL
        >>> from pydantic import SecretStr
        >>> from datetime import timedelta, datetime
        >>> client = ProductClientAPIV1(
        ...     base_url=URL("http://127.0.0.1:4000"),
        ...     token=SecretStr("dev"),
        ...     secret=SecretStr("dev"),
        ...     timeout=timedelta(seconds=10),
        ...     retry=1,
        ...     backoff=timedelta(seconds=1),
        ... )
        >>> results = client.sync_iter_products(
        ...     updated_after=datetime.fromisoformat("2023-03-01T00:00:00Z")
        ... )
        >>> print([val for val in results])

        """

        class _SyncIterator(Iterator[ProductResponse]):
            def __init__(_self) -> None:  # noqa: N805 # _selt to diffrentiate from self
                _self.current_page = 0
                _self.items: list[ProductResponse] = []  # page cache
                _self.index_in_items = 0
                _self.total_pages: Optional[int] = (
                    None  # will be updated after 1st call
                )

            def __iter__(_self) -> "_SyncIterator":  # noqa: N805
                return _self

            def __next__(_self) -> ProductResponse:  # noqa: N805
                # Load next page if needed
                if _self.index_in_items >= len(_self.items):
                    if (
                        _self.total_pages is not None
                        and _self.current_page >= _self.total_pages
                    ):
                        raise StopIteration
                    # Fetch the next page synchronously
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_closed():  # Handle cases where the loop is closed
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)
                    except RuntimeError:  # No event loop in the current thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                    page_response = loop.run_until_complete(
                        self._get_1_page(
                            page=_self.current_page + 1,
                            page_size=page_size,
                            updated_after=updated_after,
                            released_after=released_after,
                            serials=serials,
                            indicator=indicator,
                        )
                    )
                    _self.current_page += 1
                    _self.index_in_items = 0
                    _self.total_pages = page_response.total_pages
                    _self.items = page_response.products

                if len(_self.items) == 0:
                    raise StopIteration

                item = _self.items[_self.index_in_items]
                _self.index_in_items += 1
                return item

        return _SyncIterator()
