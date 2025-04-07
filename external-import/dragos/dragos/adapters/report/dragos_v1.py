import asyncio
from typing import TYPE_CHECKING, Generator, Optional

from client_api.v1 import DragosClientAPIV1
from client_api.v1.product import ProductResponse
from dragos.interfaces import Indicator, Report, Reports, Tag
from pydantic import PrivateAttr

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from client_api.v1.indicator import IndicatorResponse
    from client_api.v1.product import TagResponse
    from yarl import URL


class TagAPIV1(Tag):
    """Define Tag from Dragos API v1."""

    @classmethod
    def from_tag_response(cls, tag_response: "TagResponse") -> "TagAPIV1":
        """Convert TagResponse to Tag."""
        return cls(
            type=tag_response.tag_type,
            value=tag_response.text,
        )


class IndicatorAPIV1(Indicator):
    """Define Indicator from Dragos API v1."""

    @classmethod
    def from_indicator_response(
        cls, indicator_response: "IndicatorResponse"
    ) -> "IndicatorAPIV1":
        """Convert IndicatorResponse to Indicator."""
        return cls(
            type=indicator_response.indicator_type,
            value=indicator_response.value,
            first_seen=indicator_response.first_seen,
            last_seen=indicator_response.last_seen,
        )


class ReportAPIV1(Report):
    """Define Report from Dragos API v1."""

    _product_response: "ExtendedProductResponse" = PrivateAttr()

    @classmethod
    def from_product_response(
        cls, product_response: "ExtendedProductResponse"
    ) -> "ReportAPIV1":
        """Convert ProductResponse to Report."""
        cls._product_response = product_response

        product = product_response.product
        return cls(
            serial=product.serial,
            title=product.title,
            created_at=product.release_date,
            updated_at=product.updated_at,
            summary=product.executive_summary,
        )

    @property
    def pdf(self) -> Optional[bytes]:
        return self._product_response.pdf

    @property
    def related_tags(self) -> Generator[Tag, None, None]:
        """List all related tags."""
        for tag in self._product_response.product.tags:
            yield TagAPIV1.from_tag_response(tag)

    @property
    def related_indicators(self) -> Generator[Indicator, None, None]:
        for indicator in self._product_response.indicators:
            yield IndicatorAPIV1.from_indicator_response(indicator)


class ExtendedProductResponse:
    """Extend ProductResponse from Dragos API v1 to include indicators and pdf."""

    def __init__(self, product: "ProductResponse", client: "DragosClientAPIV1") -> None:
        """Initialize the ExtendedProductResponse."""
        self.product = product
        self._client = client

    @property
    def indicators(self) -> list["IndicatorResponse"]:
        """Get all indicators related to the product."""

        async def iter_indicators():
            """Iterate over all indicators."""
            async_indicators = self._client.indicator.iter_indicators(
                serials=[self.product.serial]
            )

            return [indicator async for indicator in async_indicators]

        indicators = asyncio.run(iter_indicators())
        return indicators

    @property
    def pdf(self) -> Optional[bytes]:
        """Get the PDF of the product."""

        async def get_pdf():
            """Get the PDF of the product."""
            return await self._client.product.get_product_pdf(
                serial=self.product.serial
            )

        pdf = asyncio.run(get_pdf())
        return pdf


class ReportsAPIV1(Reports):
    """Dragos API v1 adapter for reports."""

    def __init__(
        self,
        base_url: "URL",
        token: str,
        secret: str,
        timeout: "timedelta",
        retry: int,
        backoff: "timedelta",
    ):
        """Initialize the adapter."""
        self._client = DragosClientAPIV1(
            base_url=base_url,
            token=token,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
        )

    def iter(self, since: "datetime") -> Generator[Report, None, None]:
        """List all Dragos reports."""

        async def iter_products():
            """Iterate over all products."""
            product_responses = self._client.product.iter_products(updated_after=since)

            return [
                ExtendedProductResponse(product=product, client=self._client)
                async for product in product_responses
            ]

        products = asyncio.run(iter_products())
        for product in products:
            yield ReportAPIV1.from_product_response(product)
