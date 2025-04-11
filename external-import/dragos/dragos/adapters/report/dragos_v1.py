"""Dragos API v1 adapter for reports."""

import asyncio
from io import BytesIO
from typing import TYPE_CHECKING, Generator, Optional

from client_api.v1 import DragosClientAPIV1
from client_api.v1.indicator import IndicatorResponse
from client_api.v1.product import ProductResponse, TagResponse
from dragos.interfaces import Indicator, Report, Reports, Tag
from pydantic import PrivateAttr

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from pydantic import SecretStr
    from yarl import URL


class TagAPIV1(Tag):
    """Define Tag from Dragos API v1."""

    _tag_response: "TagResponse" = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the Tag instance."""
        Tag.__init__(self)

    @classmethod
    def from_tag_response(cls, tag_response: "TagResponse") -> "TagAPIV1":
        """Convert TagResponse instance to TagAPIV1 instance."""
        cls._tag_response = tag_response
        return cls()

    @property
    def _type(self) -> str:
        """Get tag type."""
        return self._tag_response.tag_type or ""

    @property
    def _value(self) -> str:
        """Get tag value."""
        return self._tag_response.text


class IndicatorAPIV1(Indicator):
    """Define Indicator from Dragos API v1."""

    _indicator_response: "IndicatorResponse" = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the Indcator instance."""
        Indicator.__init__(self)

    @classmethod
    def from_indicator_response(
        cls, indicator_response: "IndicatorResponse"
    ) -> "IndicatorAPIV1":
        """Convert IndicatorResponse instance to IndicatorAPIV1 instance."""
        cls._indicator_response = indicator_response
        return cls()

    @property
    def _type(self) -> str:
        """Get indicator type."""
        return self._indicator_response.indicator_type  # type: ignore[return-value]
        # expected ['sha256', 'ip', 'domain', 'md5', 'sha1']  are only strs

    @property
    def _value(self) -> str:
        """Get indicator value."""
        return self._indicator_response.value

    @property
    def _first_seen(self) -> str:
        """Get the date the indicator has been first seen."""
        return self._indicator_response.first_seen.isoformat()

    @property
    def _last_seen(self) -> str:
        """Get the date the indicator has been last seen."""
        return self._indicator_response.last_seen.isoformat()


class ReportAPIV1(Report):
    """Define Report from Dragos API v1."""

    _product_response: "ExtendedProductResponse" = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the Report instance."""
        Report.__init__(self)

    @classmethod
    def from_product_response(
        cls, product_response: "ExtendedProductResponse"
    ) -> "ReportAPIV1":
        """Convert ExtendedProductResponse instance to ReportAPIV1 instance."""
        cls._product_response = product_response
        return cls()

    @property
    def _serial(self) -> str:
        """Get report's serial."""
        return self._product_response.product.serial

    @property
    def _title(self) -> str:
        """Get report's title."""
        return self._product_response.product.title

    @property
    def _created_at(self) -> str:
        """Get report's creation date."""
        return self._product_response.product.release_date.isoformat()

    @property
    def _updated_at(self) -> str:
        """Get report's last update date."""
        return self._product_response.product.updated_at.isoformat()

    @property
    def _summary(self) -> str:
        """Get report's summary."""
        return self._product_response.product.executive_summary

    @property
    def _pdf(self) -> Optional[bytes]:
        """Get report's PDF content."""
        pdf_bytes = self._product_response.pdf
        if pdf_bytes:
            return pdf_bytes.read()
        return None

    @property
    def _related_tags(self) -> Generator[Tag, None, None]:
        """Get all related tags."""
        for tag in self._product_response.product.tags:
            yield TagAPIV1.from_tag_response(tag)

    @property
    def _related_indicators(self) -> Generator[Indicator, None, None]:
        """Gett all related indicators."""
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

        async def iter_indicators() -> list[IndicatorResponse]:
            """Iterate over all indicators."""
            async_indicators = self._client.indicator.iter_indicators(
                serials=[self.product.serial]
            )

            return [indicator async for indicator in async_indicators]

        indicators = asyncio.run(iter_indicators())
        return indicators

    @property
    def pdf(self) -> Optional[BytesIO]:
        """Get the PDF of the product."""

        async def get_pdf() -> BytesIO:
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
        token: "SecretStr",
        secret: "SecretStr",
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

        async def iter_products() -> list[ExtendedProductResponse]:
            """Iterate over all products."""
            product_responses = self._client.product.iter_products(updated_after=since)

            return [
                ExtendedProductResponse(product=product, client=self._client)
                async for product in product_responses
            ]

        products = asyncio.run(iter_products())
        for product in products:
            yield ReportAPIV1.from_product_response(product)
