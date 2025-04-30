"""Dragos API v1 adapter for reports."""

import asyncio
import warnings
from io import BytesIO
from logging import getLogger
from typing import TYPE_CHECKING, Iterator, Optional

from client_api.errors import DragosAPIError
from client_api.v1 import DragosClientAPIV1
from client_api.v1.indicator import IndicatorResponse
from client_api.v1.product import ProductResponse, TagResponse
from dragos.interfaces import Indicator, Report, Reports, Tag
from dragos.interfaces.report import (
    IncompleteReportWarning,
    IndicatorRetrievalError,
    PDFRetrievalError,
)
from pydantic import PrivateAttr

logger = getLogger(__name__)


if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from limiter import Limiter  # type: ignore[import-untyped]  # Limiter is not typed
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

    _extended_product_response: "ExtendedProductResponse" = PrivateAttr()

    def __init__(self) -> None:
        """Initialize the Report instance."""
        Report.__init__(self)

    @classmethod
    def from_extended_product_response(
        cls, extended_product_response: "ExtendedProductResponse"
    ) -> "ReportAPIV1":
        """Convert ExtendedProductResponse instance to ReportAPIV1 instance."""
        cls._extended_product_response = extended_product_response
        return cls()

    @property
    def _serial(self) -> str:
        """Get report's serial."""
        return self._extended_product_response.product.serial

    @property
    def _title(self) -> str:
        """Get report's title."""
        return self._extended_product_response.product.title

    @property
    def _created_at(self) -> str:
        """Get report's creation date."""
        return self._extended_product_response.product.release_date.isoformat()

    @property
    def _updated_at(self) -> str:
        """Get report's last update date."""
        return self._extended_product_response.product.updated_at.isoformat()

    @property
    def _summary(self) -> str:
        """Get report's summary."""
        return self._extended_product_response.product.executive_summary

    @property
    def _pdf(self) -> Optional[bytes]:
        """Get report's PDF content."""
        pdf_bytes = self._extended_product_response.pdf
        if pdf_bytes:
            return pdf_bytes.read()
        return None

    @property
    def _related_tags(self) -> list[Tag]:
        """Get all related tags."""
        tags = []
        for tag in self._extended_product_response.product.tags:
            if not tag.tag_type or not tag.text:
                # Skip tags without type or text
                logger.warning("Skipping tag without type or text")
                continue
            tags.append(TagAPIV1.from_tag_response(tag))
        return tags  # type: ignore[return-value]  # TagAPIV1 is a subclass of Tag

    @property
    def _related_indicators(self) -> list[Indicator]:
        """Gett all related indicators."""
        return [
            IndicatorAPIV1.from_indicator_response(indicator)
            for indicator in self._extended_product_response.indicators
        ]


class ExtendedProductResponse:
    """Extend ProductResponse from Dragos API v1 to include indicators and pdf."""

    def __init__(self, product: "ProductResponse", client: "DragosClientAPIV1") -> None:
        """Initialize the ExtendedProductResponse."""
        self.product = product
        self._client = client

    @property
    def indicators(self) -> list["IndicatorResponse"]:
        """Get all indicators related to the product."""
        try:
            # Get all indicators related to the product
            indicators_resp = asyncio.run(
                self._client.indicator.get_all_indicators(serials=[self.product.serial])
            )
        except DragosAPIError as e:
            raise IndicatorRetrievalError(
                f"Failed to retrieve indicators: {str(e)}"
            ) from e
        return indicators_resp.indicators

    @property
    def pdf(self) -> Optional[BytesIO]:
        """Get the PDF of the product."""

        async def get_pdf() -> BytesIO:
            """Get the PDF of the product."""
            return await self._client.product.get_product_pdf(
                serial=self.product.serial
            )

        try:
            pdf = asyncio.run(get_pdf())
        except DragosAPIError as e:
            raise PDFRetrievalError(f"Failed to retrieve PDF: {str(e)}") from e
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
        rate_limiter: Optional["Limiter"] = None,
    ) -> None:
        """Initialize the adapter."""
        self._client = DragosClientAPIV1(
            base_url=base_url,
            token=token,
            secret=secret,
            timeout=timeout,
            retry=retry,
            backoff=backoff,
            rate_limiter=rate_limiter,
        )

    def iter(self, since: "datetime") -> Iterator[Report]:
        """Create an iterator for reports based on an async one."""

        class ReportIterator(Iterator[Report]):
            def __init__(_self) -> None:  # noqa: N805 # _selt to diffrentiate from self
                _self._it = self._client.product.sync_iter_products(updated_after=since)

            def __iter__(_self) -> "ReportIterator":  # noqa: N805
                return _self

            def __next__(_self) -> Report:  # noqa: N805
                product_response = next(_self._it)
                try:
                    extended_product_response = ExtendedProductResponse(
                        product=product_response, client=self._client
                    )
                    return ReportAPIV1.from_extended_product_response(
                        extended_product_response
                    )
                except (IndicatorRetrievalError, PDFRetrievalError) as e:
                    logger.warning(f"Failed to retrieve complete report: {e}")
                    warnings.warn(
                        f"Failed to retrieve complete report: {e}",
                        category=IncompleteReportWarning,
                        stacklevel=2,
                    )

                    # Create a partial extended product response to return the report
                    class PartialExtendedProductResponse(ExtendedProductResponse):
                        @property
                        def indicators(self) -> list["IndicatorResponse"]:
                            # select based on error type
                            if isinstance(e, IndicatorRetrievalError):  # noqa: F821
                                # flake 8 does not realize that e is an instance of
                                # IndicatorRetrievalError
                                return []
                            return super().indicators

                        @property
                        def pdf(self) -> Optional[BytesIO]:
                            if isinstance(e, PDFRetrievalError):  # noqa: F821
                                return None
                            return super().pdf

                    return ReportAPIV1.from_extended_product_response(
                        extended_product_response=PartialExtendedProductResponse(
                            product=product_response, client=self._client
                        )
                    )

        return ReportIterator()
