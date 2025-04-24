# isort:skip_file
"""Offer Client to reach the Dragos Worldview API product endpoint."""
import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator, Literal, Optional

from pydantic import AwareDatetime, Field

from client_api.v1.common import BaseAPIV1BulkResponse, BaseClientAPIV1, ResponseModel
from client_api.warning import PermissiveLiteral


class ProductReference(ResponseModel):
    """Reference model for a product in the Dragos Worldview API indicator endpoint."""

    serial: str = Field(..., description="Unique serial identifier for the product.")


class IndicatorResponse(ResponseModel):
    """Response model for an indicator in the Dragos Worldview API."""

    id: int = Field(..., description="Unique identifier for the indicator.")
    value: str = Field(..., description="Value of the indicator.")
    indicator_type: PermissiveLiteral[
        Literal["sha256", "ip", "domain", "md5", "sha1"]
    ] = Field(..., description="Type of the indicator.")
    category: Optional[str] = Field(None, description="Category of the indicator.")
    comment: Optional[str] = Field(None, description="Comment about the indicator.")
    first_seen: AwareDatetime = Field(
        ..., description="Timestamp when the indicator was first seen."
    )
    last_seen: AwareDatetime = Field(
        ..., description="Timestamp when the indicator was last seen."
    )
    updated_at: AwareDatetime = Field(
        ..., description="Timestamp when the indicator was last updated."
    )
    confidence: PermissiveLiteral[Literal["low", "moderate", "high"]] = Field(
        ..., description="Confidence level of the indicator."
    )
    kill_chain: Optional[str] = Field(
        None, description="Kill chain phase of the indicator."
    )
    uuid: str = Field(..., description="UUID of the indicator.")
    status: PermissiveLiteral[Literal["released"]] = Field(
        ..., description="Status of the indicator."
    )
    severity: Optional[str] = Field(
        None, description="Severity level of the indicator."
    )
    attack_techniques: list[str] = Field(
        ..., description="List of attack techniques associated with the indicator."
    )
    ics_attack_techniques: list[str] = Field(
        ..., description="List of ICS attack techniques associated with the indicator."
    )
    kill_chains: list[str] = Field(
        ..., description="List of kill chains associated with the indicator."
    )
    pre_attack_techniques: list[str] = Field(
        ..., description="List of pre-attack techniques associated with the indicator."
    )
    threat_groups: list[str] = Field(
        ..., description="List of threat groups associated with the indicator."
    )
    products: list[ProductReference] = Field(
        ..., description="List of products associated with the indicator."
    )


class IndicatorsResponse(BaseAPIV1BulkResponse):
    """Response model for the Dragos Worldview API."""

    indicators: list[IndicatorResponse] = Field(
        ..., description="List of indicators returned in the API response."
    )


class IndicatorClientAPIV1(BaseClientAPIV1):
    """Client API for the Dragos Worldview API endpoint."""

    @staticmethod
    def _validate_params_get_1_page(
        page: int,
        page_size: int,
        updated_after: Optional[AwareDatetime],
    ) -> None:
        """Validate the parameters for the get_page method.

        Raises:
            ValueError: If the parameters are invalid.

        References:
            * https://portal.dragos.com/api/v1/doc/index.html

        """
        if page < 1:
            raise ValueError("Page number must be greater than 0.")
        if not (1 <= page_size <= 1000):
            raise ValueError("Page size must be between 1 and 1000.")
        now_utc = datetime.now(timezone.utc)
        if updated_after and updated_after > now_utc:
            raise ValueError("updated_after timestamp must be in the past.")

    async def _get_1_page(
        self,
        page: int = 1,
        page_size: int = 500,
        exclude_suspect_domain: bool = False,
        updated_after: Optional[AwareDatetime] = None,
        value: Optional[str] = None,
        type: Optional[str] = None,
        serials: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> IndicatorsResponse:
        """Get a page of indicators from the Dragos Worldview API.

        Args:
            page (int): Page number.
            page_size (int): Page size (default 500, must be less than 1001).
            exclude_suspect_domain (bool): Exclude indicators associated with Suspect Domain Reports. Default to False.
            updated_after (Optional[AwareDatetime]): To filter to recently updated indicators.
            value (Optional[str]): Search for indicators that match a specific value.
            type (Optional[str]): Search for indicators of a specific type.
            serials (Optional[list[str]]): Filter indicators from an array of serials.
            tags (Optional[list[str]]): Filter indicators matching tag(s) text.

        Returns:
            IndicatorsResponse: The response from the API.

        """
        self._validate_params_get_1_page(
            page=page,
            page_size=page_size,
            updated_after=updated_after,
        )
        url = BaseClientAPIV1.format_get_query(
            self,
            path="indicators",
            params=dict(  # noqa C408
                page=page,
                page_size=page_size,
                exclude_suspect_domain=exclude_suspect_domain,
                updated_after=updated_after.isoformat() if updated_after else None,
                value=value,
                type=type,
                serial=serials,
                tags=tags,
            ),
        )
        return await BaseClientAPIV1.get(  # type: ignore[return-value]
            self, query_url=url, response_model=IndicatorsResponse
        )

    async def get_all_indicators(
        self,
        page_size: int = 500,
        exclude_suspect_domain: bool = False,
        updated_after: Optional[AwareDatetime] = None,
        value: Optional[str] = None,
        type: Optional[str] = None,
        serials: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> IndicatorsResponse:
        """Get indicators from the Dragos Worldview API in bulk.

        Args:
            page_size (int): Page size (default 500, must be less than 1001).
            exclude_suspect_domain (bool): Exclude indicators associated with Suspect Domain Reports.
            updated_after (Optional[AwareDatetime]): To filter to recently updated indicators.
            value (Optional[str]): Search for indicators that match a specific value.
            type (Optional[str]): Search for indicators of a specific type.
            serials (Optional[list[str]]): Filter indicators from an array of serials.
            tags (Optional[list[str]]): Filter indicators matching tag(s) text.

        Returns:
            IndicatorsResponse: The response from the API.

        Examples:
            >>> from datetime import datetime, timedelta, timezone
            >>> from yarl import URL
            >>> from pydantic import SecretStr
            >>> client = IndicatorClientAPIV1(
            ...     base_url=URL("https://portal.dragos.com"),
            ...     token=SecretStr("ChangeMe"),
            ...     secret=SecretStr("ChangeMe"),
            ...     timeout=timedelta(seconds=10),
            ...     retry=3,
            ...     backoff=timedelta(seconds=5),
            ... )
            >>> indicators = asyncio.run(
            ...     client.get_all_indicators(
            ...         updated_after=datetime.now(timezone.utc) - timedelta(days=1)
            ...     )
            ... )
            >>> print(indicators)

        """
        # first page of indicators
        indicators: IndicatorsResponse = await self._get_1_page(
            page=1,
            page_size=page_size,
            exclude_suspect_domain=exclude_suspect_domain,
            updated_after=updated_after,
            value=value,
            type=type,
            serials=serials,
            tags=tags,
        )

        # get the remaining pages if relevant
        if indicators.total_pages > 1:
            tasks = [
                self._get_1_page(
                    page=page,
                    page_size=page_size,
                    exclude_suspect_domain=exclude_suspect_domain,
                    updated_after=updated_after,
                    value=value,
                    type=type,
                    serials=serials,
                    tags=tags,
                )
                for page in range(2, indicators.total_pages + 1)
            ]
            pages_data = await asyncio.gather(*tasks)
            for page_data in pages_data:
                indicators.indicators.extend(page_data.indicators)
        return indicators

    async def iter_indicators(
        self,
        page_size: int = 500,
        exclude_suspect_domain: bool = False,
        updated_after: Optional[AwareDatetime] = None,
        value: Optional[str] = None,
        type: Optional[str] = None,
        serials: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> AsyncGenerator[IndicatorResponse, None]:
        """Get indicators from the Dragos Worldview API with an async generator.

        Args:
            page_size (int): Page size (default 500, must be less than 1001).
            exclude_suspect_domain (bool): Exclude indicators associated with Suspect Domain Reports.
            updated_after (Optional[AwareDatetime]): To filter to recently updated indicators.
            value (Optional[str]): Search for indicators that match a specific value.
            type (Optional[str]): Search for indicators of a specific type.
            serials (Optional[list[str]]): Filter indicators from an array of serials.
            tags (Optional[list[str]]): Filter indicators matching tag(s) text.

        Yields:
            IndicatorResponse: The response from the API.

        Examples:
            >>> from datetime import datetime, timedelta, timezone
            >>> from yarl import URL
            >>> from pydantic import SecretStr
            >>> client = IndicatorClientAPIV1(
            ...     base_url=URL("https://portal.dragos.com"),
            ...     token=SecretStr("ChangeMe"),
            ...     secret=SecretStr("ChangeMe"),
            ...     timeout=timedelta(seconds=10),
            ...     retry=3,
            ...     backoff=timedelta(seconds=5),
            ... )
            >>> async def last_day():
            ...     async for indicator in client.iter_indicators(
            ...         updated_after=datetime.now(timezone.utc) - timedelta(days=1)
            ...     ):
            ...         print(indicator)
            >>> asyncio.run(last_day())
            >>> async def from_report(serial):
            ...     async for indicator in client.iter_indicators(serials=[serial]):
            ...         print(indicator)
            >>> asyncio.run(from_report("DOM-2024-08"))

        """
        page = 1
        while True:
            indicators: IndicatorsResponse = await self._get_1_page(
                page=page,
                page_size=page_size,
                exclude_suspect_domain=exclude_suspect_domain,
                updated_after=updated_after,
                value=value,
                type=type,
                serials=serials,
                tags=tags,
            )
            for indicator in indicators.indicators:
                yield indicator
            if page >= indicators.total_pages:
                break
            page += 1
