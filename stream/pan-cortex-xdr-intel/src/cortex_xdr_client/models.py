from typing import Literal

from pydantic import AwareDatetime, BaseModel, Field, computed_field, field_serializer


class IndicatorData(BaseModel):
    """Indicator data for `/public_api/v1/indicators/insert` endpoint.

    References:
      - https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-insert
    Notes:
      - The API documentation may not be clear about the required/optional fields. In fact, all fields are required
      (must be present) but their values can be `None`.
    """

    indicator: str = Field(
        description="The value of the indicator (e.g., IP address, domain, hash).",
    )
    type: Literal["HASH", "IP", "PATH", "DOMAIN_NAME", "FILENAME", "MIXED"] = Field(
        description="The type of the indicator (e.g., 'IP', 'DOMAIN_NAME', 'HASH').",
    )
    severity: (
        Literal["SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"] | None
    ) = Field(
        default=None,
        description="The severity of the indicator (e.g., 'SEV_040_HIGH').",
    )
    expiration_date: AwareDatetime | None = Field(
        default=None,
        description="The expiration date of the indicator as a timestamp in milliseconds.",
    )
    comment: str | None = Field(
        default=None,
        description="A comment associated with the indicator.",
    )
    reputation: (
        Literal["GOOD", "BAD", "SUSPICIOUS", "UNKNOWN", "NO_REPUTATION"] | None
    ) = Field(
        default=None,
        description="The reputation of the indicator (e.g., 'BAD').",
    )
    reliability: Literal["A", "B", "C", "D"] | None = Field(
        default=None,
        description="The reliability of the indicator (e.g., 'A', 'B', 'C', 'D').",
    )

    @computed_field
    @property
    def default_expiration_enabled(self) -> bool:
        """Compute the value of `default_expiration_enabled` based on the presence of `expiration_date`.

        Returns:
            bool: True if `expiration_date` is None, False otherwise.
        """
        return self.expiration_date is None

    @field_serializer("expiration_date")
    def serialize_datetimes(self, value: AwareDatetime | None) -> int | None:
        """Convert datetime objects to Unix timestamp in milliseconds during JSON serialization.

        Returns:
            int | None: Timestamps for fields with set values, `None` otherwise.
        """
        return int(value.timestamp() * 1000) if value else None


class IndicatorFilters(BaseModel):
    """Indicator filters for `/public_api/v1/indicators/delete` endpoint.

    References:
      - https://cortex-docs.paloaltonetworks.com/xdr-5-api/cortex-platform/iocs#post-public_api-v1-indicators-delete
    """

    field: Literal["indicator"] = Field(
        default="indicator",
        description="The field to filter on (currently only 'indicator' is supported).",
    )
    operator: Literal["EQ"] = Field(
        default="EQ",
        description="The operator to use for filtering (currently only 'EQ' is supported).",
    )
    value: str = Field(
        description="The value to filter by (e.g., the indicator value).",
    )
