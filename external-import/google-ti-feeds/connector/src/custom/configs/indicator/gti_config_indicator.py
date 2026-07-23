"""GTI configuration for indicator (IOC delta) imports."""

from datetime import timedelta

from connector.src.custom.configs.gti_config_common import GTIBaseConfig
from connector.src.custom.exceptions.gti_configuration_error import (
    GTIConfigurationError,
)
from connectors_sdk import ListFromString
from pydantic import Field, field_validator

ALLOWED_IOC_TYPES = ["file", "ip", "url", "domain"]


class GTIIndicatorConfig(GTIBaseConfig):
    """Configuration for GTI IOC indicator imports via Steady-State IOC Deltas API."""

    import_indicators: bool = Field(
        default=False,
        description="Whether to enable importing IOC indicator data from GTI via "
        "Steady-State IOC Deltas API",
    )
    indicator_types: ListFromString = Field(
        default=["file", "ip", "url", "domain"],
        description="Comma-separated list of IOC types to import. "
        "Allowed: file, ip, url, domain",
    )
    indicator_import_start_date: timedelta = Field(
        default=timedelta(days=1),
        description="ISO 8601 duration string specifying how far back to import "
        "indicators on first run (e.g. P1D for 1 day, P7D for 7 days). "
        "Must be greater than 1 hour (the IOC delta package granularity).",
    )
    indicator_min_score: int | None = Field(
        default=50,
        ge=0,
        le=100,
        description="Minimum GTI score (0-100) an indicator must have to be "
        "imported via the Steady-State IOC Deltas API. Indicators with a lower "
        "score are discarded. Indicators without a score are always imported. "
        "Set to 100 or leave unset (None) to disable the filter entirely.",
    )

    @field_validator("indicator_import_start_date", mode="after")
    @classmethod
    def validate_indicator_import_start_date(cls, v: timedelta) -> timedelta:
        """Validate that the start date lookback is greater than one hour."""
        if v <= timedelta(hours=1):
            raise GTIConfigurationError(
                "indicator_import_start_date must be greater than 1 hour "
                "(IOC delta packages have hourly granularity)."
            )
        return v

    @field_validator("indicator_types", mode="after")
    @classmethod
    def validate_indicator_types(cls, v: list[str]) -> list[str]:
        """Validate indicator types against allowed values."""
        if not v:
            raise GTIConfigurationError(
                "At least one indicator type must be specified."
            )
        invalid = set(v) - set(ALLOWED_IOC_TYPES)
        if invalid:
            raise GTIConfigurationError(
                f"Invalid indicator type(s): {', '.join(invalid)}. "
                f"Allowed values: {', '.join(ALLOWED_IOC_TYPES)}."
            )
        return v
