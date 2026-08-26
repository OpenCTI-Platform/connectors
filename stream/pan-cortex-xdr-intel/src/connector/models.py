from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class OctiIndicatorObservable(BaseModel):
    """A single observable extracted from an Indicator's `observable_values`."""

    type: str
    # For all observable types but `StixFile`
    value: str | None = Field(default=None)
    # For `StixFile` observables only
    name: str | None = Field(default=None)
    hashes: dict[str, str] | None = Field(default=None)


class OctiIndicator(BaseModel):
    """Minimal, internal representation of an Indicator's stream `data` payload."""

    id: str
    description: str | None = Field(default=None)
    observables: list[OctiIndicatorObservable] = Field(default_factory=list)
    valid_until: datetime | None = Field(default=None)
    score: int | None = Field(default=None)

    @field_validator("observables", mode="before")
    def _validate_observables(
        cls, value: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]]:
        """Extract `observables` from the raw `observable_values` list returned by
        `pycti.OpenCTIConnectorHelper.get_attribute_in_extension("observable_values", indicator)`.
        """
        if not value:
            return []

        observables = []
        for observable_data in value:
            observable_type = str(observable_data.get("type", ""))
            if observable_type.lower() == "stixfile":
                name = observable_data.get("name") or None
                hashes = observable_data.get("hashes") or None
                if name or hashes:
                    observables.append(
                        {
                            "type": observable_type,
                            "name": name,
                            "hashes": hashes,
                        }
                    )
            elif observable_value := observable_data.get("value"):
                observables.append(
                    {
                        "type": observable_type,
                        "value": observable_value,
                    }
                )

        return observables

    @field_validator("valid_until", mode="after")
    def _validate_valid_until(cls, value: datetime | None) -> datetime | None:
        """Convert naive or aware datetime to UTC."""
        if not value:
            return None

        if value.tzinfo:
            return value.astimezone(tz=timezone.utc)
        else:
            return value.replace(tzinfo=timezone.utc)


class CortexXdrIoc(BaseModel):
    """Cortex XDR Indicator of Compromise (IOC) model.

    Field constraints intentionally mirror `cortex_xdr_client.types.IndicatorPayload`
    that represent Cortex XDR API expected data.
    """

    # Existing IOC's Cortex XDR ID if known (update of an existing IOC), otherwise `None` (new IOC).
    rule_id: int | None = Field(default=None)

    indicator: str
    type: Literal["HASH", "IP", "PATH", "DOMAIN_NAME", "FILENAME", "MIXED"]
    severity: (
        Literal["SEV_010_INFO", "SEV_020_LOW", "SEV_030_MEDIUM", "SEV_040_HIGH"] | None
    ) = Field(default=None)
    expiration_date: int | None = Field(default=None)
    comment: str | None = Field(default=None)
    reputation: (
        Literal["GOOD", "BAD", "SUSPICIOUS", "UNKNOWN", "NO_REPUTATION"] | None
    ) = Field(default=None)
    reliability: Literal["A", "B", "C", "D"] | None = Field(default=None)
