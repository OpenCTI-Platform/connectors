from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IndicatorObservable(BaseModel):
    """A single observable extracted from an Indicator's `observable_values`."""

    model_config = ConfigDict(frozen=True)

    type: str
    value: str


class EventIndicator(BaseModel):
    """Minimal, internal representation of an Indicator's stream `data` payload.

    This is a plain data carrier meant to decouple downstream handlers
    (upsert/delete) from the raw OpenCTI STIX payload shape. Only `data` is
    represented here: the stream action (create/update/delete) is a separate,
    stream-level concern and is passed alongside this event, not stored on it.
    Fields are cast/validated by pydantic to fail fast and minimize downstream
    development/runtime errors.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    description: str | None = Field(default=None)
    observables: list[IndicatorObservable] = Field(default_factory=list)
    valid_until: datetime | None = Field(default=None)
    score: int | None = Field(default=None)

    @field_validator("observables", mode="before")
    def _validate_observables(
        cls, value: list[dict[str, Any]] | None
    ) -> list[dict[str, Any]]:
        """Extract `observables` from the raw `observable_values` list returned by
        `pycti.OpenCTIConnectorHelper.get_attribute_in_extension("observable_values", indicator)`.

        For `StixFile` observables, the filename (`name`) and each hash
        algorithm value are extracted as separate observables, since Cortex
        XDR treats them as distinct IOC types (`FILENAME` vs `HASH`).
        """
        if not value:
            return []

        observables = []
        for observable_data in value:
            observable_type = str(observable_data.get("type", ""))
            if observable_type.lower() == "stixfile":
                if name := observable_data.get("name"):
                    observables.append({"type": observable_type, "value": str(name)})
                for value in (observable_data.get("hashes") or {}).values():
                    observables.append({"type": observable_type, "value": str(value)})
            elif value := observable_data.get("value"):
                observables.append({"type": observable_type, "value": str(value)})

        return observables
