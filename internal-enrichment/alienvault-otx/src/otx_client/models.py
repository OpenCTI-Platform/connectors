"""Typed models of the AlienVault OTX `general` indicator response.

- `OtxGeneral`: `GET /api/v1/indicators/<IPv4|domain|url>/<value>/general`.
- `OtxPulseInfo`: its `pulse_info` block, the pulses that contain the indicator.
- `OtxPulse`: one pulse of `pulse_info.pulses`.

Quirks observed on the live API, handled here so that callers get clean values:

- An unknown indicator is still a 200 answer: `pulse_info.count` is 0 and
  `pulses` is empty. Only the models are lenient, the caller decides what "known" means.
- Only IPv4 answers have `reputation` and the geolocation keys (`city`, `region`,
  `country_name`, `country_code`, `latitude`, `longitude`, `asn`), and only when OTX
  has them. Absent, `null` and empty string all become `None`. An unreadable
  `reputation` (`"bad"`, `0.5`, an object...) becomes `None` too.
- `created` and `modified` are ISO 8601 strings without a timezone
  (`2018-02-10T00:36:00.396000`). They are UTC and become timezone-aware datetimes.
  An unreadable date, or one that overflows once converted to UTC, becomes `None`.
- `pulse_info.pulses` items that are not objects (`null`...) are dropped.
- List fields can be `null` or hold empty or non-string items: `null` becomes `[]`,
  items are stripped, unreadable or empty ones are dropped, duplicates removed in order.
- `tags` and `industries` items can hold several values joined by a comma
  (`"webscanner, bruteforce, web app attack"`, `"Legal, Financial, Healthcare"`): they
  are split. `targeted_countries` are country names that contain a comma
  (`"Tanzania, United Republic of"`): they are never split.
- `malware_families` items are objects (`{"id", "display_name", "target"}`) and
  become their `display_name`, or their `id` when it is missing. `attack_ids` items
  are objects (`{"id", "name", "display_name"}`) and become their `id` (`T1027`).
  A plain string is accepted for both.
- `adversary` is a string, often empty: an empty value becomes `None`.
- Unknown fields are ignored.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _OtxModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, populate_by_name=True)


def _clean_text(value: Any) -> str | None:
    """Return the stripped string, `None` when empty or not a string."""
    if not isinstance(value, str):
        return None
    return value.strip() or None


def _as_list(value: Any) -> list[Any]:
    """Return the items of a list-like value, `[]` for `null` or unreadable values."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return []


def _dedupe(items: list[str | None]) -> list[str]:
    """Drop empty items and duplicates, keeping the first occurrence order."""
    return list(dict.fromkeys(item for item in items if item))


def _clean_strings(value: Any, *, split_commas: bool = False) -> list[str]:
    items: list[str | None] = []
    for item in _as_list(value):
        text = _clean_text(item)
        if text is None:
            continue
        if split_commas:
            items.extend(_clean_text(part) for part in text.split(","))
        else:
            items.append(text)
    return _dedupe(items)


def _clean_named(value: Any, *keys: str) -> list[str]:
    """Clean a list of strings or objects, reading the first usable key of an object."""
    items: list[str | None] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            items.append(
                next((t for k in keys if (t := _clean_text(item.get(k)))), None)
            )
        else:
            items.append(_clean_text(item))
    return _dedupe(items)


class OtxPulse(_OtxModel):
    """An OTX pulse that contains the indicator."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    created: datetime | None = Field(default=None, description="UTC, timezone-aware.")
    modified: datetime | None = Field(default=None, description="UTC, timezone-aware.")
    tlp: str | None = Field(
        default=None,
        alias="TLP",
        description="TLP chosen by the pulse author (`white`, `green`...).",
    )
    adversary: str | None = None
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(
        default_factory=list, description="Display names of the malware families."
    )
    attack_ids: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs (`T1027`)."
    )
    industries: list[str] = Field(default_factory=list)
    targeted_countries: list[str] = Field(
        default_factory=list, description="Country names, never split on commas."
    )

    @field_validator("id", mode="before")
    @classmethod
    def _id_to_str(cls, value: Any) -> str | None:
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return _clean_text(value)

    @field_validator("name", "description", "tlp", "adversary", mode="before")
    @classmethod
    def _empty_text_to_none(cls, value: Any) -> str | None:
        return _clean_text(value)

    @field_validator("created", "modified", mode="before")
    @classmethod
    def _to_utc(cls, value: Any) -> datetime | None:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value.strip():
            try:
                parsed = datetime.fromisoformat(value.strip())
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        try:
            return parsed.astimezone(timezone.utc)
        except (OverflowError, ValueError):
            # An extreme date does not fit once converted to UTC
            return None

    @field_validator("tags", "industries", mode="before")
    @classmethod
    def _split_strings(cls, value: Any) -> list[str]:
        return _clean_strings(value, split_commas=True)

    @field_validator("targeted_countries", mode="before")
    @classmethod
    def _keep_strings(cls, value: Any) -> list[str]:
        return _clean_strings(value)

    @field_validator("malware_families", mode="before")
    @classmethod
    def _malware_names(cls, value: Any) -> list[str]:
        return _clean_named(value, "display_name", "id")

    @field_validator("attack_ids", mode="before")
    @classmethod
    def _attack_ids(cls, value: Any) -> list[str]:
        return _clean_named(value, "id")


class OtxPulseInfo(_OtxModel):
    """The pulses that contain the indicator."""

    count: int = Field(default=0, description="Number of pulses, 0 when unknown.")
    pulses: list[OtxPulse] = Field(default_factory=list)

    @property
    def is_known(self) -> bool:
        """Whether OTX knows the indicator: at least one pulse contains it."""
        return self.count > 0

    @field_validator("count", mode="before")
    @classmethod
    def _null_count_to_zero(cls, value: Any) -> Any:
        return 0 if value is None else value

    @field_validator("pulses", mode="before")
    @classmethod
    def _keep_pulse_objects(cls, value: Any) -> Any:
        """Drop the items that are not objects (`null`...), `null` becomes `[]`.

        Anything but a list is left to the validation, which rejects it.
        """
        if value is None:
            return []
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        return value


class OtxGeneral(_OtxModel):
    """The `general` section of an OTX indicator."""

    indicator: str | None = None
    type: str | None = Field(default=None, description="`IPv4`, `domain`, `URL`...")
    reputation: int | None = Field(
        default=None, description="Only present for IPv4 addresses."
    )
    city: str | None = None
    region: str | None = None
    country_name: str | None = None
    pulse_info: OtxPulseInfo = Field(default_factory=OtxPulseInfo)

    @field_validator(
        "indicator", "type", "city", "region", "country_name", mode="before"
    )
    @classmethod
    def _empty_text_to_none(cls, value: Any) -> str | None:
        return _clean_text(value)

    @field_validator("reputation", mode="before")
    @classmethod
    def _unreadable_reputation_to_none(cls, value: Any) -> int | None:
        """Keep an integer (or a whole number, or its text), else `None`."""
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value) if value.is_integer() else None
        if isinstance(value, str):
            try:
                return int(value.strip())
            except ValueError:
                return None
        return None

    @field_validator("pulse_info", mode="before")
    @classmethod
    def _null_pulse_info_to_empty(cls, value: Any) -> Any:
        return {} if value is None else value
