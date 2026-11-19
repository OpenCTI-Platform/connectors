"""Tests for the source-independent connector CLI."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from crowdstrike_indicators.entities.stix import CrowdStrikeStix2Indicator
from pydantic import BaseModel, Field
from stix2.v21 import Bundle, Indicator, Malware

from shared.cli import to_json

CREATED = datetime(2023, 11, 14, 22, 13, 21, tzinfo=UTC)


def _dump(value: Any) -> Any:
    return json.loads(json.dumps(value, default=to_json))


# JSON form of returned values


def _indicator() -> Indicator:
    return Indicator(
        pattern="[domain-name:value = 'host.example']",
        pattern_type="stix",
        created=CREATED,
        modified=CREATED,
        valid_from=CREATED,
    )


def test_stix_object_is_its_stix_json():
    indicator = _indicator()

    dumped = _dump(indicator)

    assert dumped["type"] == "indicator"
    assert dumped["id"] == indicator.id
    assert dumped["created"] == "2023-11-14T22:13:21.000Z"


def test_custom_stix_object_and_bundle_are_stix_json():
    custom = CrowdStrikeStix2Indicator(
        pattern="[domain-name:value = 'host.example']",
        pattern_type="stix",
        valid_from=CREATED,
        x_crowdstrike_extra={"source": "test"},
    )
    bundle = Bundle(objects=[custom], allow_custom=True)

    assert _dump(custom)["x_crowdstrike_extra"] == {"source": "test"}
    dumped = _dump(bundle)
    assert dumped["type"] == "bundle"
    assert dumped["objects"][0]["id"] == custom.id


class Aliased(BaseModel):
    marker: str = Field(alias="_marker")
    tags: list[str] = Field(default_factory=list)


def test_model_is_dumped_by_alias_with_its_defaults():
    assert _dump(Aliased(_marker="m-1")) == {"_marker": "m-1", "tags": []}


@dataclass(frozen=True)
class Holder:
    indicator: Indicator
    malware: list[Malware]


def test_dataclass_is_its_fields_with_nested_values_converted():
    indicator = _indicator()
    malware = Malware(name="ExampleFamily4", is_family=True)

    dumped = _dump(Holder(indicator, [malware]))

    assert list(dumped) == ["indicator", "malware"]
    assert dumped["indicator"]["id"] == indicator.id
    assert dumped["malware"][0]["name"] == "ExampleFamily4"


def test_datetime_keeps_its_offset():
    paris = timezone(timedelta(hours=1))

    assert _dump(datetime(2026, 11, 1, 12, tzinfo=paris)) == "2026-11-01T12:00:00+01:00"


def test_unsupported_value_raises_naming_its_type():
    with pytest.raises(TypeError, match="object"):
        json.dumps(object(), default=to_json)


def test_dataclass_class_itself_is_not_converted():
    with pytest.raises(TypeError, match="type"):
        json.dumps(Holder, default=to_json)
