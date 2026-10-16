import re
from datetime import datetime, timedelta, timezone

import freezegun
import pytest
from connectors_sdk.settings.annotated_types import (
    ISO_DATETIME_OR_DURATION_PATTERN,
    DatetimeFromIsoString,
    ListFromString,
    parse_comma_separated_list,
    parse_iso_string,
)
from pydantic import BaseModel, Field, TypeAdapter

# ListFromString


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            "a,b,c",
            ["a", "b", "c"],
            id="comma_separated_list",
        ),
        pytest.param(
            "a, b  , c",
            ["a", "b", "c"],
            id="comma_separated_list_with_whitespaces",
        ),
        pytest.param(
            "",
            [],
            id="empty_string",  # empty string -> empty list
        ),
        pytest.param(
            "a, ,c",
            ["a", "c"],
            id="blank_item_between_commas",
        ),
        pytest.param(
            "a,,c",
            ["a", "c"],
            id="consecutive_commas",
        ),
        pytest.param(
            ",a,",
            ["a"],
            id="leading_and_trailing_commas",
        ),
    ],
)
def test_parse_comma_separated_list_handles_string(
    input: str, expected: list[str]
) -> None:
    assert parse_comma_separated_list(input) == expected


def test_parse_comma_separated_list_passthrough() -> None:
    assert parse_comma_separated_list(["a", "b"]) == ["a", "b"]


def test_list_from_string_accepts_string_input() -> None:
    value = TypeAdapter(ListFromString).validate_python("a,b,c")
    assert value == ["a", "b", "c"]


def test_list_from_string_accepts_list_input() -> None:
    value = TypeAdapter(ListFromString).validate_python(["a", "b"])
    assert value == ["a", "b"]


def test_list_from_string_discards_empty_items() -> None:
    value = TypeAdapter(ListFromString).validate_python("scope1, ,scope3")
    assert value == ["scope1", "scope3"]


def test_list_from_string_dumps_valid_json() -> None:
    value = TypeAdapter(ListFromString).dump_python(["a", "b"], mode="json")
    assert value == ["a", "b"]


# DatetimeFromIsoString


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            "2023-10-01",
            datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc),
            id="iso_date",
        ),
        pytest.param(
            "2023-10-01T12:30",
            datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc),
            id="iso_datetime",
        ),
        pytest.param(
            "2023-10-01T12:30+02:00",
            datetime(2023, 10, 1, 10, 30, tzinfo=timezone.utc),
            id="iso_datetime_with_timezone",
        ),
        pytest.param(
            "P30D",
            datetime(2023, 9, 1, 12, 30, tzinfo=timezone.utc),
            id="iso_duration",
        ),
        pytest.param(
            "PT5M",
            datetime(2023, 10, 1, 12, 25, tzinfo=timezone.utc),
            id="iso_time_duration",
        ),
    ],
)
@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_parse_iso_string_handles_string(input: str, expected: list[str]) -> None:
    assert parse_iso_string(input) == expected


def test_parse_iso_string_passthrough() -> None:
    assert parse_iso_string(
        datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc)
    ) == datetime(2023, 10, 1, 0, 0, tzinfo=timezone.utc)


def test_datetime_isoformat_handles_any_mode() -> None:
    value = datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)
    assert value.isoformat() == "2023-10-01T12:30:00+00:00"


def test_datetime_from_iso_string_accepts_string_input() -> None:
    value = TypeAdapter(DatetimeFromIsoString).validate_python("2023-10-01T12:30")
    assert value == datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)


def test_datetime_from_iso_string_accepts_datetime_input() -> None:
    value = TypeAdapter(DatetimeFromIsoString).validate_python(
        datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)
    )
    assert value == datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc)


def test_datetime_from_iso_string_dumps_valid_json() -> None:
    value = TypeAdapter(DatetimeFromIsoString).dump_python(
        datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc), mode="json"
    )
    assert value == "2023-10-01T12:30:00+00:00"


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            datetime(2023, 10, 1, 12, 30, tzinfo=timezone.utc),
            "2023-10-01T12:30:00+00:00",
            id="datetime",
        ),
        pytest.param(
            datetime(2023, 10, 1, 10, 30, tzinfo=timezone(timedelta(hours=2))),
            "2023-10-01T10:30:00+02:00",
            id="datetime_with_timezone",
        ),
    ],
)
def test_datetime_from_iso_string_dumps_valid_json_in_pycti_mode(
    input: list[str], expected: str
) -> None:
    value = TypeAdapter(DatetimeFromIsoString).dump_python(
        input, mode="json", context={"mode": "pycti"}
    )
    assert value == expected


def test_datetime_from_iso_string_json_schema_has_iso_pattern_without_format() -> None:
    schema = TypeAdapter(DatetimeFromIsoString).json_schema()

    assert schema == {"type": "string", "pattern": ISO_DATETIME_OR_DURATION_PATTERN}


@pytest.mark.parametrize(
    "value",
    [
        "2023-10-01",
        "2023-10-01T12:30",
        "2023-10-01T12:30:00.123456",
        "2023-10-01T12:30:00Z",
        "2023-10-01T12:30:00+02:00",
        "2023-10-01 12:30:00",
        "P30D",
        "P1Y",
        "P4W",
        "P1Y2M3DT4H5M6S",
        "PT1.5S",
    ],
)
def test_iso_pattern_matches_values_accepted_at_runtime(value: str) -> None:
    assert re.match(ISO_DATETIME_OR_DURATION_PATTERN, value)
    assert isinstance(parse_iso_string(value), datetime)


@pytest.mark.parametrize(
    "value",
    ["", "P", "PT", "P1DT", "P1H", "30D", "2023-10", "2023/10/01", "yesterday"],
)
def test_iso_pattern_rejects_non_iso_values(value: str) -> None:
    assert re.match(ISO_DATETIME_OR_DURATION_PATTERN, value) is None


@freezegun.freeze_time("2023-10-01T12:30:00Z")
def test_datetime_from_iso_string_duration_default_is_kept_in_json_schema() -> None:
    class Model(BaseModel):
        start_date: DatetimeFromIsoString = Field(default="P30D", validate_default=True)

    schema = Model.model_json_schema()["properties"]["start_date"]

    assert schema["default"] == "P30D"
    assert Model().start_date == datetime(2023, 9, 1, 12, 30, tzinfo=timezone.utc)
