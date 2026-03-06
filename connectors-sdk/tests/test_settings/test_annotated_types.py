from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import freezegun
import pytest
from connectors_sdk.settings.annotated_types import (
    DatetimeFromIsoString,
    ListFromString,
    parse_comma_separated_list,
    parse_iso_string,
    serialize_list_of_strings,
)
from pydantic import TypeAdapter

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
    ],
)
def test_parse_comma_separated_list_handles_string(
    input: str, expected: list[str]
) -> None:
    assert parse_comma_separated_list(input) == expected


def test_parse_comma_separated_list_passthrough() -> None:
    assert parse_comma_separated_list(["a", "b"]) == ["a", "b"]


def test_serialize_list_of_strings_handles_pycti_mode() -> None:
    info = SimpleNamespace(context={"mode": "pycti"})
    assert serialize_list_of_strings(["a", "b"], info) == "a,b"


@pytest.mark.parametrize("context", [None, {}, {"mode": "other"}])
def test_serialize_list_of_strings_handles_non_pycti_modes(
    context: dict[str, str] | None,
) -> None:
    info = SimpleNamespace(context=context)
    value = ["a", "b"]
    assert serialize_list_of_strings(value, info) == value


def test_list_from_string_accepts_string_input() -> None:
    value = TypeAdapter(ListFromString).validate_python("a,b,c")
    assert value == ["a", "b", "c"]


def test_list_from_string_accepts_list_input() -> None:
    value = TypeAdapter(ListFromString).validate_python(["a", "b"])
    assert value == ["a", "b"]


def test_list_from_string_dumps_valid_json() -> None:
    value = TypeAdapter(ListFromString).dump_python(["a", "b"], mode="json")
    assert value == ["a", "b"]


@pytest.mark.parametrize(
    "input,expected",
    [
        pytest.param(
            ["a", "b", "c"],
            "a,b,c",
            id="list_of_strings",
        ),
        pytest.param(
            [],
            "",
            id="empty_list",
        ),  # empty list -> empty string
    ],
)
def test_list_from_string_dumps_valid_json_in_pycti_mode(
    input: list[str], expected: str
) -> None:
    value = TypeAdapter(ListFromString).dump_python(
        input, mode="json", context={"mode": "pycti"}
    )
    assert value == expected


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
