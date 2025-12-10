import pytest
from connectors_sdk.core.pydantic import parse_comma_separated_list


@pytest.mark.parametrize(
    "value,expected",
    [
        ("a,b,c", ["a", "b", "c"]),
        ("a, b , c", ["a", "b", "c"]),
        ("  a ,  b  ", ["a", "b"]),
        ("", []),  # empty string -> empty list
    ],
)
def test_environ_list_validator_string_inputs(value: str, expected: list[str]) -> None:
    assert parse_comma_separated_list(value) == expected


def test_environ_list_validator_list_passthrough() -> None:
    assert parse_comma_separated_list(["x", "y"]) == ["x", "y"]
