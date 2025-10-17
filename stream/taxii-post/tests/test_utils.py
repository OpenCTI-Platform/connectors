import pytest
from src.main import parse_version


@pytest.mark.parametrize(
    "ver, expected",
    [
        ("2", (2, 0, 0)),
        ("2.1", (2, 1, 0)),
        ("2.1.3", (2, 1, 3)),
        ("v2.1", (2, 1, 0)),
        ("  2.1  ", (2, 1, 0)),
        ("02.03.004", (2, 3, 4)),
        ("2.0-beta1", (2, 0, 1)),
        ("version 10.20.30", (10, 20, 30)),
        ("2-1-3", (2, 1, 3)),
        (2, (2, 0, 0)),  # non-string input is coerced via str()
    ],
)
def test_parse_version_valid_cases(ver, expected):
    assert parse_version(ver) == expected


def test_parse_version_ignores_extra_components():
    # Extra numeric parts beyond patch are ignored
    assert parse_version("1.2.3.4") == (1, 2, 3)
    assert parse_version("2.0.0-rc1") == (2, 0, 0)


@pytest.mark.parametrize("ver", ["", "alpha", None])
def test_parse_version_invalid_inputs(ver):
    with pytest.raises(ValueError):
        parse_version(ver)
