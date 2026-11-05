from datetime import datetime

import pytest
from alienvault.utils import iso_datetime_str_to_datetime


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2020-05-01T00:00:00", datetime(2020, 5, 1)),
        ("2020-05-01T00:00:00Z", datetime(2020, 5, 1)),
        ("2020-05-01T00:00:00.123456", datetime(2020, 5, 1, 0, 0, 0, 123456)),
        ("2020-05-01T00:00:00.123456Z", datetime(2020, 5, 1, 0, 0, 0, 123456)),
    ],
)
def test_iso_datetime_str_to_datetime(value, expected):
    result = iso_datetime_str_to_datetime(value)

    assert result == expected
    # Must stay naive: it is compared with naive pulse "modified" datetimes.
    assert result.tzinfo is None


def test_iso_datetime_str_to_datetime_parses_default_pulse_start_timestamp():
    from alienvault.settings import AlienvaultConfig

    default = AlienvaultConfig.model_fields["pulse_start_timestamp"].default

    assert iso_datetime_str_to_datetime(default) == datetime(2020, 5, 1)
