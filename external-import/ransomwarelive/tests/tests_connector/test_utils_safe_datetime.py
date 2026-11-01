from datetime import datetime

import pytest
from ransomwarelive.utils import safe_datetime


def test_parses_valid_datetime_string():
    assert safe_datetime("2025-01-01 07:20:50.000000") == datetime(
        2025, 1, 1, 7, 20, 50, 0
    )


@pytest.mark.parametrize("value", [None, "", "invalid-date", "2025-13-45"])
def test_returns_none_for_missing_or_invalid_value(value):
    """The documented contract: invalid or missing input gives None, never raises."""
    assert safe_datetime(value) is None
