import pytest
from lib.log_level import normalize_connector_log_level


@pytest.mark.parametrize(
    ("raw_value", "expected_value"),
    [
        ("info", "info"),
        ('"INFO"', "INFO"),
        ("'INFO'", "INFO"),
        ('  "INFO"  ', "INFO"),
        ("  ' info '  ", "info"),
        ('""', ""),
        ("''", ""),
        ("  ", ""),
    ],
)
def test_normalize_connector_log_level(raw_value: str, expected_value: str):
    assert normalize_connector_log_level(raw_value) == expected_value
