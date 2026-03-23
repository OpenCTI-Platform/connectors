"""Unit tests for connector utility functions."""

# pylint: disable=missing-function-docstring,missing-class-docstring,too-few-public-methods

from connector.utils import iso_now, safe_get


class TestIsoNow:
    def test_returns_utc_string(self):
        result = iso_now()
        assert result.endswith("Z")
        assert "T" in result


class TestSafeGet:
    def test_single_key(self):
        assert safe_get({"a": 1}, "a") == 1

    def test_nested_keys(self):
        assert safe_get({"a": {"b": {"c": 3}}}, "a", "b", "c") == 3

    def test_missing_key(self):
        assert safe_get({"a": 1}, "b") is None

    def test_missing_key_with_default(self):
        assert safe_get({"a": 1}, "b", default=42) == 42

    def test_none_intermediate(self):
        assert safe_get({"a": None}, "a", "b") is None

    def test_non_dict_intermediate(self):
        assert safe_get({"a": "string"}, "a", "b") is None

    def test_empty_dict(self):
        assert safe_get({}, "a", default="x") == "x"
