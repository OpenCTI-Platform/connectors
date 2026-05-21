"""Tests for the CheckRegistry."""

from connector_linter.registry import CheckRegistry


class TestGetByPrefix:
    def test_exact_code(self, dummy_checks):
        assert list(CheckRegistry.get_by_prefix("VC901").keys()) == ["VC901"]

    def test_category_prefix(self, dummy_checks):
        assert sorted(CheckRegistry.get_by_prefix("VC9").keys()) == [
            "VC901",
            "VC902",
            "VC903",
        ]

    def test_xx_suffix_stripped(self, dummy_checks):
        assert sorted(CheckRegistry.get_by_prefix("VC9xx").keys()) == [
            "VC901",
            "VC902",
            "VC903",
        ]

    def test_no_match(self, dummy_checks):
        assert CheckRegistry.get_by_prefix("VC0") == {}

    def test_partial_prefix(self, dummy_checks):
        assert sorted(CheckRegistry.get_by_prefix("VC90").keys()) == [
            "VC901",
            "VC902",
            "VC903",
        ]


class TestGetAll:
    def test_returns_copy(self, dummy_checks):
        a = CheckRegistry.get_all()
        b = CheckRegistry.get_all()
        assert a is not b
        assert a.keys() == b.keys()
