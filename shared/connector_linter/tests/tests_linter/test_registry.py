"""Tests for the CheckRegistry: select/ignore filtering and prefix matching."""

from connector_linter.registry import CheckRegistry


class TestGetByPrefix:
    """CheckRegistry.get_by_prefix() strips trailing 'x' chars and prefix-matches."""

    def test_exact_code(self, dummy_checks):
        result = CheckRegistry.get_by_prefix("VC901")
        assert list(result.keys()) == ["VC901"]

    def test_category_prefix(self, dummy_checks):
        result = CheckRegistry.get_by_prefix("VC9")
        assert sorted(result.keys()) == ["VC901", "VC902", "VC903"]

    def test_xx_suffix_stripped(self, dummy_checks):
        # "VC9xx" → prefix "VC9" → matches all VC9* codes
        result = CheckRegistry.get_by_prefix("VC9xx")
        assert sorted(result.keys()) == ["VC901", "VC902", "VC903"]

    def test_no_match(self, dummy_checks):
        result = CheckRegistry.get_by_prefix("VC0")
        assert result == {}

    def test_partial_prefix(self, dummy_checks):
        result = CheckRegistry.get_by_prefix("VC90")
        assert sorted(result.keys()) == ["VC901", "VC902", "VC903"]


class TestGetAll:
    def test_returns_copy(self, dummy_checks):
        a = CheckRegistry.get_all()
        b = CheckRegistry.get_all()
        assert a is not b
        assert a.keys() == b.keys()
