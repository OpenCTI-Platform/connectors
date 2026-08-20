"""Tests for Severity and Priority StrEnum ordering and coercion."""

from google_secops_siem_incidents.utils.enums import Priority, Severity


# ---------------------------------------------------------------------------
# Severity — ordering
# ---------------------------------------------------------------------------
class TestSeverityOrdering:
    def test_critical_is_greater_than_high(self):
        assert Severity.CRITICAL > Severity.HIGH

    def test_high_is_greater_than_or_equal_to_high(self):
        assert Severity.HIGH >= Severity.HIGH

    def test_low_is_less_than_medium(self):
        assert Severity.LOW < Severity.MEDIUM

    def test_info_is_less_than_or_equal_to_low(self):
        assert Severity.INFO <= Severity.LOW

    def test_medium_is_less_than_or_equal_to_medium(self):
        assert Severity.MEDIUM <= Severity.MEDIUM

    def test_high_is_not_less_than_low(self):
        assert not Severity.HIGH < Severity.LOW

    def test_info_is_not_greater_than_critical(self):
        assert not Severity.INFO > Severity.CRITICAL


# ---------------------------------------------------------------------------
# Severity — coercion
# ---------------------------------------------------------------------------
class TestSeverityCoercion:
    def test_coerce_from_severity_instance(self):
        assert Severity._coerce(Severity.HIGH) == Severity.HIGH

    def test_coerce_from_string(self):
        assert Severity._coerce("medium") == Severity.MEDIUM

    def test_coerce_from_uppercase_string(self):
        assert Severity._coerce("CRITICAL") == Severity.CRITICAL

    def test_coerce_returns_none_for_invalid_string(self):
        assert Severity._coerce("unknown") is None

    def test_coerce_returns_none_for_non_string(self):
        assert Severity._coerce(42) is None


# ---------------------------------------------------------------------------
# Severity — comparison with non-Severity returns NotImplemented
# ---------------------------------------------------------------------------
class TestSeverityNotImplemented:
    def test_ge_returns_not_implemented_for_invalid(self):
        assert Severity.HIGH.__ge__(42) is NotImplemented

    def test_gt_returns_not_implemented_for_invalid(self):
        assert Severity.HIGH.__gt__(42) is NotImplemented

    def test_le_returns_not_implemented_for_invalid(self):
        assert Severity.HIGH.__le__(42) is NotImplemented

    def test_lt_returns_not_implemented_for_invalid(self):
        assert Severity.HIGH.__lt__(42) is NotImplemented


# ---------------------------------------------------------------------------
# Priority — ordering
# ---------------------------------------------------------------------------
class TestPriorityOrdering:
    def test_critical_is_greater_than_high(self):
        assert Priority.CRITICAL > Priority.HIGH

    def test_high_is_greater_than_or_equal_to_high(self):
        assert Priority.HIGH >= Priority.HIGH

    def test_low_is_less_than_medium(self):
        assert Priority.LOW < Priority.MEDIUM

    def test_info_is_less_than_or_equal_to_low(self):
        assert Priority.INFO <= Priority.LOW

    def test_medium_is_less_than_or_equal_to_medium(self):
        assert Priority.MEDIUM <= Priority.MEDIUM

    def test_high_is_not_less_than_low(self):
        assert not Priority.HIGH < Priority.LOW

    def test_info_is_not_greater_than_critical(self):
        assert not Priority.INFO > Priority.CRITICAL


# ---------------------------------------------------------------------------
# Priority — coercion
# ---------------------------------------------------------------------------
class TestPriorityCoercion:
    def test_coerce_from_priority_instance(self):
        assert Priority._coerce(Priority.HIGH) == Priority.HIGH

    def test_coerce_from_string(self):
        assert Priority._coerce("medium") == Priority.MEDIUM

    def test_coerce_from_uppercase_string(self):
        assert Priority._coerce("CRITICAL") == Priority.CRITICAL

    def test_coerce_returns_none_for_invalid_string(self):
        assert Priority._coerce("unknown") is None

    def test_coerce_returns_none_for_non_string(self):
        assert Priority._coerce(42) is None


# ---------------------------------------------------------------------------
# Priority — comparison with non-Priority returns NotImplemented
# ---------------------------------------------------------------------------
class TestPriorityNotImplemented:
    def test_ge_returns_not_implemented_for_invalid(self):
        assert Priority.HIGH.__ge__(42) is NotImplemented

    def test_gt_returns_not_implemented_for_invalid(self):
        assert Priority.HIGH.__gt__(42) is NotImplemented

    def test_le_returns_not_implemented_for_invalid(self):
        assert Priority.HIGH.__le__(42) is NotImplemented

    def test_lt_returns_not_implemented_for_invalid(self):
        assert Priority.HIGH.__lt__(42) is NotImplemented
