"""Unit tests for ``lib.sanitization.sanitize_cell``.

The function is the primary defence against spreadsheet / formula
injection. These tests pin the contract:

* ``None`` and non-string inputs are coerced safely (no ``TypeError``);
* leading control characters (``\\t``, ``\\r``, ``\\n``) are stripped;
* leading formula triggers (``=``, ``+``, ``-``, ``@``) are escaped as
  ``[<char>]…`` so spreadsheet applications stop interpreting the cell
  as a formula;
* "safe" characters in the middle of the string are not touched.
"""

import pytest
from lib.sanitization import (
    FORMULA_TRIGGERS,
    LEADING_CONTROL_CHARS,
    sanitize_cell,
)


class TestSanitizeCellNonStrings:
    """``sanitize_cell`` must coerce non-string inputs safely."""

    def test_none_returns_empty_string(self):
        assert sanitize_cell(None) == ""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, "0"),
            (42, "42"),
            (-7, "[-]7"),  # leading "-" comes out of str(-7) and must be escaped
            (3.14, "3.14"),
            (-3.14, "[-]3.14"),
            (True, "True"),
            (False, "False"),
        ],
    )
    def test_numbers_and_booleans_are_coerced(self, value, expected):
        assert sanitize_cell(value) == expected

    def test_list_input_is_coerced_via_str(self):
        # ``sanitize_cell`` does not flatten containers — it only guarantees
        # a string output. Worst case the leading ``[`` from ``str([...])``
        # appears unchanged, which is harmless in a spreadsheet cell.
        assert sanitize_cell(["a", "b"]) == "['a', 'b']"


class TestSanitizeCellLeadingControlCharacters:
    """Leading ``\\t`` / ``\\r`` / ``\\n`` must be stripped."""

    @pytest.mark.parametrize("ctrl", LEADING_CONTROL_CHARS)
    def test_single_leading_control_char_is_stripped(self, ctrl):
        assert sanitize_cell(f"{ctrl}hello") == "hello"

    def test_multiple_leading_control_chars_are_all_stripped(self):
        assert sanitize_cell("\t\r\n\t hello") == " hello"

    def test_middle_control_char_is_preserved(self):
        # Only *leading* control chars are stripped — preserving the rest
        # avoids destroying user-provided whitespace inside the value.
        assert sanitize_cell("hello\tworld") == "hello\tworld"

    def test_leading_control_then_formula_trigger_is_both_stripped_and_escaped(self):
        # Strip the tab first, then escape the now-leading ``=``.
        assert sanitize_cell("\t=SUM(A1:A2)") == "[=]SUM(A1:A2)"


class TestSanitizeCellFormulaInjection:
    """Leading ``=`` / ``+`` / ``-`` / ``@`` must be escaped."""

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("=SUM(A1:A2)", "[=]SUM(A1:A2)"),
            ("+1+1", "[+]1+1"),
            ("-1", "[-]1"),
            ("@SUM(1,2)", "[@]SUM(1,2)"),
            ("=", "[=]"),
        ],
    )
    def test_formula_triggers_are_escaped(self, raw, expected):
        assert sanitize_cell(raw) == expected

    @pytest.mark.parametrize("trigger", FORMULA_TRIGGERS)
    def test_every_documented_trigger_is_escaped(self, trigger):
        assert sanitize_cell(f"{trigger}payload") == f"[{trigger}]payload"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("hello", "hello"),
            ("1=2", "1=2"),
            ("a-b", "a-b"),
            ("user@example.com", "user@example.com"),
            ("", ""),
        ],
    )
    def test_safe_values_are_returned_as_is(self, raw, expected):
        assert sanitize_cell(raw) == expected
