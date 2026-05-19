"""Spreadsheet cell sanitisation helpers.

This module is intentionally dependency-free (no ``unogenerator`` / no
``pycti``) so the ``sanitize_cell`` defence against formula and
control-character injection can be unit-tested without LibreOffice
being available on the CI runner.
"""

from typing import Any

# Leading control characters are stripped to mitigate spreadsheet injection
# that abuses tab / carriage-return separators.
LEADING_CONTROL_CHARS = ("\t", "\r", "\n")
# Pre-joined form used by :func:`sanitize_cell` so the leading-control-char
# strip is a single C-level pass instead of a quadratic Python loop on
# values with many leading control characters.
_LEADING_CONTROL_CHARS_STR = "".join(LEADING_CONTROL_CHARS)

# Leading ``=``/``+``/``-``/``@`` are escaped with ``[<char>]`` so spreadsheet
# applications do not interpret the cell as a formula.
FORMULA_TRIGGERS = ("=", "+", "-", "@")


def sanitize_cell(value: Any) -> str:
    """Return ``value`` rendered as a spreadsheet-safe string.

    ``None`` and non-string inputs (numbers, booleans, ...) are coerced
    safely. The returned value is protected against two classes of issue:

    * formula injection — leading ``=``/``+``/``-``/``@`` are wrapped in
      square brackets so spreadsheet apps stop interpreting the cell as a
      formula;
    * control-character injection — leading tab, carriage-return or newline
      characters are stripped.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.lstrip(_LEADING_CONTROL_CHARS_STR)
    if text and text[0] in FORMULA_TRIGGERS:
        text = "[" + text[0] + "]" + text[1:]
    return text
