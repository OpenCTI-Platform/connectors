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
    while text and text[0] in LEADING_CONTROL_CHARS:
        text = text[1:]
    if text and text[0] in FORMULA_TRIGGERS:
        text = "[" + text[0] + "]" + text[1:]
    return text
