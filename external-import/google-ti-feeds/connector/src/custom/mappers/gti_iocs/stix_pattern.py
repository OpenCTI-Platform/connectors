"""Helpers to build STIX patterns from GTI values."""


def escape_pattern_value(value: str) -> str:
    """Escape a value for a single-quoted STIX pattern string.

    Backslashes first, then single quotes, as required by the STIX 2.1 pattern grammar.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")
