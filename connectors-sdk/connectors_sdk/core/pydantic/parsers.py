"""Common parsers for pydantic models."""


def parse_comma_separated_list(value: str | list[str]) -> list[str]:
    """Coerce a comma-separated string into a list[str], trimming surrounding
    whitespace for each element. If the input is already a list[str], it is
    returned unchanged.

    This is useful for values originating from environment variables or other
    string-based sources (e.g., "a, b , c") and converts them to ["a", "b", "c"].

    Parameters
    - value: Either a string (e.g., "a,b,c") or a list[str].

    Returns:
    - A list[str]. For string inputs, the string is split on commas and each
      token is stripped of leading/trailing whitespace.

    Examples:
    - "a, b ,c" -> ["a", "b", "c"]
    - ["a", "b"] -> ["a", "b"]
    """
    if isinstance(value, str):
        return [string.strip() for string in value.split(",") if value]
    return value
