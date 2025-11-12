"""Custom Pydantic serializers for the Connectors SDK."""

from pydantic import SerializationInfo


def pycti_list_serializer(v: list[str], info: SerializationInfo) -> str | list[str]:
    """Serialize a list[str] as a comma-separated string when the Pydantic
    serialization context requests "pycti" mode; otherwise, return the list
    unchanged.

    This serializer is intended for use with Pydantic v2 `PlainSerializer` and
    is typically activated only during JSON serialization (`when_used="json"`),
    so the in-memory Python value remains a `list[str]` while the JSON output
    can be a single string when required by external systems.

    Parameters
    - v: The value to serialize. Expected to be a list of strings.
    - info: Serialization context provided by Pydantic. If `info.context`
      contains {"mode": "pycti"}, the list will be joined into a single
      comma-separated string.

    Returns:
    - A comma-separated string if context mode is "pycti" and `v` is a list.
    - The original value `v` unchanged in all other cases.

    Notes:
    - Joining does not insert spaces; e.g., ["a", "b", "c"] -> "a,b,c".
    - If any element contains commas, those commas are not escaped.

    Examples:
    - info.context={"mode": "pycti"} and v=["e1", "e2"] -> "e1,e2"
    - info.context is None or mode != "pycti" -> ["e1", "e2"]
    """
    if isinstance(v, list) and info.context and info.context.get("mode") == "pycti":
        return ",".join(v)  # [ "e1", "e2", "e3" ] -> "e1,e2,e3"
    return v
