"""Commonly used Pydantic types with custom validation and serialization logic."""

from typing import Annotated

from connectors_sdk.core.pydantic.parsers import parse_comma_separated_list
from connectors_sdk.core.pydantic.serializers import pycti_list_serializer
from pydantic import BeforeValidator, PlainSerializer

ListFromString = Annotated[
    list[str],  # Final type
    BeforeValidator(parse_comma_separated_list),
    PlainSerializer(pycti_list_serializer, when_used="json"),
]
ListFromString.__doc__ = """
Annotated list[str] that:
- Validates: Accepts a comma-separated string (e.g., "a,b,c") or a list[str].
  If a string is provided, it is split on commas and whitespace is trimmed for
  each item.
- Serializes (JSON): When the Pydantic serialization context includes
  {"mode": "pycti"}, the list is serialized as a single comma-separated string
  (e.g., ["a","b"] -> "a,b"). Otherwise, it serializes as a JSON array by default.

Components
- BeforeValidator(environ_list_validator): Converts input strings to list[str]
  early in validation.
- PlainSerializer(pycti_list_serializer, when_used="json"): Produces the "pycti"
  string form only for JSON serialization.

Examples
- Validation:
    from pydantic import BaseModel

    class Model(BaseModel):
        tags: ListFromString

    Model.model_validate({"tags": "a, b , c"}).tags  # -> ["a", "b", "c"]
    Model.model_validate({"tags": ["x", "y"]}).tags  # -> ["x", "y"]

- Serialization:
    m = Model.model_validate({"tags": ["e1", "e2"]})
    m.model_dump()                              # -> {'tags': ['e1', 'e2']}
    m.model_dump_json()                         # -> {"tags":["e1","e2"]}
    m.model_dump_json(context={"mode": "pycti"})# -> {"tags":"e1,e2"}
"""
