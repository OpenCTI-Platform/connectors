"""Source-independent debug command line: run any connector factory's components."""

import json
from dataclasses import fields, is_dataclass
from datetime import date
from typing import Any

from pydantic import BaseModel
from stix2.base import _STIXBase


def to_json(value: Any) -> Any:
    """Return the JSON form of a value that :func:`json.dumps` cannot write.

    Meant as ``json.dumps(..., default=to_json)``: ``json.dumps`` writes the
    returned value in turn, so values nested in it are converted the same way.

    * a STIX object (every stix2 object, custom ones included): its STIX JSON,
      with STIX timestamps and property order;
    * a pydantic model: every field, under its alias;
    * a dataclass instance: its fields, in declaration order;
    * a date or a datetime: ISO 8601.

    :raises TypeError: for any other value.
    """
    if isinstance(value, _STIXBase):
        return json.loads(value.serialize(pretty=True))
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, date):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
