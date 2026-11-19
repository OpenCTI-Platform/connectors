"""EXAMPLE typed models -- validate the raw API data.

`IPReputation` below is an example. It describes the response of the
fictional `/ip/{ip}` endpoint (see `template_client/api_client.py`), not
any real API. Replace it with one model per response your connector reads.

The client validates each response with its model. If the API sends
unexpected data (a missing field, a wrong type...), Pydantic raises a
`ValidationError` right away, with a clear message. Without a model, the
error would only appear later, during the STIX conversion, and would be
harder to understand.

These models describe the *raw* data, exactly as the API sends it. They are
not STIX objects: the processors convert them to STIX.

TODO:
    - [ ] Replace `IPReputation` with the models of your API responses.
    - [ ] Use the field names of the API as they are. Rename them only in the
        processors, when converting to STIX.
    - [ ] Only declare the fields you use: Pydantic ignores the other ones.
"""

from pydantic import BaseModel, Field


class IPReputation(BaseModel):
    """EXAMPLE model -- the response of the fictional `/ip/{ip}` endpoint."""

    ip: str = Field(description="The IP address.")
    score: int = Field(description="Reputation score, from 0 (safe) to 100.")
    tags: list[str] = Field(description="Tags given by the source.", default=[])
    asn: int | None = Field(
        description="Number of the autonomous system of the IP.",
        default=None,
    )
    as_name: str | None = Field(
        description="Name of the autonomous system of the IP.",
        default=None,
    )
    permalink: str | None = Field(
        description="URL of the IP page on the source website.",
        default=None,
    )
