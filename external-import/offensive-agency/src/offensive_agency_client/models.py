"""Typed models of the offensive.agency STIX feed.

They describe the raw feed objects, not the STIX objects sent to OpenCTI: the
conversion happens in `connector/data_processors/`. Only the fields the
connector uses are declared; pydantic ignores the others.
"""

from typing import Any, Literal

from pydantic import AwareDatetime, BaseModel, Field, field_validator


def _none_to_empty_list(value: Any) -> Any:
    """Turn a `null` list sent by the feed into an empty list."""
    return [] if value is None else value


class FeedExternalReference(BaseModel):
    """External reference of a feed object."""

    source_name: str = Field(min_length=1)
    url: str | None = None
    description: str | None = None
    external_id: str | None = None


class FeedTool(BaseModel):
    """An offensive AI agent (STIX `tool`)."""

    type: Literal["tool"]
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str | None = None
    tool_types: list[str] = Field(default_factory=list)
    external_references: list[FeedExternalReference] = Field(default_factory=list)
    created: AwareDatetime | None = None

    _coalesce_lists = field_validator(
        "tool_types", "external_references", mode="before"
    )(_none_to_empty_list)


class FeedIndicator(BaseModel):
    """An Internet-exposed agent console (STIX `indicator` on an IPv4 address)."""

    type: Literal["indicator"]
    id: str = Field(min_length=1)
    description: str | None = None
    pattern: str = Field(min_length=1)
    indicator_types: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    external_references: list[FeedExternalReference] = Field(default_factory=list)
    created: AwareDatetime | None = None
    modified: AwareDatetime
    valid_from: AwareDatetime | None = None

    _coalesce_lists = field_validator(
        "indicator_types", "labels", "external_references", mode="before"
    )(_none_to_empty_list)


class FeedRelationship(BaseModel):
    """A link between two feed objects (`indicator --indicates--> tool`)."""

    type: Literal["relationship"]
    id: str = Field(min_length=1)
    relationship_type: str = Field(min_length=1)
    source_ref: str = Field(min_length=1)
    target_ref: str = Field(min_length=1)
    created: AwareDatetime | None = None


class FeedBundle(BaseModel):
    """Envelope of the feed: a STIX bundle whose objects are still raw dicts.

    The objects are validated one by one by the client, so that a single
    malformed object is skipped instead of failing the whole feed.
    """

    type: Literal["bundle"]
    objects: list[dict[str, Any]] = Field(default_factory=list)

    _coalesce_lists = field_validator("objects", mode="before")(_none_to_empty_list)


class Feed(BaseModel):
    """The feed objects the connector uses, already validated."""

    tools: list[FeedTool] = Field(default_factory=list)
    indicators: list[FeedIndicator] = Field(default_factory=list)
    relationships: list[FeedRelationship] = Field(default_factory=list)
