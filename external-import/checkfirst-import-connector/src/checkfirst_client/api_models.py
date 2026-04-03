"""Data row model for data returned by Checkfirst API."""

from datetime import datetime, timezone

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class AlternateURL(BaseModel):
    """Represents an alternate URL for an article."""

    model_config = ConfigDict(frozen=True)

    url: str | None = Field(default=None)
    language: str | None = Field(default=None)


class Article(BaseModel):
    """Represents an article as returned by the Checkfirst API."""

    model_config = ConfigDict(frozen=True)

    # For debug purpose only (not part of the API response)
    row_number: int = Field()
    # Required fields for Checkfirst client (if not present, the article will be skipped)
    url: str = Field()
    source_title: str = Field()
    source_url: str = Field()
    published_date: datetime = Field()
    # Optional fields
    id: str = Field(validation_alias="_id")
    alternates_urls: list[AlternateURL] = Field(default=[])
    canonical_url: str | None = Field(default=None)
    description: str | None = Field(default=None)
    domain: str | None = Field(default=None)
    keywords: list[str] = Field(default=[])
    language: str | None = Field(default=None)
    og_description: str | None = Field(default=None)
    og_image: str | None = Field(default=None)
    scraped_date: datetime | None = Field(default=None)
    title: str | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def remove_empty_strings(cls, data: dict) -> dict:
        """Convert empty strings to None for optional fields."""
        for key in list(data.keys()):
            if data[key] == "":
                del data[key]
        return data

    @field_validator("published_date", mode="after")
    @classmethod
    def set_published_date_to_utc(cls, value: datetime) -> datetime:
        """Ensure published_date is in UTC."""
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
