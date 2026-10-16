"""EUVD raw API payload models.

These models describe *raw* data, exactly as returned by the
`GET /search` (and `GET /enisaid`) endpoints of the ENISA EUVD API -- they
are **not** STIX objects. STIX conversion happens in
`enisa_euvd.processors.vulnerability_processor`.

Field names intentionally mirror the API's own camelCase names via
`Field(alias=...)`, keeping the raw shape close to the wire format while
exposing a Pythonic snake_case attribute to the rest of the connector.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator

# The API returns dates as "Sep 23, 2026, 12:31:13 PM" (no timezone; the
# ENISA EUVD API operates in UTC).
_EUVD_DATETIME_FORMAT = "%b %d, %Y, %I:%M:%S %p"


def _parse_euvd_datetime(value: object) -> object:
    """Parse an EUVD date string into a timezone-aware (UTC) `datetime`."""
    if isinstance(value, str):
        return datetime.strptime(value, _EUVD_DATETIME_FORMAT).replace(
            tzinfo=timezone.utc
        )
    return value


def _split_lines(value: object) -> list[str]:
    """Split a newline-separated string field into a list, preserving order.

    The EUVD API returns `references` and `aliases` as a single string with
    one value per line (or `null` when empty); coalesce both shapes into a
    plain `list[str]` (blank lines dropped, duplicates kept as-is).
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    lines = [line.strip() for line in str(value).splitlines()]
    return [line for line in lines if line]


class EUVDVendor(BaseModel):
    """A vendor, as nested under a product reference."""

    name: str = Field(description="Name of the vendor.")


class EUVDProduct(BaseModel):
    """A product, as nested under a product reference."""

    name: str = Field(description="Name of the product.")
    vendor: EUVDVendor = Field(description="Vendor of the product.")


class EUVDProductRef(BaseModel):
    """One entry of `enisaIdProduct`: a product affected by the vulnerability."""

    product: EUVDProduct
    product_version: str | None = Field(
        default=None,
        description="Affected version(s), e.g. '1.2.3' or '0 <2.0.0'.",
    )


class EUVDVulnerability(BaseModel):
    """One item of the `GET /search` (or `GET /enisaid`) API response."""

    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(description="The EUVD identifier, e.g. 'EUVD-2024-00001'.")
    description: str = Field(description="Full description of the vulnerability.")
    date_published: datetime = Field(alias="datePublished")
    date_updated: datetime = Field(alias="dateUpdated")
    base_score: float | None = Field(default=None, alias="baseScore")
    base_score_version: str | None = Field(default=None, alias="baseScoreVersion")
    base_score_vector: str | None = Field(default=None, alias="baseScoreVector")
    epss: float | None = Field(default=None, description="EPSS score (0-1).")
    references: list[str] = Field(
        default_factory=list,
        description="Related URLs (advisories, NVD/CVE detail pages...).",
    )
    aliases: list[str] = Field(
        default_factory=list,
        description="Other identifiers for the same vulnerability (CVE, GHSA...).",
    )
    products: list[EUVDProductRef] = Field(
        default_factory=list,
        alias="enisaIdProduct",
        description="Affected products, each with its vendor and version range.",
    )

    @field_validator("date_published", "date_updated", mode="before")
    @classmethod
    def _validate_dates(cls, value: object) -> object:
        return _parse_euvd_datetime(value)

    @field_validator("references", "aliases", mode="before")
    @classmethod
    def _validate_lines(cls, value: object) -> list[str]:
        return _split_lines(value)
