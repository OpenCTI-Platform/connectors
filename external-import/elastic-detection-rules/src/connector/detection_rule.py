"""Vendor-neutral view of a detection rule deployed in a security platform."""

from datetime import datetime

from pydantic import BaseModel, Field

# Values of ``x_opencti_rule_level``.
RULE_LEVELS = ("informational", "low", "medium", "high", "critical")
_LEVEL_SYNONYMS = {"info": "informational", "moderate": "medium"}


def normalize_level(value: object) -> str | None:
    """Map a vendor severity to an ``x_opencti_rule_level`` value.

    Returns ``None`` when the severity is missing or has no counterpart.
    """
    if value is None:
        return None
    level = str(value).strip().lower()
    level = _LEVEL_SYNONYMS.get(level, level)
    return level if level in RULE_LEVELS else None


class RuleSkippedError(Exception):
    """A vendor rule that cannot be represented as a rule Indicator."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class DetectionRule(BaseModel):
    """A detection rule as deployed in the security platform."""

    key: str = Field(
        description="Unique key of the rule in the platform, used to reconcile runs.",
        min_length=1,
    )
    external_id: str = Field(
        description="Vendor rule id, carried by the deployment relationship.",
        min_length=1,
    )
    name: str = Field(min_length=1)
    description: str | None = None
    pattern: str = Field(description="Rule query or logic.", min_length=1)
    pattern_type: str = Field(min_length=1)
    enabled: bool
    created_at: datetime | None = None
    modified_at: datetime | None = None
    level: str | None = Field(
        default=None, description="One of RULE_LEVELS, None when unknown."
    )
    logsource: dict[str, str] | None = Field(
        default=None,
        description="Sigma-like log source (category / product / service).",
    )
    platforms: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK platforms."
    )
    techniques: dict[str, str | None] = Field(
        default_factory=dict,
        description="Uppercase MITRE ATT&CK id -> technique name when the vendor provides it.",
    )
    url: str | None = Field(
        default=None, description="Link to the rule in the vendor console."
    )
