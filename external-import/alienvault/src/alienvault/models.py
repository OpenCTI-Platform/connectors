"""OpenCTI AlienVault models module."""

from datetime import datetime
from typing import Any, List, Literal, Optional, Set, Union

from pydantic.v1 import BaseModel, Field, validator

__all__ = [
    "Pulse",
    "PulseIndicator",
]


class PulseIndicator(BaseModel):
    """OTX pulse indicator model."""

    id: int
    type: str
    title: str
    indicator: str
    description: str
    created: datetime
    is_active: Union[bool, int]
    content: str
    observations: Optional[int] = None
    role: Optional[str]
    access_type: Optional[Literal["public", "private", "redacted"]] = None
    access_reason: Optional[str]
    access_groups: Optional[List[int]]
    expiration: Optional[datetime]


class Pulse(BaseModel):
    """OTX pulse model."""

    id: str
    name: str
    description: str
    author_name: str
    public: bool
    revision: int
    adversary: List[str] = Field(default_factory=list)
    malware_families: List[str]
    industries: List[str]
    attack_ids: List[str]
    tlp: str
    tags: List[str]
    created: datetime
    modified: datetime
    references: List[str]
    targeted_countries: List[str]
    indicators: List[PulseIndicator]

    @validator("adversary", pre=True)
    def _split_adversary(cls, value: Any) -> List[str]:
        """Split the OTX adversary into unique, non-empty names.

        OTX sends a comma-separated string such as "Linen Typhoon, Storm-2603"
        (or null). Names are stripped and de-duplicated case-insensitively,
        keeping the first spelling and the input order.
        """
        if value is None:
            return []

        if isinstance(value, str):
            names = value.split(",")
        elif isinstance(value, (list, tuple)):
            names = list(value)
        else:
            names = [value]

        adversaries: List[str] = []
        seen: Set[str] = set()
        for name in names:
            # Numbers were coerced to strings before the validator existed.
            if isinstance(name, (int, float)):
                name = str(name)
            if not isinstance(name, str):
                raise TypeError("adversary must be a string, a number or a list")

            # The key is lowercased and stripped like pycti IntrusionSet.generate_id,
            # so each STIX id appears once. The first spelling is kept because
            # it is the name OpenCTI displays.
            name_clean = name.strip()
            if not name_clean or name_clean.lower() in seen:
                continue

            seen.add(name_clean.lower())
            adversaries.append(name_clean)
        return adversaries

    @property
    def url(self) -> str:
        """Pulse URL."""
        return f"https://otx.alienvault.com/pulse/{self.id}"
