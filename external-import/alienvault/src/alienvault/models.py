"""OpenCTI AlienVault models module."""
from datetime import datetime
from typing import List, Literal, Optional, Union

from pydantic import BaseModel

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
    adversary: str
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

    @property
    def url(self) -> str:
        """Pulse URL."""
        return f"https://otx.alienvault.com/pulse/{self.id}"
