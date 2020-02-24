# -*- coding: utf-8 -*-
"""OpenCTI AlienVault models module."""

from datetime import datetime
from typing import Union, Optional, List

from pydantic import BaseModel


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
    role: Optional[str] = None
    access_type: Optional[str] = None
    access_reason: Optional[str] = None
    access_groups: Optional[List[int]] = None
    expiration: Optional[datetime] = None


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
