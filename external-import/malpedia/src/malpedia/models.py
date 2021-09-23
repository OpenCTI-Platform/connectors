# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector models."""

from datetime import datetime, date
import re
from typing import Optional, List

import dateutil.parser as dp
from pydantic import BaseModel


class Family(BaseModel):
    """Malpedia Family model."""

    malpedia_name: Optional[str]
    updated: Optional[date] = date.today()
    library_entries: Optional[list]
    attribution: Optional[list]
    description: Optional[str]
    notes: Optional[list]
    alt_names: Optional[list]
    sources: Optional[list]
    urls: List[str]
    common_name: Optional[str]
    uuid: str

    @property
    def malpedia_url(self) -> str:
        """Malpedia URL."""
        return f"https://malpedia.caad.fkie.fraunhofer.de/details/{self.malpedia_name}"

    @property
    def all_names(self) -> list:
        """Malpedia names list."""
        return [self.common_name] + self.alt_names + [self.malpedia_name]

    @property
    def main_name(self) -> str:
        """Malpedia names list."""
        if self.common_name == "":
            return self.malpedia_name
        return self.common_name


class YaraRule(BaseModel):
    """Malpedia Yara Rules model."""

    tlp_level: str
    rule_name: str
    raw_rule: str

    @property
    def date(self) -> str:
        """Malpedia yara date."""
        extract = re.search(r"([0-9]{4}\-[0-9]{2}\-[0-9]{2})", self.raw_rule)
        if extract is None:
            return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")
        try:
            return dp.isoparse(extract.group(1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        except Exception:
            return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")


class Sample(BaseModel):
    """Malpedia Sample model."""

    status: str
    sha256: str
    version: str


class ActorMeta(BaseModel):
    country: str = ""
    refs: list = []
    synonyms: list = []


class Actor(BaseModel):
    value: str
    meta: ActorMeta
    description: str = ""
    uuid: str
