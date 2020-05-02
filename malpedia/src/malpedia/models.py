# -*- coding: utf-8 -*-
"""OpenCTI Malpedia connector models."""

import re
import dateutil.parser as dp
from datetime import datetime, date
from typing import Optional, List

from pydantic import BaseModel, UUID4, constr, AnyUrl, Field


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
    urls: List[AnyUrl]
    common_name: Optional[str]
    uuid: UUID4

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
        else:
            return self.common_name


class YaraRule(BaseModel):
    """Malpedia Yara Rules model."""

    _TLP_MAPPING = {
        "tlp_white": "TLP:WHITE",
        "tlp_green": "TLP:GREEN",
        "tlp_amber": "TLP:AMBER",
        "tlp_red": "TLP:RED",
    }

    tlp_level: str
    rule_name: str
    raw_rule: str

    @property
    def cti_tlp(self) -> str:
        """Malpedia TLP mapped to OpenCTI."""
        return self._TLP_MAPPING[self.tlp_level]

    @property
    def date(self) -> str:
        """Malpedia yara date."""
        extract = re.search("([0-9]{4}\-[0-9]{2}\-[0-9]{2})", self.raw_rule)
        if extract is None:
            return date.today()
        else:
            try:
                return dp.isoparse(extract.group(1)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            except:
                return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S+00:00")


class Sample(BaseModel):
    """Malpedia Sample model."""

    status: str
    sha256: constr(regex="^[A-Fa-f0-9]{64}$")  # noqa: F722
    version: str


class ActorMeta(BaseModel):
    cfr_suspected_victims: list = Field(None, alias="cfr-suspected-victims")
    country: str = ""
    refs: list = []
    cfr_target_category: list = Field(None, alias="cfr-target-category")
    cfr_type_of_incident: str = Field(None, alias="cfr-type-of-incident")
    synonyms: list = []
    cfr_suspected_state_sponsor: str = Field(None, alias="cfr-suspected-state-sponsor")
    attribution_confidence: int = Field(None, alias="attribution-confidence")


class ActorRelated(BaseModel):
    dest_uuid: str = Field(alias="dest-uuid")
    ref_type: str = Field(alias="type")
    tags: str


class Actor(BaseModel):
    value: str
    meta: ActorMeta
    # families: List[Family]
    description: str = ""
    # related: list
    uuid: UUID4
