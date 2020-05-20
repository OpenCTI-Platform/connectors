# -*- coding: utf-8 -*-
"""OpenCTI Valhalla connector models."""

from datetime import datetime
from typing import List
from pydantic import BaseModel


class Status(BaseModel):
    """Valhalla API Status model"""

    error: str
    num_rules: int
    status: str
    version: int


class YaraRule(BaseModel):
    """Valhalla YaraRule model"""

    author: str
    content: str
    date: str
    description: str
    minimum_yara: str
    name: str
    reference: str
    required_modules: list
    rule_hash: str
    score: int
    tags: list

    @property
    def cti_date(self) -> str:
        # Valhalla date format: 2020-04-27 13:28:41
        d = datetime.strptime(self.date, "%Y-%m-%d %H:%M:%S")
        return d.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    @property
    def cti_description(self) -> str:
        return (
            self.description
            + "\n\n"
            + "Minimum Yara version: "
            + self.minimum_yara
            + "\n\n"
            + "Required Yara modules: "
            + ", ".join(self.required_modules)
        )


class ApiResponse(BaseModel):
    """Valhalla API Respose model"""

    api_version: str
    copyright: str
    customer: str
    date: str
    legal_note: str
    title: str
    rules: List[YaraRule]

    @property
    def cti_date(self) -> str:
        # Valhalla date format: 2020-04-27 13:28:41
        d = datetime.strptime(self.date, "%Y-%m-%d %H:%M:%S")
        return d.strftime("%Y-%m-%dT%H:%M:%S+00:00")
