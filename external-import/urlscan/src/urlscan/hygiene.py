"""Hygiene client"""

import logging
from datetime import datetime
from typing import List, Optional

import pydantic
import requests
from pydantic import BaseModel, Field
from requests import RequestException, Response

__all__ = [
    "HygieneClient",
]

log = logging.getLogger(__name__)


class HygieneClient:
    """Hygiene client"""

    def __init__(self):
        """Initialization"""
        self.base_url = "https://hygiene.threatanalysis.io"
        self.session = requests.Session()

    def is_safe(self, value: str) -> bool:
        """Check if a domain or IP is potentially safe in the Hygiene lists.
        :param value: Observable value
        :return: True if the indicator is safe
        """
        try:
            resp: Response = self.session.get(f"{self.base_url}/{value}")
            resp.raise_for_status()
        except RequestException:
            log.exception("Hygiene error")
            return False
        except Exception:
            raise

        result = pydantic.parse_raw_as(HygieneResponse, resp.text)
        if result.is_safe:
            log.debug(f"Skipping (safe): {value}")
            return True

        if result.umbrella and result.umbrella.rank > 0:
            log.debug(f"Skipping (umbrella): {value}")
            return True

        return False


class SharedModel(BaseModel):
    """Shared fields among all results"""

    indicator: str
    source: str
    description: str
    updated: datetime


class MispResult(SharedModel):
    """Misp result item"""


class HygieneResult(SharedModel):
    """Hygiene result item"""

    organization: str
    application: str


class UmbrellaResult(SharedModel):
    """Umbrella result item"""

    rank: int


class IronNetResult(SharedModel):
    """IronNet result item"""


class HygieneResponse(BaseModel):
    """Response from the default endpoint"""

    indicator: str
    is_safe: bool = False
    misp: List[MispResult] = Field(default_factory=list)
    hygiene: List[HygieneResult] = Field(default_factory=list)
    umbrella: Optional[UmbrellaResult] = None
    ironnet: Optional[IronNetResult] = None
