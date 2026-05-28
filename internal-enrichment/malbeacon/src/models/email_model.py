from typing import Optional

from dateutil import parser
from pydantic.v1 import BaseModel


class EmailBeacon(BaseModel):
    """Malbeacon Email Beacon base model"""

    tstamp: Optional[str]  # format: 2020-10-22 09:04:40
    emailaddress: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[str]
    malhashes: Optional[str]
    actorip: Optional[str]
    actorcity: Optional[str]
    actorregion: Optional[str]
    actorcountrycode: Optional[str]
    actorasnorg: Optional[str]
    actorhostname: Optional[str]
    actorloc: Optional[str]
    actortimezone: Optional[str]
    referrer: Optional[str]
    refdomain: Optional[str]
    refdomainresolved: Optional[str]
    refcity: Optional[str]
    refregion: Optional[str]
    refcountrycode: Optional[str]
    reftimezone: Optional[str]
    refasnorg: Optional[str]
    refloc: Optional[str]
    refhostname: Optional[str]

    @property
    def cti_tags(self) -> list:
        return self.tags.split(",")

    @property
    def cti_hashes(self) -> list:
        return self.malhashes.split(",")

    @property
    def cti_date(self):
        return parser.parse(self.tstamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")
