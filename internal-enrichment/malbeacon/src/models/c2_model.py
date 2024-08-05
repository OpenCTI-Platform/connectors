from typing import Optional

from dateutil import parser
from pydantic.v1 import BaseModel


class C2Beacon(BaseModel):
    """MalBeacon C2 Beacon base model"""

    tstamp: Optional[str]  # format: 2020-10-22 09:04:40
    actorasnorg: Optional[str]
    actorcity: Optional[str]
    actorcountrycode: Optional[str]
    actorhostname: Optional[str]
    actorip: Optional[str]
    actorloc: Optional[str]
    actorregion: Optional[str]
    actortimezone: Optional[str]
    c2: Optional[str]
    c2asnorg: Optional[str]
    c2city: Optional[str]
    c2countrycode: Optional[str]
    c2domain: Optional[str]
    c2domainresolved: Optional[str]
    c2hostname: Optional[str]
    c2loc: Optional[str]
    c2region: Optional[str]
    c2timezone: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[str]

    @property
    def cti_tags(self) -> list:
        return self.tags.split(",")

    @property
    def cti_date(self):
        return parser.parse(self.tstamp).strftime("%Y-%m-%dT%H:%M:%S+00:00")
