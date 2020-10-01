from datetime import datetime, date
from pydantic import BaseModel, Optional


class C2Beacon(BaseModel):
    """MalBeacon C2 Beacon base model"""

    tstamp: Optional[date] = date.today()
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
    tags: Optional[list]


class EmailBeacon(BaseModel):
    """Malbeacon Email Beacon base model"""

    tstamp: Optional[date] = date.today()
    emailaddress: Optional[str]
    cookie_id: Optional[str]
    useragent: Optional[str]
    tags: Optional[list]
    malhashes: Optional[list]
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
