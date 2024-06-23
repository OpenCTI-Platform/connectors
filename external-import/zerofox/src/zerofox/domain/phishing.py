# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class Host(BaseModel):
    ip: str
    asn: int
    geo: str


class Cert(BaseModel):
    authority: str
    fingerprint: str
    issued: datetime


class Phishing(BaseModel):
    scanned: datetime
    domain: str
    url: str
    host: Host
    cert: Cert | None
