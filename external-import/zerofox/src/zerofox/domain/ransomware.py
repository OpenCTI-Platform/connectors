# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class Ransomware(BaseModel):
    created_at: datetime
    md5: str | None
    sha1: str | None
    sha256: str
    sha512: str | None
    emails: list[str] | None
    ransom_note: str
    ransomware_name: list[str] | None
    tags: list[str]
