# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class Ransomware(BaseModel):
    created_at: datetime
    md5: str
    sha1: str
    sha256: str
    sha512: str
    emails: list[str] | None
    ransom_note: str
    ransomware_name: list[str]
    tags: list[str]
