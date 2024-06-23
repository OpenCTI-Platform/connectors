# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class C2Domain(BaseModel):
    domain: str
    port: int
    tags: list[str]
    ip_addresses: list[str]
    created_at: datetime
    updated_at: datetime
