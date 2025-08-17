# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class FoxBotnet(BaseModel):
    bot_name: str
    c2_domain: str | None
    c2_ip_address: str | None
    ip_address: str
    listed_at: datetime
    country_code: str | None
    zip_code: str | None
    tags: list[str]
