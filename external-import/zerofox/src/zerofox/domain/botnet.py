# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class Botnet(BaseModel):
    ip_address: str
    listed_at: datetime
    bot_name: str
    tags: list[str]
