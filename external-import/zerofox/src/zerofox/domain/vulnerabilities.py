# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class Vulnerability(BaseModel):
    base_score: int
    description: str
    exploitability_score: int
    impact_score: int
    created_at: datetime
    updated_at: datetime
    vector_string: str
    cve: str
    summary: str
