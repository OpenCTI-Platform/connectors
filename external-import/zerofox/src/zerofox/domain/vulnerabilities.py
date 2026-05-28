# standard library
from datetime import datetime

# third-party
from pydantic import BaseModel


class Vulnerability(BaseModel):
    base_score: float
    description: str
    exploitability_score: float
    impact_score: float
    created_at: datetime
    updated_at: datetime
    vector_string: str
    cve: str
    summary: str | None
    remediation: str | None
