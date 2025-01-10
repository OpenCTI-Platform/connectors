from pydantic import (
    BaseModel,
    Field,
    ConfigDict,
    PositiveInt,
)
from datetime import timedelta

class ProofpointEtReputationConfigVar(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, str_min_length=1)

    duration_period: timedelta = Field(description="Duration in ISO 8601 format", examples=["PT24H", "P1D"])
    api_token: str = Field(description="API token for authentication")
    create_indicator: bool = Field(description="Variable indicating whether indicators should be created or not")
    min_score: int = Field(PositiveInt, ge=0, le=100, description="Minimum score for processing, must be higher at 20")