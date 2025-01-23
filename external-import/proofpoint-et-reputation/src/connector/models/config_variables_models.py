from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field, PositiveInt


class ProofpointEtReputationConfigVar(BaseModel):
    """
    ConfigurationVar model for the ProofPoint ET Reputation connector.

    This class defines the configuration variables required by the ProofPoint ET Reputation connector.
    It uses Pydantic's BaseModel for validation and provides metadata for each field.

    Attributes:
        connector_duration_period (timedelta):
            Duration of the connector's operation, specified in ISO 8601 format.
            Examples include "PT24H" for 24 hours or "P1D" for one day.
        extra_api_token (str):
            API token used for authentication with the ProofPoint ET Reputation API.
        extra_create_indicator (bool):
            Flag indicating whether indicators should be created from the reputation data.
            If True, indicators and relationship will be generated; otherwise, only observables will be created.
        extra_min_score (int):
            Minimum score threshold for processing reputation data.
            The value must be between 20 and 100, ProofPoint Et Reputation typically does not store entities with a
            score below 20.

    Notes:
        - The `model_config` ensures that string fields are stripped of whitespace and have a minimum length of 1.
        - Validation is enforced on `min_score` to ensure it falls within the defined range (20-100) and is meaningful
        for ProofPoint data.
    """

    model_config = ConfigDict(str_strip_whitespace=True, str_min_length=1)

    connector_duration_period: timedelta = Field(
        ...,
        description="Duration period in ISO 8601 format.",
        examples=["PT24H", "P1D"],
    )
    extra_api_token: str = Field(..., description="API token for authentication.")
    extra_create_indicator: bool = Field(
        ...,
        description="Variable indicating whether indicators should be created or not.",
    )
    extra_min_score: PositiveInt = Field(
        ...,
        ge=20,
        le=100,
        description="Minimum score for processing, must be higher at 20.",
    )
