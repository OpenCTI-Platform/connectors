from abc import ABC
from datetime import timedelta
from typing import Literal

from connectors_sdk.core.pydantic import ListFromString
from pydantic import (
    BaseModel,
    Field,
)


class BaseConnectorConfig(BaseModel, ABC):
    id: str = Field(
        description="A UUID v4 to identify the connector in OpenCTI.",
    )
    name: str = Field(
        description="The name of the connector.",
    )
    scope: ListFromString = Field(
        description="The scope of the connector, e.g. 'flashpoint'."
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs of the connector."
    )
    log_level: Literal["debug", "info", "warn", "warning", "error", "critical"] = Field(
        description="The minimum level of logs to display."
    )


class ExternalImportConnectorConfig(BaseConnectorConfig):
    type: str = "EXTERNAL_IMPORT"


class InternalEnrichmentsConnectorConfig(BaseConnectorConfig):
    type: str = "INTERNAL_ENRICHMENT"
