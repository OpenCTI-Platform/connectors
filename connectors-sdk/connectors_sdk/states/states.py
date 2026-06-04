"""State models for connectors.

This module is responsible for defining the state model of each connector type.
Every connector should use its corresponding state model to ensure consistency and reliability in state management.
Each class can be used as-is (they're not abstract classes) or subclassed to fit specific needs.
"""

from datetime import datetime

from connectors_sdk.states._base_state import BaseConnectorState
from pydantic import Field


class ExternalImportConnectorState(BaseConnectorState):
    """State model for connectors of type `EXTERNAL_IMPORT`.
    This class inherits from `pydantic.BaseModel`.
    It can be used as-is or subclassed with custom fields to fit specific connector needs.
    All fields defined in this model MUST be JSON serializable as they will be stored as JSON
    in OpenCTI (see https://docs.pydantic.dev/latest/concepts/serialization/#json-mode).
    """

    last_run: datetime | None = Field(default=None)
