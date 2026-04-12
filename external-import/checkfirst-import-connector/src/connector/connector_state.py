"""
The state manager is responsible for loading and saving the connector's state to OpenCTI.
It provides a simple interface to manage the state and ensures that it's properly cached and updated.

Architecture:
- ConnectorState: Load, validate and save connector's state
- OpenCTIConnectorHelper: Communicate with OpenCTI platform (read/write state)
"""

import json
from datetime import datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


class ConnectorState(BaseModel):
    """Connector state manager.
    All values defined in the state manager MUST be JSON serializable
    as they will be stored as JSON in OpenCTI (see https://docs.pydantic.dev/latest/concepts/serialization/#json-mode).
    """

    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,  # ensure model is revalidate when setting properties
    )

    _helper: OpenCTIConnectorHelper = PrivateAttr()
    _cache: "ConnectorState | None" = PrivateAttr(default=None)

    last_run: datetime | None = Field(default=None)
    last_page: int = Field(default=1)

    def __init__(self, helper: OpenCTIConnectorHelper, **kwargs: Any):
        """Initialize the state manager with the connector helper."""
        super().__init__(**kwargs)

        self._helper = helper
        self._cache: "ConnectorState | None" = None

    def load(self) -> "ConnectorState":
        """Load the state from OpenCTI."""
        if self._cache is None:
            state = self._helper.get_state() or {}
            for key in state:
                setattr(self, key, state[key])

            self._cache = self.model_copy()

        return self._cache

    def save(self) -> None:
        """Save the state to OpenCTI."""
        state_dict = self.model_dump_json(exclude_none=True)

        self._helper.set_state(json.loads(state_dict))
        self._cache = self.model_copy()

    def clear_cache(self) -> None:
        """Clear the state cache."""
        self._cache = None
