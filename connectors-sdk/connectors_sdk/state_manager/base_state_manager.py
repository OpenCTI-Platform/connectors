"""Base state manager for connectors.

The state manager is responsible for loading and saving the connector's state to OpenCTI.
It provides a simple interface to manage the state and ensures that it's properly cached and updated.
All connectors should use a state manager to ensure consistency and reliability in state management.
Can be used as-is (it's not an abstract class) or subclassed to fit specific needs.

Architecture:
- BaseConnectorStateManager: Load, validate and save connector's state
- OpenCTIConnectorHelper: Communicate with OpenCTI platform (read/write state)
"""

import json
from datetime import datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel, ConfigDict, Field


class BaseConnectorStateManager(BaseModel):
    """State manager for connectors.
    Can be used as-is (this is not an abstract class) or subclassed to fit specific needs.
    All values defined in the state manager MUST be JSON serializable
    as they will be stored as JSON in OpenCTI (see https://docs.pydantic.dev/latest/concepts/serialization/#json-mode).
    """

    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,  # ensure model is revalidate when setting properties
    )

    last_run: datetime | None = Field(default=None)

    def __init__(self, helper: OpenCTIConnectorHelper, **kwargs: Any):
        """Initialize the state manager with the connector helper."""
        super().__init__(**kwargs)

        self.helper = helper
        self._cache: "BaseConnectorStateManager | None" = None

    def load(self) -> "BaseConnectorStateManager":
        """Load the state from OpenCTI."""
        if self._cache is None:
            state = self.helper.get_state() or {}
            for key in state:
                setattr(self, key, state[key])

            self._cache = self.model_copy()

        return self._cache

    def save(self) -> None:
        """Save the state to OpenCTI."""
        declared_fields = set(type(self).model_fields)
        state_dict = self.model_dump_json(include=declared_fields)

        self.helper.set_state(json.loads(state_dict))
        self._cache = self.model_copy()

    def clear_cache(self) -> None:
        """Clear the state cache."""
        self._cache = None
