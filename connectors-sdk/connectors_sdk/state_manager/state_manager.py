"""State manager for connectors.

This module is responsible for loading and saving a connector's state to OpenCTI.
It provides a simple interface to manage the state and ensures that it's properly cached and updated.
All connectors should use `ConnectorStateManager` to ensure consistency and reliability in state management.
Can be used as-is (it's not an abstract class) or subclassed to fit specific needs.

Architecture:
- ConnectorStateManager: Load, validate and save connector's state
- OpenCTIConnectorHelper: Communicate with OpenCTI platform (read/write state)
"""

from datetime import datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr


class ConnectorStateManager(BaseModel):
    """State manager for connectors.
    This class inherits from `pydantic.BaseModel`. It can be used as-is (this is not an abstract class)
    or subclassed with custom fields to fit specific connector needs.
    All fields defined in the state manager MUST be JSON serializable as they will be stored as JSON
    in OpenCTI (see https://docs.pydantic.dev/latest/concepts/serialization/#json-mode).
    """

    model_config = ConfigDict(
        extra="allow",
        validate_assignment=True,  # ensure model is revalidate when setting properties
    )

    _helper: OpenCTIConnectorHelper = PrivateAttr()

    last_run: datetime | None = Field(default=None)

    def __init__(self, helper: OpenCTIConnectorHelper, **kwargs: Any) -> None:
        """Initialize the state manager with the connector helper.
        By default, the fields of the state manager are not populated.
        The `load` method must be called to populate the fields with the state stored on OpenCTI.

        Arguments:
            helper: The `OpenCTIConnectorHelper` instance to communicate with the OpenCTI platform.
            **kwargs: Any fields to set on the state manager (these fields will also be stored on OpenCTI).
        """
        super().__init__(**kwargs)

        # Validate `helper` argument as Pydantic will not do it since it's a private attribute
        if not isinstance(helper, OpenCTIConnectorHelper):
            raise ValueError(
                "`helper` argument is required and must be an instance of `pycti.OpenCTIConnectorHelper`"
            )

        self._helper = helper

    def load(self) -> None:
        """Overwrite instance's fields with the connector's state stored on OpenCTI."""
        state = self._helper.get_state() or {}
        for key in state:
            # Prevent potential conflicts with `_helper` private attribute (not likely but possible)
            if key == "_helper":
                continue

            setattr(self, key, state[key])

    def save(self) -> None:
        """Save instance's fields as connector's state on OpenCTI."""
        declared_fields = set(type(self).model_fields)

        state_dict = self.model_dump(mode="json", include=declared_fields)
        # Send both declared _and_ extra fields (to not delete any connector state's attributes on OpenCTI)
        if self.model_extra:
            state_dict.update(self.model_extra)

        self._helper.set_state(state_dict)
        self._helper.force_ping()  # ensure the state is updated immediately on OpenCTI
