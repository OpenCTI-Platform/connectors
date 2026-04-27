"""State manager for connectors.

This module is responsible for loading and saving a connector's state to OpenCTI.
It provides a simple interface to manage the state and ensures that it's properly cached and updated.
All connectors should use `ConnectorStateManager` to ensure consistency and reliability in state management.
Can be used as-is (it's not an abstract class) or subclassed to fit specific needs.

Architecture:
- ConnectorStateManager: Load, validate and save connector's state
- OpenCTIConnectorHelper: Communicate with OpenCTI platform (read/write state)
"""

import warnings
from datetime import datetime
from typing import Any

from pycti import OpenCTIConnectorHelper
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_serializer


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
    _sync: bool = PrivateAttr(default=False)

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
        self._sync = False

    def __setattr__(self, name: str, value: Any) -> None:
        """Track (re)assignments of declared fields and mark the state as not synchronized.

        Arguments:
            name: The name of the attribute being set.
            value: The value being assigned to the attribute.
        """
        super().__setattr__(name, value)

        if self._sync and name in type(self).model_fields:
            # Use `BaseModel.__setattr__` directly so updating `_sync`
            # cannot re-trigger this custom `__setattr__`.
            super().__setattr__("_sync", False)

    @field_serializer("*", mode="wrap", when_used="json")
    def _serialize_datetimes(self, value: Any, handler: Any) -> Any:
        """Replace the default JSON serializer, in order to use +00:00 offset instead of Z prefix.
        This is convenient so `assert self.model_dump(mode="json")["last_run"] == self.last_run.isoformat()`
        is `True` across both codebase and tests (using the same serializer).
        Consistent with `DatetimeFromIsoString` in `connectors_sdk.settings.annotated_types` module too.
        """
        if isinstance(value, datetime):
            return value.isoformat()  # Override default JSON serializer
        return handler(value)

    def load(self, force: bool = False) -> None:
        """Overwrite instance's fields with the connector's state stored on OpenCTI.

        Arguments:
            force: If `True`, load the state from OpenCTI even if there are unsaved changes in the state manager instance.
        """
        if self._sync or force:
            state = self._helper.get_state() or {}
            for key in state:
                # Prevent potential conflicts with private attributes (not likely but possible)
                if key in ("_helper", "_sync"):
                    continue

                setattr(self, key, state[key])

            # The state manager instance is now synchronized with OpenCTI
            self._sync = True
        else:
            warnings.warn(
                "Loading connector's state from OpenCTI would overwrite unsaved changes in the state manager instance. "
                "Save current changes by calling `save()` or use `force=True` to load the state anyway.",
                UserWarning,
                stacklevel=2,
            )

    def save(self) -> None:
        """Save instance's fields as connector's state on OpenCTI."""
        declared_fields = set(type(self).model_fields)

        state_dict = self.model_dump(mode="json", include=declared_fields)
        # Send both declared _and_ extra fields (to not delete any connector state's attributes on OpenCTI)
        if self.model_extra:
            state_dict.update(self.model_extra)

        self._helper.set_state(state_dict)
        self._helper.force_ping()  # ensure the state is updated immediately on OpenCTI
        # OpenCTI is now synchronized with the state manager instance
        self._sync = True
