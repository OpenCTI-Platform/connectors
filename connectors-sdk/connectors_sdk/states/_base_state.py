"""State base classes for connectors.

This module is responsible for loading and saving a connector's state to OpenCTI.
It provides a simple interface to manage the state and ensures that it's properly cached and updated.
All connectors should use `BaseConnectorState` to ensure consistency and reliability in state management.

This module is private and should not be imported directly inside connectors.
The public subclasses should be used instead (e.g. `ExternalImportConnectorState` for external import connectors).

Architecture:
- _StateClient: Communicate with OpenCTI platform (read/write state)
- BaseConnectorState: Load, validate and save connector's state
"""

from __future__ import annotations

import warnings
from abc import ABC
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.logging.logger import Logger
from connectors_sdk.logging.sdk_logger import sdk_logger
from pydantic import BaseModel, ConfigDict, PrivateAttr, field_serializer

if TYPE_CHECKING:
    from connectors_sdk.logging._base_logger import BaseLogger
    from pycti import OpenCTIConnectorHelper


class _StateClient:
    """State client for managing states on OpenCTI.
    It is used internally by `BaseConnectorState` to handle the actual communication with OpenCTI.
    Connector developers should not interact with this class directly.
    """

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("_StateClient")

    _helper: OpenCTIConnectorHelper

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """Initialize the state client with the connector helper.
        On initialization, the state's fields are not populated.
        The `load` method must be called to populate the state's fields with the state stored on OpenCTI.

        Arguments:
            helper: The `OpenCTIConnectorHelper` instance to communicate with the OpenCTI platform.
        """
        self._helper = helper

        self.logger.debug(f"{self.__class__.__name__} instantiated successfully")

    def load_state(self) -> dict[str, Any]:
        """Get connector's state stored on OpenCTI."""
        state = self._helper.get_state() or {}

        self.logger.debug("Raw state loaded from OpenCTI", {"state": state})

        return state

    def save_state(self, state: BaseConnectorState) -> None:
        """Save state's fields as connector's state on OpenCTI."""
        # Send both declared and extra fields (but not private attributes)
        state_dict = state.to_json()
        self._helper.set_state(state_dict)
        # Ensure the state is updated immediately on OpenCTI (instead of waiting for the next ping)
        self._helper.force_ping()

        self.logger.debug("State saved to OpenCTI", {"state": state_dict})


class BaseConnectorState(BaseModel, ABC):
    """Base class for connectors states.
    It must be subclassed per connectors types.
    All fields defined in this model MUST be JSON serializable as they will be stored as JSON
    in OpenCTI (see https://docs.pydantic.dev/latest/concepts/serialization/#json-mode).
    """

    model_config = ConfigDict(
        # Allow extra fields that could be stored on OpenCTI but not declared in the model
        # (e.g. if the connector's state has evolved since the last time it was loaded)
        extra="allow",
        # Ensure that the model is revalidated when setting properties,
        # to keep the state consistent and avoid saving invalid data on OpenCTI
        validate_assignment=True,
    )

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("BaseConnectorState")

    _client: _StateClient | None = PrivateAttr(default=None)
    _can_be_loaded: bool = PrivateAttr(default=False)

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Attach a logger child named after the concrete `BaseConnectorState` subclass."""
        super().__init_subclass__(**kwargs)
        package_name = cls.__module__.split(".")[0]
        cls.logger = Logger(f"{package_name}.{cls.__name__}")

    def model_post_init(self, context: Any) -> None:
        """Enable loading the state from OpenCTI after the model is initialized.

        On initialization, the state's fields are not populated.
        The `load` method must be called to populate the state's fields with the state stored on OpenCTI.
        """
        _ = context  # Unused argument (required by pydantic)
        self._can_be_loaded = True

    def inject_dependencies(self, helper: OpenCTIConnectorHelper) -> None:
        """Attach an instance of `OpenCTIConnectorHelper` to the state.
        This is used to link the state instance to the corresponding `pycti` state API,
        so that it can be loaded from / saved to OpenCTI.

        Arguments:
            helper: The `OpenCTIConnectorHelper` instance to link to this state.
        """
        # Wrap the helper to prepare state API calls properly
        self._client = _StateClient(helper)

        self.logger.debug(
            f"Dependencies injected into `{self.__class__.__name__}` instance. `_StateClient` set up."
        )

    def to_json(self) -> dict[str, Any]:
        """Get the state as a JSON-serializable dict.
        Used before saving the state to OpenCTI, or for logging purposes.
        """
        # Include declared and extra fields (but not private attributes)
        declared_fields = set(type(self).model_fields)

        state_dump = self.model_dump(mode="json", include=declared_fields)
        if self.model_extra:
            state_dump.update(self.model_extra)

        return state_dump

    def load(self, force: bool = False) -> None:
        """Load the state from OpenCTI.
        This will overwrite the instance's fields with the connector's state stored on OpenCTI.
        If the state instance has potential unsaved changes, a warning will be raised and
        the state will NOT be loaded, to prevent unintentional data loss.

        Arguments:
            force: If `True`, load the state from OpenCTI even if there are potential
            unsaved changes in the state instance.
        """
        if not self._client:
            raise RuntimeError(
                "State client is not initialized. Call `inject_dependencies` method first."
            )

        if not self._can_be_loaded and not force:
            warnings.warn(
                "Loading connector's state from OpenCTI would overwrite potential unsaved changes in the state instance. "
                "Save current changes by calling `save()` or use `force=True` to load the state anyway.",
                UserWarning,
                stacklevel=2,
            )
            return

        raw_state = self._client.load_state()
        for key, value in raw_state.items():
            # Prevent potential conflicts with private attributes
            # (not likely but possible)
            if key in ("_client", "_can_be_loaded"):
                continue

            setattr(self, key, value)

        # Prevent loading the state again before `save` is called
        # (to avoid overwriting potential unsaved changes)
        self._can_be_loaded = False

    def save(self) -> None:
        """Save the state to OpenCTI."""
        if not self._client:
            raise RuntimeError(
                "State client is not initialized. Call `inject_dependencies` method first."
            )

        self._client.save_state(self)
        self._can_be_loaded = True

    @field_serializer("*", mode="wrap", when_used="json")
    def _serialize_datetimes(self, value: Any, handler: Any) -> Any:
        """Replace the default JSON serializer, in order to use +00:00 offset instead of Z prefix.
        This is convenient so `assert self.model_dump(mode="json")["last_run"] == self.last_run.isoformat()`
        is `True` across both codebase and tests (using the same serializer).
        Consistent with `DatetimeFromIsoString` in `connectors_sdk.settings.annotated_types` module too.

        Arguments:
            value: The value to serialize.
            handler: The default JSON serializer to use for non-datetime values.

        Returns:
            The serialized value.
        """
        if isinstance(value, datetime):
            return value.isoformat()  # Override default JSON serializer
        return handler(value)
