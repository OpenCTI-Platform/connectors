"""Store of the standardized errors a connector handled during a run.

``ErrorStore()`` always returns the same store, so any part of a connector can record
an error without passing an object around. At the end of a scheduled run, the
connector returns the recorded errors to pycti, which sends them to OpenCTI with the
connector's ping::

    from connectors_sdk import DataConversionError, ErrorStore

    def process_message(self):  # callback passed to helper.schedule_process
        store = ErrorStore()
        store.clear()  # a run starts with an empty store
        for item in items:
            try:
                ...
            except DataConversionError as err:
                store.record_error(err)  # handled: the run skips the item
        return [error.convert_to_pycti_format() for error in store.get_errors()]

The store is shared by the threads of a process, not across processes.
"""

import threading
from typing import ClassVar, Self

from connectors_sdk.exceptions.connector_errors import ConnectorError


class ErrorStore:
    """Single store of the ``ConnectorError`` objects recorded during a run.

    Every ``ErrorStore()`` call returns the same instance, and calling it again never
    discards the recorded errors. Recording, reading and clearing are thread-safe.
    """

    _instance: ClassVar["ErrorStore | None"] = None
    _creation_lock: ClassVar[threading.Lock] = threading.Lock()

    _errors: list[ConnectorError]
    _lock: threading.Lock

    def __new__(cls) -> Self:
        """Return the single store, creating it on the first call.

        Its state is set only here: the class has no ``__init__``, so getting the
        store again never resets it.
        """
        if cls._instance is None:
            with cls._creation_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    instance._errors = []
                    instance._lock = threading.Lock()
                    cls._instance = instance
        return cls._instance  # type: ignore[return-value]  # the single instance is of cls

    def record_error(self, error: ConnectorError) -> None:
        """Record one handled error.

        Args:
            error: The error to record. The same error recorded twice is kept twice.

        Raises:
            TypeError: If ``error`` is not a ``ConnectorError``. Nothing is recorded.
        """
        if not isinstance(error, ConnectorError):
            raise TypeError(
                f"ErrorStore records ConnectorError instances only, "
                f"got {type(error).__name__}."
            )
        with self._lock:
            self._errors.append(error)

    def get_errors(self) -> list[ConnectorError]:
        """Return the recorded errors, in the order they were recorded.

        Returns:
            A new list of the recorded error objects: changing it does not change the
            store, and reading removes nothing.
        """
        with self._lock:
            return list(self._errors)

    def clear(self) -> None:
        """Remove every recorded error, e.g. at the start of a run."""
        with self._lock:
            self._errors.clear()
