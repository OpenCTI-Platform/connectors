"""Store of the errors created during one call of a connector callback.

``ErrorStore`` is a singleton: it always returns the same store instance.
Connector code never calls it: a ``ConnectorError`` records itself in the store when
it is created, so the connector only raises (or handles) the error.

The store keeps errors only while it is recording. Only the SDK starts and stops
recording, around each call of the callback that pycti runs (a scheduled run, an
enrichment message, a stream event, ...). ``stop_recording()`` returns the errors
of the call, to report them to OpenCTI.

The store and its recording flag are shared by the threads of a process, not across
processes.

Examples:
    A connector only raises or handles the error. It never calls the store::

        from connectors_sdk import DataConversionError

        for item in items:
            try:
                ...
            except DataConversionError as err:  # recorded when it was created
                logger.warning("Skipping item", meta={"code": err.code})
"""

import threading
from typing import ClassVar, Self


class ErrorStore:
    """Store of the errors created while it is recording.

    Every ``ErrorStore()`` call returns the same instance, and calling it again never
    discards the recorded errors. Every method is thread-safe.
    """

    _instance: ClassVar["ErrorStore | None"] = None
    _creation_lock: ClassVar[threading.Lock] = threading.Lock()

    _lock: threading.Lock
    _recording: bool
    _errors: list[Exception]
    _error_ids: set[int]

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
                    instance._error_ids = set()
                    instance._recording = False
                    instance._lock = threading.Lock()
                    cls._instance = instance
        return cls._instance  # type: ignore[return-value]  # the single instance is of cls

    def start_recording(self) -> None:
        """Empty the store and start recording errors.

        For the SDK only, before each call of the connector callback. Errors left by
        a previous call are discarded.
        """
        with self._lock:
            self._errors.clear()
            self._error_ids.clear()
            self._recording = True

    def stop_recording(self) -> list[Exception]:
        """Stop recording errors and return the recorded ones.

        For the SDK only, after each call of the connector callback. Then the store
        keeps nothing until the next ``start_recording()``.

        Returns:
            A new list of the recorded errors, in the order they were recorded.
        """
        with self._lock:
            errors, self._errors = self._errors, []
            self._error_ids.clear()
            self._recording = False
            return errors

    def record_error(self, error: Exception) -> None:
        """Record one error, only while recording is on.

        A ``ConnectorError`` calls this itself when it is created. When recording is
        off, nothing is kept and nothing is raised.

        Args:
            error: The error to record. Any exception is accepted, as it is. An error
                that is already in the store is not added again.
        """
        with self._lock:
            # When recording is off, nobody would read or empty the store: keep nothing.
            # Ids are compared, not the errors themselves: a class could redefine `==`.
            # An id is unique here, since the list keeps every stored error alive.
            if self._recording and id(error) not in self._error_ids:
                self._errors.append(error)
                self._error_ids.add(id(error))

    def get_errors(self) -> list[Exception]:
        """Return the recorded errors, in the order they were recorded.

        Returns:
            A new list of the recorded error objects: changing it does not change the
            store, and reading removes nothing.
        """
        with self._lock:
            return list(self._errors)

    def clear(self) -> None:
        """Remove every recorded error. Recording stays on if it was on."""
        with self._lock:
            self._errors.clear()
            self._error_ids.clear()
