"""Report the errors of a scheduled run to OpenCTI.

POC only: the same file is shared with the TeamT5 connector. The target is a run
wrapper in connectors-sdk, plus a try/except around the callback in pycti. This file
then goes away, and the connectors do not change.
"""

import functools
from collections.abc import Callable
from typing import Any, ParamSpec

from connectors_sdk import ConnectorError, ErrorStore, UnknownError

P = ParamSpec("P")


def _unknown_error(err: Exception) -> UnknownError:
    """Return the ``UnknownError`` reporting an exception that is not standardized.

    The message keeps the exception's type: ``[KeyError] 'objects'``, or
    ``[TimeoutError]`` when the exception has no message.
    """
    message = str(err)
    error_type = type(err).__name__
    return UnknownError(f"[{error_type}] {message}" if message else f"[{error_type}]")


def report_run_errors(
    callback: Callable[P, object],
) -> Callable[P, list[dict[str, Any]]]:
    """Return the errors of each run of ``callback``, in the pycti format.

    The decorated callback is meant to be the ``message_callback`` of pycti's
    ``schedule_iso``, which reports the returned list with the connector's ping.

    Each call:

    - starts and ends with an empty ``ErrorStore``, so that only the errors of this
      run are returned;
    - catches every ``Exception`` raised by ``callback``, so that a failed run does
      not stop the schedule. A ``ConnectorError`` is reported as it is, any other
      exception as an ``UnknownError``;
    - returns the errors recorded during the run, in the order they were recorded,
      followed by the error that stopped the run, if any. pycti keeps the last
      error of each code, so the error that stopped the run wins;
    - ignores the value returned by ``callback``.

    ``SystemExit`` and ``KeyboardInterrupt`` are not caught: the process stops.

    Args:
        callback: The function running one scheduled run.

    Returns:
        The decorated callback.
    """

    @functools.wraps(callback)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> list[dict[str, Any]]:
        store = ErrorStore()
        store.clear()
        try:
            callback(*args, **kwargs)
        except ConnectorError as err:
            store.record_error(err)
        # A failed run must not stop the schedule
        except Exception as err:  # noqa: BLE001
            store.record_error(_unknown_error(err))
        # No finally: a return there would swallow SystemExit and KeyboardInterrupt
        errors = [error.convert_to_pycti_format() for error in store.get_errors()]
        store.clear()
        return errors

    return wrapper
