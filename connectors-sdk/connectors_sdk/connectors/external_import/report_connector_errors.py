"""Report to OpenCTI the errors of each run of an external import connector.

Use ``report_connector_errors`` on the callback that an external import connector
gives to ``helper.schedule_process``. The connector never calls the ``ErrorStore``:
every ``ConnectorError`` created during the run records itself, and the decorator
reports all of them to pycti at the end of the run.
"""

import functools
from collections.abc import Callable
from typing import ParamSpec

from connectors_sdk.exceptions.error_store import ErrorStore
from connectors_sdk.logger import get_logger

P = ParamSpec("P")

logger = get_logger(__name__)


def report_connector_errors(callback: Callable[P, object]) -> Callable[P, None]:
    """Report to pycti the errors created during each run of ``callback``.

    For each call of the returned function:

    - The ``ErrorStore`` is emptied and starts recording, then ``callback`` is
      called.
    - A ``ConnectorError`` created during the run records itself, even when the
      connector handles it (for example, logs it and skips an item).
    - An exception that escapes ``callback`` is logged with its traceback and
      recorded.

    The callback's top-level ``except`` must re-raise the error instead of
    swallowing it, so that it is reported.

    Use it as a decorator on the callback, or as a function that wraps the callback.

    Args:
        callback: The ``message_callback`` that the connector gives to
            ``helper.schedule_process``. Its return value is ignored.

    Returns:
        A function with the same parameters as ``callback``, which returns ``None``.

    Raises:
        ExceptionGroup: At the end of a run that recorded errors, with all of them,
            in the order they were recorded. It is raised even when every error is
            a ``WARNING``: raising is how the errors reach pycti, not a sign that the
            connector's run failed.

    Examples:
        As a decorator::

            from connectors_sdk import report_connector_errors

            class MyConnector:
                @report_connector_errors
                def process_message(self) -> None:
                    try:
                        ...
                    except Exception as err:
                        self.logger.error(
                            "Connector run failed", meta={"error": str(err)}
                        )
                        raise  # reported by the decorator

                def run(self) -> None:
                    self.helper.schedule_process(
                        message_callback=self.process_message,
                        duration_period=self.duration_period,
                    )

        As a function that wraps the callback::

            self.helper.schedule_process(
                message_callback=report_connector_errors(self.process_message),
                duration_period=self.duration_period,
            )
    """

    @functools.wraps(callback)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
        error_store = ErrorStore()
        error_store.start_recording()

        try:
            callback(*args, **kwargs)

        except (KeyboardInterrupt, SystemExit):
            # A stop (Ctrl+C, container stop, sys.exit) is not a connector error.
            # Do not record it and do not convert it: re-raise it as it is, so that
            # pycti handles the stop and a SystemExit keeps its exit code.
            logger.info("Connector stopped by user or system")
            raise

        except Exception as err:
            logger.exception("Connector's run failed", meta={"error": str(err)})
            # Recorded as it is, never wrapped. A ConnectorError that recorded
            # itself when it was created is ignored by the store.
            error_store.record_error(err)

        finally:
            errors = error_store.stop_recording()

        # Raise after the try, never in the finally: a raise in the finally would
        # replace a KeyboardInterrupt or a SystemExit
        if errors:
            raise ExceptionGroup("Errors during the connector's run", errors)

    return wrapper
