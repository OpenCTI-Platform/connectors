"""Connector external-import loop"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Callable

from pycti import OpenCTIConnectorHelper

__all__ = [
    "ConnectorLoop",
]

log = logging.getLogger(__name__)


class ConnectorLoop(threading.Thread):
    """Helper that reduces external-import boilerplate for looping and state management"""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        interval: int,
        loop_interval: int,
        callback: Callable[[str], None],
        stop_on_error: bool = False,
    ) -> None:
        """
        Create a new ListenQueue object
        :param helper: Connector helper
        :param interval: Interval between runs in seconds
        :param loop_interval: Interval between loops between runs in seconds
        :param callback: callback(work_id), executed after the interval has elapsed
        :param stop_on_error: Stop looping when an unhandled exception is thrown
        """
        super().__init__()
        self._helper = helper
        self._interval = interval
        self._loop_interval = loop_interval
        self._callback = callback
        self._stop_on_error = stop_on_error
        self._exit_event = threading.Event()

    def run(self) -> None:
        """
        Run the connector loop.
        :return: None
        """
        log.info("Starting connector loop")

        while True:
            try:
                self._run_loop()
            except KeyboardInterrupt:
                log.info("Connector stop (interrupt)")
                break
            except SystemExit:
                log.info("Connector stop (exit)")
                break
            except Exception as ex:
                log.exception("Unhandled exception in connector loop: %s", ex)
                if self._stop_on_error:
                    break

            if self._helper.connect_run_and_terminate:
                log.info("Connector stop (run-once)")
                break

            if self._exit_event.is_set():
                log.info("Connector stop (event)")
                break

            time.sleep(self._loop_interval)

        # Ensure the state is pushed
        self._helper.force_ping()

    def _run_loop(self) -> None:
        """
        The looping portion of the connector loop.
        :return: None
        """
        # Get the current timestamp and check
        state = self._helper.get_state() or {}

        now = datetime.utcnow().replace(microsecond=0)
        last_run = state.get("last_run", 0)
        last_run = datetime.utcfromtimestamp(last_run).replace(microsecond=0)

        if last_run.year == 1970:
            log.info("Connector has never run")
        else:
            log.info(f"Connector last run: {last_run}")

        # Check the difference between now and the last run to the interval
        if (now - last_run).total_seconds() > self._interval:
            log.info("Connector will now run")
            last_run = now

            name = self._helper.connect_name or "Connector"
            work_id = self._helper.api.work.initiate_work(
                self._helper.connect_id,
                f"{name} run @ {now}",
            )

            try:
                self._callback(work_id)
            except Exception as ex:
                log.exception(f"Unhandled exception processing connector feed: %s", ex)
                self._helper.api.work.to_processed(work_id, f"Failed: {ex}", True)
            else:
                log.info("Connector successfully run")
                self._helper.api.work.to_processed(work_id, "Complete")

            # Get the state again, incase it changed in the callback
            state = self._helper.get_state() or {}

            # Store the start time as the last run
            state["last_run"] = int(now.timestamp())
            self._helper.set_state(state)

            next_run = last_run + timedelta(seconds=self._interval)
            log.info(f"Last_run stored, next run at %s", next_run)
        else:
            next_run = last_run + timedelta(seconds=self._interval)
            log.info(f"Connector will not run, next run at %s", next_run)

    def stop(self) -> None:
        """
        Stop the thread
        :return: None
        """
        self._exit_event.set()
