"""Base class for the Intel 471 darknet external-import connector.

The configuration is loaded and validated by :class:`settings.ConnectorSettings`
(environment variables, ``src/config.yml`` or ``config.yml``), so the
connector runs both inside Docker and as a plain Python process.

Notable behaviours:

* ``CONNECTOR_DURATION_PERIOD`` (or the deprecated ``CONNECTOR_RUN_EVERY``)
  must be strictly positive: a clear ``ValueError`` is raised at startup
  otherwise.
* Timestamps are computed with timezone-aware :func:`datetime.now` /
  :func:`datetime.fromtimestamp`.
* ``_run_cycle`` only advances ``last_run`` (and marks the work as
  successful) when collection and bundle send both complete without
  raising; otherwise the work is marked in-error and the cursor is
  left untouched so the next run retries from the same window.
"""

import sys
import time
from datetime import datetime, timezone

import stix2
from pycti import OpenCTIConnectorHelper
from settings import ConnectorSettings

_MIN_SLEEP_SECONDS = 1
_MAX_SLEEP_SECONDS = 60


class ExternalImportConnector:
    """Specific external-import connector.

    Subclasses must implement :meth:`_collect_intelligence`.
    """

    def __init__(self) -> None:
        self.config = ConnectorSettings()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())

        # Validate eagerly so the operator gets a clear error at startup.
        self._get_interval()

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------
    def _get_interval(self) -> int:
        interval_seconds = int(self.config.connector.duration_period.total_seconds())
        if interval_seconds <= 0:
            # A zero interval (e.g. ``PT0S``) would make
            # ``elapsed >= interval_seconds`` true on every iteration
            # and the worker loop would call ``_collect_intelligence``
            # back-to-back with only the inner one-second floor from
            # ``_sleep_seconds`` between attempts — hammering Intel 471
            # and OpenCTI for no good reason. Require a strictly
            # positive interval so a misconfiguration cannot push the
            # connector into a tight collection loop.
            msg = (
                f"CONNECTOR_DURATION_PERIOD value "
                f"'{self.config.connector.duration_period}' must be strictly "
                "positive."
            )
            self.helper.log_error(msg)
            raise ValueError(msg)
        return interval_seconds

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------
    def _collect_intelligence(self, since=None) -> list:
        raise NotImplementedError

    def run(self) -> None:
        self.helper.log_info(f"Starting {self.helper.connect_name} connector...")
        interval_seconds = self._get_interval()
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state() or {}
                last_run = current_state.get("last_run")
                if last_run is not None:
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector last run: "
                        + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector has never run"
                    )

                elapsed = None if last_run is None else (timestamp - last_run)
                if last_run is None or elapsed >= interval_seconds:
                    self._run_cycle(last_run=last_run, timestamp=timestamp)
                else:
                    remaining = interval_seconds - elapsed
                    self.helper.log_info(
                        f"{self.helper.connect_name} connector will not run, "
                        f"next run in: {remaining}s"
                    )
            except KeyboardInterrupt:
                # ``Ctrl+C`` / ``SIGINT``: graceful operator-initiated
                # shutdown. Always exit ``0`` so container supervisors
                # do not treat the deliberate signal as a crash that
                # should trigger a restart backoff.
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except SystemExit:
                # Re-raise so the original ``SystemExit.code`` propagates
                # to the orchestrator. Catching it here and unconditionally
                # exiting ``0`` would mask any non-zero status raised
                # from helper code or future fatal preconditions /
                # health checks and make real failures look like clean
                # exits.
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                raise
            except Exception as exc:  # noqa: BLE001 - last-resort safety net
                self.helper.log_error(str(exc))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(self._sleep_seconds(interval_seconds))

    def _run_cycle(self, *, last_run, timestamp: int) -> None:
        """Execute one collection cycle and persist the new ``last_run``.

        ``last_run`` is only advanced and the work is only marked as
        successfully processed when the entire cycle (collection +
        bundle send) completes without raising. On failure, the work
        is marked in-error and the cursor is left untouched so the
        next run retries from the same window instead of silently
        skipping the failed window.
        """
        self.helper.log_info(f"{self.helper.connect_name} will run!")
        now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        friendly_name = f"{self.helper.connect_name} run @ " + now.strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        try:
            since = (
                datetime.fromtimestamp(last_run, tz=timezone.utc)
                if last_run is not None
                else None
            )
            bundle_objects = self._collect_intelligence(since=since) or []
            if bundle_objects:
                bundle = stix2.Bundle(
                    objects=bundle_objects, allow_custom=True
                ).serialize()
                self.helper.log_info(
                    f"Sending {len(bundle_objects)} STIX objects to OpenCTI..."
                )
                self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                )
        except Exception as exc:  # noqa: BLE001 - keep looping on errors
            self.helper.log_error(
                f"{self.helper.connect_name} run failed: {exc}. "
                "last_run will NOT be advanced."
            )
            try:
                self.helper.api.work.to_processed(
                    work_id, f"Run failed: {exc}", in_error=True
                )
            except Exception as report_exc:  # noqa: BLE001
                self.helper.log_error(
                    f"Could not mark work {work_id} as failed: {report_exc}"
                )
            return

        message = (
            f"{self.helper.connect_name} connector successfully run, "
            f"storing last_run as {timestamp}"
        )
        self.helper.log_info(message)
        current_state = self.helper.get_state() or {}
        current_state["last_run"] = timestamp
        self.helper.set_state(current_state)
        self.helper.api.work.to_processed(work_id, message)

    def _sleep_seconds(self, interval_seconds: int) -> int:
        if interval_seconds <= 0:
            return _MIN_SLEEP_SECONDS
        return max(_MIN_SLEEP_SECONDS, min(_MAX_SLEEP_SECONDS, interval_seconds))
