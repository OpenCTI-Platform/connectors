"""Base class for the Mattermost external-import connector.

The class is intentionally kept self-contained so the connector can run both
inside Docker (configuration via environment variables) and as a plain
Python process (configuration via ``src/config.yml``). It is *not* a copy of
the shared base used by older connectors — the previous version had three
notable bugs flagged in review:

* ``update_existing_data`` was eventually stored as the string ``"false"``,
  i.e. a truthy value, when the configured value was invalid;
* the scheduler always slept for 60s, which broke short
  ``CONNECTOR_RUN_EVERY`` values (e.g. ``30s``);
* timestamps were computed with the deprecated naive
  :func:`datetime.utcfromtimestamp`.

All three issues are addressed below.
"""

import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import stix2
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

_INTERVAL_UNITS: Dict[str, int] = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 60 * 60 * 24,
}

# Floor for the inner ``time.sleep`` so short ``CONNECTOR_RUN_EVERY`` values
# remain responsive while keeping the connector idle when the next run is far
# in the future.
_MIN_SLEEP_SECONDS = 1
_MAX_SLEEP_SECONDS = 60


class ExternalImportConnector:
    """Specific external-import connector.

    Subclasses must implement :meth:`_collect_intelligence` to return a list
    of STIX 2.1 objects.
    """

    def __init__(self) -> None:
        config = self._load_config()
        self.helper = OpenCTIConnectorHelper(config)

        # CONNECTOR_RUN_EVERY ----------------------------------------------
        interval = get_config_variable(
            "CONNECTOR_RUN_EVERY",
            ["connector", "run_every"],
            config,
            default=None,
        )
        if not isinstance(interval, str) or not interval.strip():
            msg = (
                "CONNECTOR_RUN_EVERY is required and must be a string of the "
                "form '<int><d|h|m|s>' (e.g. '7d', '12h', '10m', '30s')."
            )
            self.helper.log_error(msg)
            raise ValueError(msg)
        self.interval: str = interval.lower().strip()
        # Validate eagerly so the operator gets a clear error at startup.
        self._get_interval()

        # CONNECTOR_UPDATE_EXISTING_DATA -----------------------------------
        raw_update = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
            default=False,
        )
        self.update_existing_data: bool = self._coerce_bool(raw_update, default=False)

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_config() -> Dict[str, Any]:
        """Return the configuration dictionary used to build the helper.

        When ``src/config.yml`` is present (next to ``main.py``) the file is
        loaded with :func:`yaml.safe_load`. Otherwise an empty mapping is
        returned and ``OpenCTIConnectorHelper`` will use environment
        variables.
        """
        config_file_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config.yml",
        )
        if not os.path.isfile(config_file_path):
            return {}
        with open(config_file_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}

    @staticmethod
    def _coerce_bool(value: Any, *, default: bool) -> bool:
        """Return a sane :class:`bool` from a user-provided value."""
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            normalised = value.strip().lower()
            if normalised in ("true", "1", "yes", "on"):
                return True
            if normalised in ("false", "0", "no", "off", ""):
                return False
        return default

    # ------------------------------------------------------------------
    # Interval handling
    # ------------------------------------------------------------------
    def _get_interval(self) -> int:
        """Return the configured interval in **seconds**."""
        unit = self.interval[-1]
        if unit not in _INTERVAL_UNITS:
            msg = (
                f"CONNECTOR_RUN_EVERY value '{self.interval}' has an "
                "unsupported time unit. Expected one of d, h, m, s."
            )
            self.helper.log_error(msg)
            raise ValueError(msg)
        try:
            magnitude = int(self.interval[:-1])
        except ValueError as exc:
            msg = (
                f"CONNECTOR_RUN_EVERY value '{self.interval}' is not a "
                f"valid integer prefix: {exc}"
            )
            self.helper.log_error(msg)
            raise ValueError(msg) from exc
        if magnitude < 0:
            msg = (
                f"CONNECTOR_RUN_EVERY value '{self.interval}' must be a "
                "non-negative integer."
            )
            self.helper.log_error(msg)
            raise ValueError(msg)
        return magnitude * _INTERVAL_UNITS[unit]

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------
    def _collect_intelligence(self, since: Optional[datetime]) -> List[Any]:
        """Return the STIX objects produced for this scheduling cycle."""
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
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info(f"{self.helper.connect_name} connector stopped")
                sys.exit(0)
            except Exception as exc:  # noqa: BLE001 - last-resort safety net
                self.helper.log_error(str(exc))

            if self.helper.connect_run_and_terminate:
                self.helper.log_info(f"{self.helper.connect_name} connector ended")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(self._sleep_seconds(interval_seconds))

    def _run_cycle(self, *, last_run: Optional[int], timestamp: int) -> None:
        """Execute one collection cycle and persist the new ``last_run``.

        ``last_run`` is only advanced and the work is only marked as
        successfully processed when the entire cycle (collection +
        bundle send) completes without raising. On failure, the work
        is marked in-error and the cursor is left untouched so the
        next run retries from the same window instead of silently
        dropping data.
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
                    update=self.update_existing_data,
                    work_id=work_id,
                )
        except Exception as exc:  # noqa: BLE001 - we keep looping on errors
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
        """Return the number of seconds to sleep before checking again.

        Capped to :data:`_MAX_SLEEP_SECONDS` so the connector stays
        responsive to shutdown signals on long intervals, and to the
        configured interval (with a small floor) so users that set a short
        ``CONNECTOR_RUN_EVERY`` (e.g. ``30s``) actually see their jobs fire
        on time instead of being delayed by an unconditional 60s sleep.
        """
        if interval_seconds <= 0:
            return _MIN_SLEEP_SECONDS
        return max(_MIN_SLEEP_SECONDS, min(_MAX_SLEEP_SECONDS, interval_seconds))
