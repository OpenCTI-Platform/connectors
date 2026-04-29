"""Google SecOps external-import connector."""

import asyncio
import sys
import traceback
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import google.auth.exceptions
from pycti import OpenCTIConnectorHelper

from google_secops_siem_incidents.client_api import GoogleSecOpsApiClient
from google_secops_siem_incidents.converter_to_stix import ConverterToStix
from google_secops_siem_incidents.settings import ConnectorSettings
from google_secops_siem_incidents.state_manager import GoogleSecOpsSIEMState

_LOG_PREFIX = "[CONNECTOR]"


def _obj_type(o: Any) -> str:
    """Extract STIX type from a stix2 object or dict."""
    if isinstance(o, dict):
        return o.get("type", "")
    return getattr(o, "type", "")


def _obj_id(o: Any) -> str:
    """Extract STIX id from a stix2 object or dict."""
    if isinstance(o, dict):
        return o.get("id", "")
    return getattr(o, "id", "")


def _unique_count(stix_objects: list[Any]) -> int:
    """Count unique STIX objects by ID."""
    return len({_obj_id(o) for o in stix_objects if _obj_id(o)})


def _type_summary(stix_objects: list[Any]) -> str:
    """Return a compact STIX type count string with duplicate indication.

    Args:
        stix_objects: List of STIX objects (stix2 objects or dicts).

    Returns:
        Sorted comma-separated string, e.g. 'incident: 10 (~5 unique), ipv4-addr: 4'.
    """
    type_ids: dict[str, set[str]] = {}
    type_counts: Counter[str] = Counter()
    for o in stix_objects:
        t = _obj_type(o)
        type_counts[t] += 1
        obj_id = _obj_id(o)
        if obj_id:
            type_ids.setdefault(t, set()).add(obj_id)

    parts = []
    for t, total in sorted(type_counts.items()):
        unique = len(type_ids.get(t, set()))
        if unique and unique < total:
            parts.append(f"{t}: {total} (~{unique} unique)")
        else:
            parts.append(f"{t}: {total}")
    return ", ".join(parts)


class GoogleSecOpsConnector:
    """External-import connector that fetches Google SecOps SIEM incidents and sends them to OpenCTI."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialise the connector with configuration and helper.

        Args:
            config: Connector configuration.
            helper: OpenCTI helper instance.
        """
        self.config = config
        self.helper = helper
        self._client: GoogleSecOpsApiClient | None = None
        self.converter_to_stix = ConverterToStix(
            helper=self.helper,
            tlp_level=self.config.google_secops_siem_incidents.tlp_level,
        )

    @property
    def client(self) -> GoogleSecOpsApiClient:
        """Lazy-initialize and return the Chronicle API client.

        Returns:
            Initialised GoogleSecOpsApiClient instance.
        """
        if self._client is None:
            self._client = GoogleSecOpsApiClient(
                config=self.config.google_secops_siem_incidents,
            )
        return self._client

    @client.setter
    def client(self, value: Any) -> None:
        """Allow tests to inject a mock client.

        Args:
            value: Replacement client instance.
        """
        self._client = value

    def _collect_intelligence(self, state: GoogleSecOpsSIEMState | None = None) -> None:
        """Run the async fetch-and-send pipeline synchronously via asyncio.run.

        Args:
            state: Pre-loaded state; loads a fresh one when None.
        """
        if state is None:
            state = GoogleSecOpsSIEMState(helper=self.helper)
            state.load()
        asyncio.run(self._async_process_message(state))

    async def _async_process_message(self, state: GoogleSecOpsSIEMState) -> None:
        """Fetch Chronicle rule alerts, convert to STIX bundles, and persist state.

        Args:
            state: Current connector state with timestamp and pagination fields.
        """
        try:
            checkpoint = state.pagination_checkpoint

            if checkpoint:
                start_time = checkpoint["window_start"]
                end_time = checkpoint["window_end"]
                global_max_ts: str | None = checkpoint.get("run_max_ts")
                first_run = False
                resumed = True
            else:
                last_alert_ts = state.last_alert_timestamp
                start_time = (
                    last_alert_ts.isoformat() if last_alert_ts is not None else None
                )
                first_run = start_time is None
                if first_run:
                    lookback = self.config.google_secops_siem_incidents.first_start_time
                    start_time = (datetime.now(tz=timezone.utc) - lookback).isoformat()
                end_time = datetime.now(tz=timezone.utc).isoformat()
                global_max_ts = None
                resumed = False

            _log_extra: dict[str, Any] = {
                "start_time": start_time,
                "end_time": end_time,
                "first_run": first_run,
            }
            if resumed:
                _log_extra["resumed"] = True
            self.helper.connector_logger.info(
                f"{_LOG_PREFIX} Run started",
                _log_extra,
            )

            batch_num = 0
            total_alerts = 0
            total_stix_objects = 0
            total_unique_ids: set[str] = set()
            work_id: str | None = None
            friendly_name = f"{self.helper.connect_name} alerts"

            async for response in self.client.fetch_rule_alerts(
                start_time=start_time,
                end_time=end_time,
            ):
                batch_num += 1
                alert_count = sum(len(ra.alerts) for ra in response.rule_alerts)
                total_alerts += alert_count

                _log_extra = {
                    "batch_num": batch_num,
                    "rule_alerts": len(response.rule_alerts),
                    "alerts": alert_count,
                }
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Batch fetched",
                    _log_extra,
                )

                stix_objects: list[Any] = []
                batch_max_ts: str | None = None

                for rule_alert in response.rule_alerts:
                    for alert in rule_alert.alerts:
                        stix_objects.extend(
                            self.converter_to_stix.convert_rule_alert(
                                alert, rule_alert.rule_metadata
                            )
                        )
                        ts = alert.detection_timestamp
                        if batch_max_ts is None or (
                            datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            > datetime.fromisoformat(
                                batch_max_ts.replace("Z", "+00:00")
                            )
                        ):
                            batch_max_ts = ts

                if batch_max_ts is not None:
                    if global_max_ts is None or (
                        datetime.fromisoformat(batch_max_ts.replace("Z", "+00:00"))
                        > datetime.fromisoformat(global_max_ts.replace("Z", "+00:00"))
                    ):
                        global_max_ts = batch_max_ts

                _log_extra = {
                    "batch_num": batch_num,
                    "stix_count": f"{len(stix_objects)} (~{_unique_count(stix_objects)} unique)",
                    "type_summary": _type_summary(stix_objects),
                }
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Batch converted to STIX",
                    _log_extra,
                )

                if stix_objects:
                    stix_objects = [
                        o
                        for o in stix_objects
                        if _obj_type(o) != "relationship"
                    ] + [
                        o
                        for o in stix_objects
                        if _obj_type(o) == "relationship"
                    ]
                    if work_id is None:
                        work_id = self.helper.api.work.initiate_work(
                            self.helper.connect_id,
                            friendly_name,
                        )
                    stix_objects.extend([self.converter_to_stix.author, self.converter_to_stix.tlp_marking])
                    stix_bundle = self.helper.stix2_create_bundle(stix_objects)
                    self.helper.send_stix2_bundle(
                        stix_bundle,
                        work_id=work_id,
                        cleanup_inconsistent_bundle=True,
                    )
                    total_stix_objects += len(stix_objects)
                    total_unique_ids.update(
                        _obj_id(o) for o in stix_objects if _obj_id(o)
                    )
                    _log_extra = {
                        "batch_num": batch_num,
                        "work_id": work_id,
                        "stix_count": f"{len(stix_objects)} (~{_unique_count(stix_objects)} unique)",
                        "type_summary": _type_summary(stix_objects),
                    }
                    self.helper.connector_logger.info(
                        f"{_LOG_PREFIX} Bundle sent",
                        _log_extra,
                    )

                if response.too_many_alerts:
                    pivot = GoogleSecOpsApiClient._compute_pagination_pivot(response)
                    if pivot is not None and global_max_ts is not None:
                        pivot_dt = datetime.fromisoformat(pivot.replace("Z", "+00:00"))
                        max_dt = datetime.fromisoformat(
                            global_max_ts.replace("Z", "+00:00")
                        )
                        checkpoint_data = {
                            "window_start": start_time,
                            "window_end": pivot_dt.isoformat(),
                            "run_max_ts": max_dt.isoformat(),
                        }
                        state.pagination_checkpoint = checkpoint_data
                        state.save()
                        _log_extra = {
                            "batch_num": batch_num,
                            "window_end": pivot_dt.isoformat(),
                            "run_max_ts": max_dt.isoformat(),
                        }
                        self.helper.connector_logger.info(
                            f"{_LOG_PREFIX} State checkpoint",
                            _log_extra,
                        )

            if work_id is not None:
                self.helper.api.work.to_processed(
                    work_id, f"{self.helper.connect_name} run completed"
                )

            if batch_num > 0:
                state.pagination_checkpoint = None
                if global_max_ts is not None:
                    max_dt = datetime.fromisoformat(
                        global_max_ts.replace("Z", "+00:00")
                    )
                    state.last_alert_timestamp = max_dt + timedelta(seconds=1)
                state.save()
                if global_max_ts is not None:
                    _log_extra = {
                        "total_batches": batch_num,
                        "last_alert_timestamp": state.last_alert_timestamp.isoformat(),
                    }
                    self.helper.connector_logger.info(
                        f"{_LOG_PREFIX} State updated",
                        _log_extra,
                    )

            _log_extra = {
                "total_batches": batch_num,
                "total_alerts": total_alerts,
                "total_stix_objects": f"{total_stix_objects} (~{len(total_unique_ids)} unique)",
                "start_time": start_time,
                "end_time": end_time,
            }
            self.helper.connector_logger.info(
                f"{_LOG_PREFIX} Run completed",
                _log_extra,
            )
        except google.auth.exceptions.RefreshError as err:
            _log_extra = {"reason": str(err), "traceback": traceback.format_exc()}
            self.helper.connector_logger.error(
                f"{_LOG_PREFIX} Google authentication failed — "
                "verify GOOGLE_SECOPS_SIEM_INCIDENTS_CREDENTIALS_JSON "
                "contains a valid service account key with the correct scopes.",
                _log_extra,
            )
        except Exception as err:
            _log_extra = {"reason": str(err), "traceback": traceback.format_exc()}
            self.helper.connector_logger.error(
                f"{_LOG_PREFIX} Unexpected error during async run",
                _log_extra,
            )
        finally:
            await self.client.close()

    def process_message(self) -> None:
        """Execute one connector run: log state, drive the async pipeline, and persist last_run."""
        try:
            state = GoogleSecOpsSIEMState(helper=self.helper)
            state.load()

            if state.last_run is not None:
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Connector last run",
                    {"last_run_datetime": str(state.last_run)},
                )
            else:
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Connector has never run..."
                )

            self._collect_intelligence(state)

            state.last_run = datetime.now(tz=timezone.utc)
            state.save()

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                f"{_LOG_PREFIX} Connector stopped.",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)

    def run(self) -> None:
        """Start the connector with recurring scheduled runs."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
