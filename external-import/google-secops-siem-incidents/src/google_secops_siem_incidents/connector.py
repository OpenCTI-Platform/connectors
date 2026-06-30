"""Google SecOps external-import connector."""

import asyncio
import sys
import traceback
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import google.auth.exceptions
from google_secops_siem_incidents.client_api import GoogleSecOpsApiClient
from google_secops_siem_incidents.converter_to_stix import ConverterToStix
from google_secops_siem_incidents.settings import ConnectorSettings
from google_secops_siem_incidents.state_manager import GoogleSecOpsSIEMState
from google_secops_siem_incidents.utils.timestamps import parse_ts as _parse_ts
from pycti import OpenCTIConnectorHelper

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
        self._secops_base_url: str | None = None

        secops_siem_config = self.config.google_secops_siem_incidents
        self.converter_to_stix = ConverterToStix(
            helper=self.helper,
            tlp_level=secops_siem_config.tlp_level,
            severity_filter=secops_siem_config.severity_filter,
            priority_filter=secops_siem_config.priority_filter,
            risk_score_filter=secops_siem_config.risk_score_filter,
            tags_include=secops_siem_config.tags_include or None,
            tags_exclude=secops_siem_config.tags_exclude or None,
        )

    @property
    def client(self) -> GoogleSecOpsApiClient:
        """Lazy-initialize and return the API client.

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

    async def _resolve_secops_base_url(self) -> str | None:
        """Fetch instance info and extract the first SecOps URL.

        Returns:
            Base SecOps URL string, or None if unavailable.
        """
        try:
            instance_info = await self.client.fetch_instance_info()
            if instance_info.secops_urls:
                url = instance_info.secops_urls[0].rstrip("/")
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} SecOps base URL resolved",
                    meta={"secops_base_url": url},
                )
                return url
            self.helper.connector_logger.warning(
                f"{_LOG_PREFIX} Instance info returned no secopsUrls — "
                "external references will not be attached to incidents."
            )
        except Exception as err:
            self.helper.connector_logger.warning(
                f"{_LOG_PREFIX} Failed to fetch instance info — "
                "external references will not be attached to incidents.",
                meta={"reason": str(err)},
            )
        return None

    def _collect_intelligence(self, state: GoogleSecOpsSIEMState | None = None) -> None:
        """Run the async fetch-and-send pipeline synchronously via asyncio.run.

        Args:
            state: Pre-loaded state; loads a fresh one when None.
        """
        if state is None:
            state = GoogleSecOpsSIEMState()
            state.inject_dependencies(self.helper)
            state.load()
        asyncio.run(self._async_process_message(state))

    async def _async_process_message(self, state: GoogleSecOpsSIEMState) -> None:
        """Fetch rule alerts, convert to STIX bundles, and persist state.

        Args:
            state: Current connector state with timestamp and pagination fields.
        """
        try:
            secops_base_url = await self._resolve_secops_base_url()
            if secops_base_url != self._secops_base_url:
                self._secops_base_url = secops_base_url
                self.converter_to_stix.secops_base_url = secops_base_url

            start_time, end_time, global_max_ts, first_run, resumed = (
                self._resolve_time_window(state)
            )
            self._log_run_started(start_time, end_time, first_run, resumed)

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

                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Batch fetched",
                    meta={
                        "batch_num": batch_num,
                        "rule_alerts": len(response.rule_alerts),
                        "alerts": alert_count,
                    },
                )

                stix_objects, batch_max_ts = self._convert_batch(response)
                global_max_ts = self._advance_max_ts(global_max_ts, batch_max_ts)

                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Batch converted to STIX",
                    meta={
                        "batch_num": batch_num,
                        "stix_count": f"{len(stix_objects)} (~{_unique_count(stix_objects)} unique)",
                        "type_summary": _type_summary(stix_objects),
                    },
                )

                if stix_objects:
                    work_id = self._send_bundle(
                        stix_objects, work_id, friendly_name, batch_num
                    )
                    total_stix_objects += len(stix_objects)
                    total_unique_ids.update(
                        _obj_id(o) for o in stix_objects if _obj_id(o)
                    )

                if response.too_many_alerts:
                    self._save_pagination_checkpoint(
                        response, state, start_time, global_max_ts, batch_num
                    )

            self._finalize_run(
                state,
                work_id,
                batch_num,
                global_max_ts,
                total_alerts,
                total_stix_objects,
                total_unique_ids,
                start_time,
                end_time,
            )
        except google.auth.exceptions.RefreshError as err:
            self.helper.connector_logger.error(
                f"{_LOG_PREFIX} Google authentication failed — "
                "verify GOOGLE_SECOPS_SIEM_INCIDENTS_CREDENTIALS_JSON "
                "contains a valid service account key with the correct scopes.",
                meta={"reason": str(err), "traceback": traceback.format_exc()},
            )
        except Exception as err:
            self.helper.connector_logger.error(
                f"{_LOG_PREFIX} Unexpected error during async run",
                meta={"reason": str(err), "traceback": traceback.format_exc()},
            )
        finally:
            await self.client.close()

    def _resolve_time_window(
        self, state: GoogleSecOpsSIEMState
    ) -> tuple[str, str, str | None, bool, bool]:
        """Determine the query time window from state or config defaults.

        Returns:
            Tuple of (start_time, end_time, global_max_ts, first_run, resumed).
        """
        checkpoint = state.pagination_checkpoint
        if checkpoint:
            return (
                checkpoint["window_start"],
                checkpoint["window_end"],
                checkpoint.get("run_max_ts"),
                False,
                True,
            )

        last_alert_ts = state.last_alert_timestamp
        start_time = last_alert_ts.isoformat() if last_alert_ts is not None else None
        first_run = start_time is None
        if first_run:
            lookback = self.config.google_secops_siem_incidents.first_start_time
            start_time = (datetime.now(tz=timezone.utc) - lookback).isoformat()
        end_time = datetime.now(tz=timezone.utc).isoformat()
        return start_time, end_time, None, first_run, False

    def _log_run_started(
        self, start_time: str, end_time: str, first_run: bool, resumed: bool
    ) -> None:
        """Emit the 'Run started' structured log."""
        _log_extra: dict[str, Any] = {
            "start_time": start_time,
            "end_time": end_time,
            "first_run": first_run,
        }
        if resumed:
            _log_extra["resumed"] = True
        self.helper.connector_logger.info(f"{_LOG_PREFIX} Run started", meta=_log_extra)

    def _convert_batch(self, response: Any) -> tuple[list[Any], str | None]:
        """Convert all alerts in a response batch to STIX objects.

        Returns:
            Tuple of (stix_objects, batch_max_detection_timestamp).
        """
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
                if batch_max_ts is None or _parse_ts(ts) > _parse_ts(batch_max_ts):
                    batch_max_ts = ts

        return stix_objects, batch_max_ts

    @staticmethod
    def _advance_max_ts(
        global_max_ts: str | None, batch_max_ts: str | None
    ) -> str | None:
        """Return the later of global_max_ts and batch_max_ts."""
        if batch_max_ts is None:
            return global_max_ts
        if global_max_ts is None or _parse_ts(batch_max_ts) > _parse_ts(global_max_ts):
            return batch_max_ts
        return global_max_ts

    def _send_bundle(
        self,
        stix_objects: list[Any],
        work_id: str | None,
        friendly_name: str,
        batch_num: int,
    ) -> str:
        """Order objects, append author/marking, bundle, and send to OpenCTI.

        Returns:
            The work_id (created on first call, reused after).
        """
        ordered = [o for o in stix_objects if _obj_type(o) != "relationship"] + [
            o for o in stix_objects if _obj_type(o) == "relationship"
        ]
        ordered.extend(
            [self.converter_to_stix.author, self.converter_to_stix.tlp_marking]
        )
        if work_id is None:
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                friendly_name,
            )
        stix_bundle = self.helper.stix2_create_bundle(ordered)
        self.helper.send_stix2_bundle(
            stix_bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )
        self.helper.connector_logger.info(
            f"{_LOG_PREFIX} Bundle sent",
            meta={
                "batch_num": batch_num,
                "work_id": work_id,
                "stix_count": f"{len(ordered)} (~{_unique_count(ordered)} unique)",
                "type_summary": _type_summary(ordered),
            },
        )
        return work_id

    def _save_pagination_checkpoint(
        self,
        response: Any,
        state: GoogleSecOpsSIEMState,
        start_time: str,
        global_max_ts: str | None,
        batch_num: int,
    ) -> None:
        """Persist a pagination checkpoint when too_many_alerts is True."""
        pivot = GoogleSecOpsApiClient.compute_pagination_pivot(response)
        if pivot is None or global_max_ts is None:
            return
        pivot_dt = _parse_ts(pivot)
        max_dt = _parse_ts(global_max_ts)
        state.pagination_checkpoint = {
            "window_start": start_time,
            "window_end": pivot_dt.isoformat(),
            "run_max_ts": max_dt.isoformat(),
        }
        state.save()
        self.helper.connector_logger.info(
            f"{_LOG_PREFIX} State checkpoint",
            meta={
                "batch_num": batch_num,
                "window_end": pivot_dt.isoformat(),
                "run_max_ts": max_dt.isoformat(),
            },
        )

    def _finalize_run(
        self,
        state: GoogleSecOpsSIEMState,
        work_id: str | None,
        batch_num: int,
        global_max_ts: str | None,
        total_alerts: int,
        total_stix_objects: int,
        total_unique_ids: set[str],
        start_time: str,
        end_time: str,
    ) -> None:
        """Mark work as processed, persist final state, and log run completion."""
        if work_id is not None:
            self.helper.api.work.to_processed(
                work_id, f"{self.helper.connect_name} run completed"
            )

        if batch_num > 0:
            state.pagination_checkpoint = None
            if global_max_ts is not None:
                max_dt = _parse_ts(global_max_ts)
                state.last_alert_timestamp = max_dt + timedelta(seconds=1)
            state.save()
            if global_max_ts is not None:
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} State updated",
                    meta={
                        "total_batches": batch_num,
                        "last_alert_timestamp": (
                            state.last_alert_timestamp.isoformat()
                            if state.last_alert_timestamp
                            else None
                        ),
                    },
                )

        self.helper.connector_logger.info(
            f"{_LOG_PREFIX} Run completed",
            meta={
                "total_batches": batch_num,
                "total_alerts": total_alerts,
                "total_stix_objects": f"{total_stix_objects} (~{len(total_unique_ids)} unique)",
                "start_time": start_time,
                "end_time": end_time,
            },
        )

    def process_message(self) -> None:
        """Execute one connector run: log state, drive the async pipeline, and persist last_run."""
        try:
            state = GoogleSecOpsSIEMState()
            state.inject_dependencies(self.helper)
            state.load()

            if state.last_run is not None:
                self.helper.connector_logger.info(
                    f"{_LOG_PREFIX} Connector last run",
                    meta={"last_run_datetime": str(state.last_run)},
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
                meta={"connector_name": self.helper.connect_name},
            )
            sys.exit(0)

    def run(self) -> None:
        """Start the connector with recurring scheduled runs."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
