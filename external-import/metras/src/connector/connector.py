"""Metras Feed connector (EXTERNAL_IMPORT).

Polls EDR alerts, binaries and endpoints from Metras and imports them into
OpenCTI as STIX. Incremental: alerts filter client-side on last_occurrence_time
(no fromTime param), binaries use server-side fromTime windowing.
"""

import sys
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from connector.converter_to_stix import ConverterToStix
from connector.utils import is_newer_than, normalize_timestamp, stix_timestamp
from metras_client import MetrasAPIError, MetrasClient
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings


class MetrasFeedConnector:
    def __init__(
        self, config: "ConnectorSettings", helper: OpenCTIConnectorHelper
    ) -> None:
        self.config = config
        self.helper = helper
        cfg = config.metras
        self.client = MetrasClient(
            helper=helper,
            base_url=str(cfg.api_base_url),
            api_key=cfg.api_key.get_secret_value(),
            verify_ssl=cfg.verify_ssl,
        )
        self.converter = ConverterToStix(helper, tlp_level=cfg.tlp_level)
        self.cfg = cfg
        self._interval = self._duration_seconds(config.connector.duration_period)

    @staticmethod
    def _duration_seconds(duration: timedelta | str) -> int:
        """Resolve CONNECTOR_DURATION_PERIOD (timedelta or ISO8601 string) to seconds."""
        if hasattr(duration, "total_seconds"):
            return max(60, int(duration.total_seconds()))
        # Minimal ISO8601 duration parse (PT#H#M#S / P#D) as a fallback.
        import re

        text = str(duration or "PT1H").upper()
        match = re.fullmatch(
            r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", text
        )
        if not match:
            return 3600
        days, hours, minutes, seconds = (int(g or 0) for g in match.groups())
        total = days * 86400 + hours * 3600 + minutes * 60 + seconds
        return max(60, total or 3600)

    # ------------------------------------------------------------------ #
    def run(self) -> None:
        try:
            self.client.ping()
            self.helper.connector_logger.info(
                "[CONNECTOR] Metras API connection verified"
            )
        except MetrasAPIError as exc:
            self.helper.connector_logger.error(
                "[CONNECTOR] Metras API ping failed at startup", {"error": str(exc)}
            )
            sys.exit(1)

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting Metras Feed import loop",
            {"interval_seconds": self._interval},
        )
        while True:
            try:
                self._import_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.connector_logger.info("[CONNECTOR] Stopping")
                break
            except Exception as exc:  # noqa: BLE001 - keep the loop alive
                self.helper.connector_logger.error(
                    "[CONNECTOR] Import cycle crashed", {"error": str(exc)}
                )
            time.sleep(self._interval)

    # ------------------------------------------------------------------ #
    def _import_data(self) -> None:
        state = self.helper.get_state() or {}
        alerts_cursor = normalize_timestamp(state.get("alerts_last_occurrence"))
        binaries_cursor = state.get("binaries_last_seen")  # ISO string for fromTime

        now_iso = stix_timestamp(datetime.now(timezone.utc))
        friendly = f"Metras Feed import @ {now_iso}"
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, friendly)

        all_objects = [self.converter.author_object()]
        new_alerts_max = alerts_cursor
        new_binaries_max = binaries_cursor
        counts = {"alerts": 0, "binaries": 0, "endpoints": 0}
        errors = []

        # --- EDR alerts (client-side incremental) ---
        if self.cfg.import_alerts:
            try:
                for alert in self.client.iter_edr_alerts(page_size=self.cfg.page_size):
                    ts = alert.get("last_occurrence_time")
                    if not is_newer_than(ts, alerts_cursor):
                        continue
                    objs = self.converter.process_alert(alert)
                    if objs:
                        all_objects.extend(objs)
                        counts["alerts"] += 1
                    parsed = normalize_timestamp(ts)
                    if parsed and (new_alerts_max is None or parsed > new_alerts_max):
                        new_alerts_max = parsed
                self.helper.connector_logger.info(
                    "[CONNECTOR] Alerts processed", {"new_incidents": counts["alerts"]}
                )
            except MetrasAPIError as exc:
                errors.append(f"alerts: {exc}")
                self.helper.connector_logger.error(
                    "[CONNECTOR] Alert import failed", {"error": str(exc)}
                )

        # --- Binaries (server-side fromTime window) ---
        if self.cfg.import_binaries:
            try:
                for binary in self.client.iter_binaries(
                    from_time=binaries_cursor, page_size=self.cfg.page_size
                ):
                    objs = self.converter.process_binary(
                        binary, malicious_only=self.cfg.binary_malicious_only
                    )
                    if objs:
                        all_objects.extend(objs)
                        counts["binaries"] += 1
                    last_seen = binary.get("last_seen")
                    if last_seen and (
                        new_binaries_max is None or last_seen > new_binaries_max
                    ):
                        new_binaries_max = last_seen
                self.helper.connector_logger.info(
                    "[CONNECTOR] Binaries processed", {"new_files": counts["binaries"]}
                )
            except MetrasAPIError as exc:
                errors.append(f"binaries: {exc}")
                self.helper.connector_logger.error(
                    "[CONNECTOR] Binary import failed", {"error": str(exc)}
                )

        # --- Endpoints (full inventory each run) ---
        if self.cfg.import_endpoints:
            try:
                payload = self.client.list_endpoints()
                for endpoint in payload.get("endpoints") or []:
                    objs = self.converter.process_endpoint(endpoint)
                    if objs:
                        all_objects.extend(objs)
                        counts["endpoints"] += 1
                self.helper.connector_logger.info(
                    "[CONNECTOR] Endpoints processed",
                    {"endpoints": counts["endpoints"]},
                )
            except MetrasAPIError as exc:
                errors.append(f"endpoints: {exc}")
                self.helper.connector_logger.error(
                    "[CONNECTOR] Endpoint import failed", {"error": str(exc)}
                )

        total = counts["alerts"] + counts["binaries"] + counts["endpoints"]

        # Total failure: every enabled category errored and nothing produced.
        if errors and total == 0:
            msg = "Metras import failed: " + "; ".join(errors)
            self.helper.api.work.to_processed(work_id, msg, in_error=True)
            self.helper.connector_logger.error(
                "[CONNECTOR] Import cycle failed", {"msg": msg}
            )
            return

        if len(all_objects) > 1:  # more than just the author
            bundle = self.helper.stix2_create_bundle(all_objects)
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, cleanup_inconsistent_bundle=True
            )
            msg = (
                f"Imported {counts['alerts']} incidents, {counts['binaries']} files, "
                f"{counts['endpoints']} endpoints ({len(all_objects)} STIX objects)"
            )
        else:
            msg = "No new Metras data to import"

        if errors:
            msg += " | partial errors: " + "; ".join(errors)
        self.helper.api.work.to_processed(work_id, msg)
        self.helper.connector_logger.info(
            "[CONNECTOR] Import cycle done", {"summary": msg}
        )

        # Advance cursors only for categories that did not hard-fail.
        new_state = dict(state)
        if "alerts" not in "".join(errors) and new_alerts_max is not None:
            new_state["alerts_last_occurrence"] = stix_timestamp(new_alerts_max)
        if "binaries" not in "".join(errors) and new_binaries_max:
            new_state["binaries_last_seen"] = new_binaries_max
        new_state["last_run"] = now_iso
        self.helper.set_state(new_state)
