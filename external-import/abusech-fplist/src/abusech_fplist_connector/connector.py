import logging
import sys
from datetime import datetime, timezone

from abusech_fplist_connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient

# Maps entry_type → STIX pattern template for Indicator lookup
INDICATOR_PATTERNS = {
    "sha256_hash": "[file:hashes.'SHA-256' = '{v}']",
    "md5_hash": "[file:hashes.MD5 = '{v}']",
    "sha1_hash": "[file:hashes.'SHA-1' = '{v}']",
    "sha3_384": "[file:hashes.'SHA3-384' = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "ip:port": (
        "[network-traffic:dst_ref.type = 'ipv4-addr' "
        "AND network-traffic:dst_ref.value = '{ip}' "
        "AND network-traffic:dst_port = {port}]"
    ),
}


class ConnectorAbusechFplist:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(helper, config)
        # pycti's API client logs every query at INFO ("Listing Indicators with
        # filters"), flooding the output on large FP lists
        if self.helper.log_level.lower() != "debug":
            logging.getLogger("api").setLevel(logging.WARNING)

    def _find_indicator(self, entry_type: str, entry_value: str) -> str | None:
        """Return the OpenCTI id of the matching Indicator, or None if not found."""
        pattern_template = INDICATOR_PATTERNS.get(entry_type)
        if not pattern_template:
            return None

        try:
            if entry_type == "ip:port":
                parts = entry_value.split(":")
                ip, port = parts[0], parts[1] if len(parts) > 1 else "0"
                pattern = pattern_template.format(ip=ip, port=port)
            else:
                pattern = pattern_template.format(v=entry_value.replace("'", "\\'"))

            result = self.helper.api.indicator.read(
                filters={
                    "mode": "and",
                    "filters": [{"key": "pattern", "values": [pattern]}],
                    "filterGroups": [],
                }
            )
            return result["id"] if result else None
        except Exception as err:
            self.helper.connector_logger.error(
                f"[CONNECTOR] Error searching indicator for {entry_value}",
                {"error": str(err)},
            )
            return None

    def _remove_entry(self, entry: dict) -> None:
        entry_type = entry["entry_type"]
        entry_value = entry["entry_value"]
        removal_id = entry["removal_id"]

        if not entry_value:
            self.helper.connector_logger.debug(
                f"[CONNECTOR] FP #{removal_id} has empty value, skipping",
                {"type": entry_type},
            )
            return

        self.helper.connector_logger.info(
            f"[CONNECTOR] Searching FP #{removal_id}",
            {"type": entry_type, "value": entry_value},
        )
        ind_id = self._find_indicator(entry_type, entry_value)
        if ind_id:
            if self.config.abusech_fplist.dry_run:
                self.helper.connector_logger.info(
                    f"[DRY RUN] Would delete indicator #{removal_id}",
                    {"type": entry_type, "value": entry_value, "id": ind_id},
                )
            else:
                self.helper.api.stix_domain_object.delete(id=ind_id)
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Deleted indicator #{removal_id}",
                    {"type": entry_type, "value": entry_value},
                )
        else:
            self.helper.connector_logger.debug(
                f"[CONNECTOR] FP #{removal_id} not found in OpenCTI (skipped)",
                {"type": entry_type, "value": entry_value},
            )

    def process_message(self) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        work_id = None
        try:
            current_state = self.helper.get_state() or {}
            last_removal_id = int(current_state.get("last_removal_id", 0))
            self.helper.connector_logger.info(
                "[CONNECTOR] Resuming from last removal_id",
                {"last_removal_id": last_removal_id},
            )

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                f"Connector {self.helper.connect_name}",
            )

            all_entries = self.client.get_fplist()

            new_entries = [
                e for e in all_entries if int(e["removal_id"]) > last_removal_id
            ]
            # Process oldest first so the marker always moves forward
            new_entries.sort(key=lambda e: int(e["removal_id"]))

            self.helper.connector_logger.info(
                f"[CONNECTOR] {len(new_entries)} new FP entries to process"
            )

            max_removal_id = last_removal_id
            for entry in new_entries:
                self._remove_entry(entry)
                max_removal_id = int(entry["removal_id"])

            if max_removal_id > last_removal_id:
                current_state["last_removal_id"] = max_removal_id
                current_state["last_run"] = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                self.helper.set_state(current_state)
                self.helper.connector_logger.info(
                    f"[CONNECTOR] State updated to removal_id={max_removal_id}"
                )

            message = (
                f"{self.helper.connect_name} run completed, "
                f"processed up to removal_id={max_removal_id}"
            )
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped.")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            if work_id:
                self.helper.api.work.to_processed(work_id, str(err), in_error=True)

    def run(self) -> None:
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
