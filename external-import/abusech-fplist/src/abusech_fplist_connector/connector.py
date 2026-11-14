import ipaddress
import logging
import sys
from datetime import datetime, timezone

from abusech_fplist_connector.client_api import ConnectorClient
from abusech_fplist_connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

# entry_type → candidate STIX pattern templates. ThreatFox stores ip:port IOCs
# as an ipv4-addr pattern and SHA-1 hashes as file:hashes.SHA1, hence the
# multiple candidates.
INDICATOR_PATTERNS = {
    "sha256_hash": ["[file:hashes.'SHA-256' = '{v}']"],
    "md5_hash": ["[file:hashes.MD5 = '{v}']"],
    "sha1_hash": [
        "[file:hashes.'SHA-1' = '{v}']",
        "[file:hashes.SHA1 = '{v}']",
    ],
    "sha3_384": ["[file:hashes.'SHA3-384' = '{v}']"],
    "domain": ["[domain-name:value = '{v}']"],
    "url": ["[url:value = '{v}']"],
    "ip:port": [
        (
            "[network-traffic:dst_ref.type = 'ipv4-addr' "
            "AND network-traffic:dst_ref.value = '{ip}' "
            "AND network-traffic:dst_port = {port}]"
        ),
        "[ipv4-addr:value = '{ip}']",
    ],
}


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


class ConnectorAbusechFplist:
    """External-import connector that deletes from OpenCTI the Indicators
    reported as false positives by abuse.ch.

    Unlike a regular external-import connector it does not create entities:
    it fetches the abuse.ch False Positive List and deletes the matching
    Indicators, so no STIX bundle is ever sent. Observables are left untouched.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(helper, config)
        # pycti logs every API query at INFO, flooding the output on large FP lists
        if self.helper.log_level.lower() != "debug":
            logging.getLogger("api").setLevel(logging.WARNING)

    def _find_indicators(self, entry_type: str, entry_value: str) -> list[str]:
        """Return the OpenCTI ids of the Indicators matching any candidate pattern."""
        pattern_templates = INDICATOR_PATTERNS.get(entry_type)
        if not pattern_templates:
            return []

        if entry_type == "ip:port":
            ip, _, port = entry_value.rpartition(":")
            port_int = int(port) if port.isdigit() else 0
            if not _is_ipv4(ip) or not 0 < port_int <= 65535:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Invalid or unsupported ip:port value (IPv4:port only), skipping",
                    {"value": entry_value},
                )
                return []
            format_args = {"ip": ip, "port": port_int}
        else:
            format_args = {"v": entry_value.replace("\\", "\\\\").replace("'", "\\'")}

        indicator_ids: list[str] = []
        seen_ids: set[str] = set()
        for pattern_template in pattern_templates:
            pattern = pattern_template.format(**format_args)
            # API errors are not caught on purpose: they abort the run so the
            # state marker is not advanced past unchecked entries
            data = {"pagination": {"hasNextPage": True, "endCursor": None}}
            while data["pagination"].get("hasNextPage"):
                data = self.helper.api.indicator.list(
                    first=1000,
                    after=data["pagination"].get("endCursor"),
                    filters={
                        "mode": "and",
                        "filters": [{"key": "pattern", "values": [pattern]}],
                        "filterGroups": [],
                    },
                    withPagination=True,
                    customAttributes="id",
                )
                for indicator in data.get("entities") or []:
                    ind_id = indicator.get("id")
                    if ind_id and ind_id not in seen_ids:
                        indicator_ids.append(ind_id)
                        seen_ids.add(ind_id)
        return indicator_ids

    def _remove_entry(self, entry: dict) -> None:
        """Delete (or log, in dry run) every Indicator matching the FP entry."""
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
        ind_ids = self._find_indicators(entry_type, entry_value)
        if ind_ids:
            for ind_id in ind_ids:
                if self.config.abusech_fplist.dry_run:
                    self.helper.connector_logger.info(
                        f"[DRY RUN] Would delete indicator #{removal_id}",
                        {"type": entry_type, "value": entry_value, "id": ind_id},
                    )
                else:
                    self.helper.api.stix_domain_object.delete(id=ind_id)
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Deleted indicator #{removal_id}",
                        {"type": entry_type, "value": entry_value, "id": ind_id},
                    )
        else:
            self.helper.connector_logger.debug(
                f"[CONNECTOR] FP #{removal_id} not found in OpenCTI (skipped)",
                {"type": entry_type, "value": entry_value},
            )

    def process_message(self) -> None:
        """Fetch the FP list and process the entries newer than the state marker.

        The `last_removal_id` marker is only advanced after a fully successful
        run (and never in dry run), so failed or interrupted runs are retried:
        deletions are idempotent, already-deleted Indicators are simply not
        found again.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        work_id = None
        try:
            current_state = self.helper.get_state() or {}
            try:
                last_removal_id = int(current_state.get("last_removal_id", 0))
            except (TypeError, ValueError):
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Invalid last_removal_id in state, resetting to 0",
                    {"last_removal_id": current_state.get("last_removal_id")},
                )
                last_removal_id = 0
            self.helper.connector_logger.info(
                "[CONNECTOR] Resuming from last removal_id",
                {"last_removal_id": last_removal_id},
            )

            all_entries = self.client.get_fplist()

            new_entries = [
                e for e in all_entries if int(e["removal_id"]) > last_removal_id
            ]
            # Process oldest first so the marker always moves forward
            new_entries.sort(key=lambda e: int(e["removal_id"]))

            if new_entries:
                self.helper.connector_logger.info(
                    f"[CONNECTOR] {len(new_entries)} new FP entries to process"
                )

                now = datetime.now(timezone.utc)
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    f"{self.helper.connect_name} run @ {now.isoformat(timespec='seconds')}",
                )

                max_removal_id = last_removal_id
                for entry in new_entries:
                    self._remove_entry(entry)
                    max_removal_id = int(entry["removal_id"])

                if self.config.abusech_fplist.dry_run:
                    message = (
                        f"{self.helper.connect_name} dry run completed, "
                        f"would have processed up to removal_id={max_removal_id} "
                        "(state not updated)"
                    )
                else:
                    current_state["last_removal_id"] = max_removal_id
                    current_state["last_run"] = now.strftime("%Y-%m-%d %H:%M:%S")
                    self.helper.set_state(current_state)
                    message = (
                        f"{self.helper.connect_name} run completed, "
                        f"processed up to removal_id={max_removal_id}"
                    )

                self.helper.api.work.to_processed(work_id, message)
                self.helper.connector_logger.info(message)
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] No new FP entries to process"
                )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped.")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))
            if work_id:
                self.helper.api.work.to_processed(work_id, str(err), in_error=True)

    def run(self) -> None:
        """Start the connector and schedule its runs every `duration_period`."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
