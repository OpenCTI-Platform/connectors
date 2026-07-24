import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.utils import group_targets_by_host
from withaname_client.api_client import WithanameClient
from pycti import OpenCTIConnectorHelper


class WithanameConnector:
    """
    Connector for importing DDoSIA targets from witha.name into OpenCTI.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the connector.

        Args:
            config: Connector configuration.
            helper: OpenCTI connector helper.
        """
        self.config = config
        self.helper = helper

        self.client = WithanameClient(
            helper=self.helper,
            base_url=self.config.withaname.api_base_url,
        )

        self.converter_to_stix = ConverterToStix(
            helper=self.helper,
            tlp_level=self.config.withaname.tlp_level,
        )

    def _select_configs_to_process(
        self, configs: List[Dict[str, Any]], state: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter and sort configurations to process based on the current state and configuration.

        Args:
            configs: List of all available configurations from the API.
            state: The current connector state.

        Returns:
            A list of configurations to process, sorted by timestamp ascending.
        """
        processed_configs = []
        for item in configs:
            # Robustly convert timestamp to float, defaulting to 0 if missing or invalid
            ts_val = item.get("ts")
            try:
                ts_float = float(ts_val) if ts_val is not None else 0.0
            except (ValueError, TypeError):
                ts_float = 0.0

            item["_ts_float"] = ts_float
            processed_configs.append(item)

        # Sort by timestamp ascending (oldest first)
        sorted_configs = sorted(processed_configs, key=lambda x: x["_ts_float"])

        if state and "last_cfg_ts" in state:
            # Incremental import: only those strictly newer than the last processed timestamp
            last_ts = state["last_cfg_ts"]
            return [item for item in sorted_configs if item["_ts_float"] > last_ts]

        # First run logic
        start_ts = self.config.withaname.import_start_timestamp

        if start_ts is None:
            # Default: only the most recent snapshot
            return [sorted_configs[-1]] if sorted_configs else []

        if start_ts == 0:
            # Import all available history
            return sorted_configs

        # Import everything from the specified timestamp onwards
        return [item for item in sorted_configs if item["_ts_float"] >= start_ts]

    def _process_snapshot(self, config_item: Dict[str, Any]) -> List[Any]:
        """
        Process a single snapshot: fetch data, group by host, and convert to STIX.

        Args:
            config_item: The configuration item metadata.

        Returns:
            A list of STIX objects (as dicts) for this snapshot.

        Raises:
            Exception: If the snapshot cannot be processed, to allow the caller to handle the failure.
        """
        cfg_id = config_item["id"]
        ts_val = config_item.get("ts")
        try:
            cfg_ts = float(ts_val) if ts_val is not None else 0.0
        except (TypeError, ValueError):
            cfg_ts = 0.0

        self.helper.connector_logger.info(
            f"[CONNECTOR] Processing snapshot {cfg_id}",
            {"cfg_id": cfg_id, "ts": cfg_ts},
        )

        # 1. Fetch snapshot content
        snapshot_data = self.client.get_config(cfg_id)
        targets = snapshot_data.get("targets", [])

        if not targets:
            self.helper.connector_logger.info(
                f"[CONNECTOR] Snapshot {cfg_id} is empty", {"cfg_id": cfg_id}
            )
            return []

        # 2. Group targets by host
        aggregated_data = group_targets_by_host(targets)
        stix_objects = []

        # 3. Convert each host aggregate to STIX
        for host, data in aggregated_data.items():
            # Create Domain with external reference to the snapshot
            domain_obj = self.converter_to_stix.create_domain(host, cfg_id=cfg_id)
            stix_objects.append(json.loads(domain_obj.to_stix2_object().serialize()))

            # Create IPs and relationships
            for ip in data["ips"]:
                ip_obj = self.converter_to_stix.create_ipv4(ip)
                stix_objects.append(json.loads(ip_obj.to_stix2_object().serialize()))

                rel_obj = self.converter_to_stix.create_resolves_to_relationship(
                    domain_obj, ip_obj
                )
                stix_objects.append(json.loads(rel_obj.to_stix2_object().serialize()))

            # Create Note with raw targets (if enabled in config)
            if self.config.withaname.create_notes:
                note_obj = self.converter_to_stix.create_note_for_host(
                    domain=domain_obj,
                    cfg_id=cfg_id,
                    cfg_ts=cfg_ts,
                    host=host,
                    targets=data["raw_targets"],
                )
                stix_objects.append(json.loads(note_obj.to_stix2_object().serialize()))

        return stix_objects

    def process_message(self) -> None:
        """
        Main processing loop for the connector.
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector run...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # 1. Get current state
            current_state = self.helper.get_state() or {}

            # 2. Fetch available configurations with pagination
            all_configs = []
            page = 1
            start_ts = self.config.withaname.import_start_timestamp

            while True:
                self.helper.connector_logger.info(
                    f"[CONNECTOR] Fetching configurations page {page}..."
                )
                response = self.client.get_configs(page=page)
                items = response.get("items", [])

                if not items:
                    break

                all_configs.extend(items)

                # Optimization: if we have a start_ts, we can stop if the last item of the page
                # is already older than our start_ts (since API is most recent first)
                if start_ts is not None and start_ts > 0:
                    last_item_ts = float(items[-1].get("ts", 0))
                    if last_item_ts < start_ts:
                        break

                # If we only want the first page (start_ts is None), we stop after page 1
                if start_ts is None:
                    break

                page += 1

            if not all_configs:
                self.helper.connector_logger.info(
                    "[CONNECTOR] No configurations found in API"
                )
                return

            # 3. Select snapshots to process
            configs_to_process = self._select_configs_to_process(
                all_configs, current_state
            )

            if not configs_to_process:
                self.helper.connector_logger.info(
                    "[CONNECTOR] No new snapshots to process"
                )
                return

            self.helper.connector_logger.info(
                f"[CONNECTOR] Found {len(configs_to_process)} new snapshots to process"
            )

            # 4. Process each snapshot sequentially
            for config_item in configs_to_process:
                cfg_id = config_item["id"]
                cfg_ts = float(config_item.get("ts", 0))

                # Initiate a work for this specific snapshot
                friendly_name = f"DDoSIA - {cfg_id}"
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                try:
                    # Collect and convert
                    stix_objects = self._process_snapshot(config_item)

                    if stix_objects:
                        # Note: author and marking are handled automatically by the helper
                        # (no need to append them to stix_objects)
                        bundle = self.helper.stix2_create_bundle(stix_objects)
                        self.helper.send_stix2_bundle(
                            bundle,
                            work_id=work_id,
                            cleanup_inconsistent_bundle=True,
                        )

                        self.helper.connector_logger.info(
                            f"[CONNECTOR] Snapshot {cfg_id} imported",
                            {"objects_count": len(stix_objects)},
                        )

                    # Mark work as processed
                    self.helper.api.work.to_processed(
                        work_id,
                        f"Processed snapshot {cfg_id} with {len(stix_objects)} objects",
                    )

                    # Update state ONLY after successful processing and import
                    now = datetime.now(timezone.utc)
                    self.helper.set_state(
                        {
                            "last_run": now.isoformat(),
                            "last_cfg_id": cfg_id,
                            "last_cfg_ts": cfg_ts,
                        }
                    )

                except Exception as e:
                    self.helper.connector_logger.error(
                        f"[CONNECTOR] Critical error processing snapshot {cfg_id}. Skipping state update.",
                        {"cfg_id": cfg_id, "error": str(e)},
                    )
                    # Mark work as failed
                    self.helper.api.work.to_processed(
                        work_id, f"Failed to process snapshot {cfg_id}: {str(e)}"
                    )
                    # We do NOT update the state here, so the snapshot will be retried next run

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                f"[CONNECTOR] Unexpected error during run: {str(err)}",
                {"error": str(err)},
            )

    def run(self) -> None:
        """
        Start the connector and schedule its runs.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
