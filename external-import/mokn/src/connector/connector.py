"""Main MokN Connector for OpenCTI."""

import sys
from datetime import datetime, timezone
from typing import Any, List, Optional

from mokn.api_client import MoknApiClient
from pycti import OpenCTIConnectorHelper

from .converter_to_stix import ConverterToStix
from .settings import ConnectorSettings


class MoknConnector:
    """MokN external import connector for OpenCTI."""

    def __init__(
        self, config: ConnectorSettings, helper: OpenCTIConnectorHelper
    ) -> None:
        """
        Initialize the connector.
        :param config: Connector settings.
        :param helper: OpenCTI connector helper.
        """
        self.config = config
        self.helper = helper
        self.api_client = MoknApiClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _collect_intelligence(self) -> List[Any]:
        """
        Collect login attempts from MokN API and convert to STIX objects.
        :return: List of STIX objects to send.
        """
        stix_objects: List[Any] = []
        last_run_timestamp = self._get_last_run_timestamp()
        login_attempts = self.api_client.fetch_attack_data(last_run_timestamp)

        if not login_attempts:
            self.helper.connector_logger.info(
                "No new login attempts to process",
                {"last_run_timestamp": last_run_timestamp},
            )
            return stix_objects

        stix_objects = self.converter_to_stix.process_attack_data(login_attempts)
        if stix_objects:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def _get_last_run_timestamp(self) -> Optional[int]:
        """
        Get the timestamp of the last successful run.
        :return: Last run timestamp (unix) or None.
        """
        current_state = self.helper.get_state()
        if not current_state:
            return None

        last_timestamp = current_state.get("last_timestamp")
        if last_timestamp is not None:
            return last_timestamp

        last_run = current_state.get("last_run")
        result: Optional[int] = None
        try:
            if last_run is None:
                result = None
            elif isinstance(last_run, str):
                try:
                    dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
                    result = int(dt.timestamp())
                except ValueError:
                    result = int(last_run)
            else:
                result = last_run
        except (ValueError, TypeError):
            self.helper.connector_logger.warning(
                "Invalid last_run timestamp format", {"last_run": last_run}
            )
            result = None
        return result

    def process_message(self) -> None:
        """
        Main connector process to collect and process login attempts.
        :return: None
        """
        try:
            start_time = datetime.now(timezone.utc)
            friendly_name = f"{self.helper.connect_name} - {start_time.isoformat()}"
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            last_run_timestamp = self._get_last_run_timestamp()
            if last_run_timestamp:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_timestamp": last_run_timestamp},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run...",
                    {"connector_name": self.helper.connect_name},
                )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            stix_objects = self._collect_intelligence()
            if stix_objects:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": len(bundles_sent)},
                )
            else:
                self.helper.connector_logger.info(
                    "No STIX objects to send",
                    {"connector_name": self.helper.connect_name},
                )

            message = (
                f"Imported {len(stix_objects)} objects"
                if stix_objects
                else "No new data to import"
            )
            self.helper.api.work.to_processed(work_id, message)

            end_time = datetime.now(timezone.utc)
            new_state = {
                "last_run": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_timestamp": int(end_time.timestamp()),
            }
            self.helper.set_state(new_state)

            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector run completed",
                {
                    "state": new_state,
                    "items_processed": len(stix_objects),
                },
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except (ValueError, TypeError, KeyError) as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] Import failed", {"error": str(err)}
            )
            raise

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler.
        :return: None
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )


__all__ = ["MoknConnector"]
