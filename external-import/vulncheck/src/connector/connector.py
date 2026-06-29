import sys
from datetime import datetime

import stix2
import vclib.util.works as works
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from vclib.connector_client import ConnectorClient
from vclib.converter_to_stix import ConverterToStix
from vclib.models.data_source import DataSource
from vclib.util.config import get_time_until_next_run
from vclib.util.memory_usage import reset_max_mem


class ConnectorVulnCheck:
    """
    Manager-supported connector class for VulnCheck.

    Wraps the existing vclib logic with Pydantic-based settings
    and the standard connector pattern expected by the OpenCTI manager.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        vulncheck_cfg = config.vulncheck
        self.api_key = vulncheck_cfg.api_key.get_secret_value()
        self.api_base_url = str(vulncheck_cfg.api_base_url)
        self.data_sources = vulncheck_cfg.data_sources

        self.client = ConnectorClient(self.helper, self.config.connector_vulncheck)
        self.converter_to_stix = ConverterToStix(self.helper)

    def _collect_intelligence(
        self, target_data_sources: list[DataSource], connector_state
    ):
        """Collect intelligence from the source and convert into STIX objects."""
        for source in target_data_sources:
            self.helper.connector_logger.info(
                f"[CONNECTOR] Collecting data for {source.name}",
            )
            source.collect_data_source(
                self.config,
                self.helper,
                self.client,
                self.converter_to_stix,
                self.helper.connector_logger,
                connector_state,
            )

    def _get_target_data_sources(self) -> list[DataSource]:
        configured_data_sources = self.data_sources
        target_data_sources: list[DataSource] = []
        for name in configured_data_sources:
            target_data_sources.append(DataSource.from_string(name))

        self.helper.connector_logger.debug(
            "[CONNECTOR] Configured Data Sources",
            {"data_sources": target_data_sources},
        )
        return target_data_sources

    def _get_validated_data_sources(
        self, target_sources: list[DataSource]
    ) -> list[DataSource]:
        validated_sources: list[DataSource] = []
        self.helper.connector_logger.debug(
            "[CONNECTOR] Validating sources...",
            {"data_sources": target_sources},
        )
        for source in target_sources:
            if source.validate(self.api_base_url, self.api_key):
                self.helper.connector_logger.debug(
                    f"[CONNECTOR] Valid source: {source.name}",
                )
                validated_sources.append(source)
            else:
                self.helper.connector_logger.warning(
                    f"[CONNECTOR] Invalid source: {source.name}",
                )
        self.helper.connector_logger.debug(
            "[CONNECTOR] Sources validated!",
        )
        return validated_sources

    def _initial_run(self):
        work_name = "First Run"
        work_id = works.start_work(self.helper, self.helper.connector_logger, work_name)
        stix_objects = [
            stix2.TLP_AMBER,
            stix2.TLP_WHITE,
            self.converter_to_stix.author,
        ]
        works.send_bundle(
            helper=self.helper,
            logger=self.helper.connector_logger,
            stix_objects=stix_objects,
            work_id=work_id,
        )
        works.finish_work(
            helper=self.helper,
            logger=self.helper.connector_logger,
            work_id=work_id,
            work_name=work_name,
        )

    def process_message(self) -> None:
        """Connector main process to collect intelligence."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        reset_max_mem()

        try:
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            connector_state = self.helper.get_state()

            target_data_sources = self._get_validated_data_sources(
                self._get_target_data_sources()
            )

            if connector_state is not None and "last_run" in connector_state:
                last_run = connector_state["last_run"]
                last_run_dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
                last_run_timestamp = int(last_run_dt.timestamp())

                hours, minutes = get_time_until_next_run(
                    current_timestamp, last_run_timestamp
                )
                if hours != 0 and minutes != 0:
                    self.helper.connector_logger.info(
                        f"[CONNECTOR] Last data ingest less than 24 hours ago, next ingest in {hours}h{minutes}m",
                    )
                    return

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run - doing initial run for base objects"
                )
                self._initial_run()

            try:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Running connector...",
                    {"connector_name": self.helper.connect_name},
                )

                self._collect_intelligence(target_data_sources, connector_state)

            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Error in the collection of intelligence",
                    {"error": str(e)},
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "[CONNECTOR] Updating connector state for collected data sources",
                {"current_timestamp": current_timestamp},
            )
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")

            new_state = self._get_updated_state(
                target_data_sources, current_state_datetime
            )

            self.helper.set_state(new_state)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                "[Connector] Error in the execution of the connector.",
                meta={"error": str(err)},
            )

    def _get_updated_state(
        self, target_data_sources: list[DataSource], current_state_datetime
    ) -> dict:
        new_state = {
            data_source.name: current_state_datetime
            for data_source in target_data_sources
        }
        new_state["last_run"] = current_state_datetime
        return new_state

    def run(self) -> None:
        """Run the main process encapsulated in a scheduler."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=str(self.config.connector.duration_period),
        )
