import sys
from datetime import datetime

import connector.util.works as works
import stix2
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.sources import registry
from connector.sources.registry import SourceSpec
from connector.util.config import get_time_until_next_run
from connector.util.memory_usage import reset_max_mem
from connector.util.source_logger import SourceLogger
from pycti import OpenCTIConnectorHelper
from vulncheck_client import VulnCheckClient


class ConnectorVulnCheck:
    """
    Connector class for VulnCheck

    This class wraps the entire process of collectioning intelligence from the
    VulnCheck API and converting it into STIX objects.

    Attributes:
    - config: Configuration object
    - helper: OpenCTIConnectorHelper object
    - client: VulnCheckClient object
    - converter_to_stix: ConverterToStix object
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with injected configuration and helper
        """
        self.config = config
        self.helper = helper
        self.client = VulnCheckClient(
            self.helper,
            base_url=self.config.vulncheck.api_base_url,
            api_key=self.config.vulncheck.api_key.get_secret_value(),
        )
        self.converter_to_stix = ConverterToStix(self.helper)

    def _collect_intelligence(
        self, target_data_sources: list[SourceSpec], connector_state
    ) -> list[SourceSpec]:
        """
        Collect intelligence from the sources and convert into STIX objects.

        Each source is isolated: if one raises, it is logged and skipped so the
        remaining sources still run. Returns the sources that completed
        successfully — only those should have their state timestamp advanced
        (a failed source must keep its prior timestamp so the next run re-pulls
        the window it missed, instead of silently skipping it).
        """
        succeeded: list[SourceSpec] = []
        for source in target_data_sources:
            self.helper.connector_logger.info(
                f"[CONNECTOR] Collecting data for {source.name}",
            )
            try:
                source.collect(
                    self.config,
                    self.helper,
                    self.client,
                    self.converter_to_stix,
                    SourceLogger(self.helper.connector_logger, source.name),
                    connector_state,
                )
                succeeded.append(source)
            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Error collecting data source; "
                    "state not advanced (will retry next run)",
                    {"source": source.name, "error": str(e)},
                )
        return succeeded

    def _get_target_data_sources(self) -> list[SourceSpec]:
        # registry.resolve validates names and applies the vulncheck-nvd2 ->
        # skip nist-nvd2 preference (logging the skip via the connector logger).
        target_data_sources = registry.resolve(
            self.config.vulncheck.data_sources, self.helper.connector_logger
        )
        self.helper.connector_logger.debug(
            "[CONNECTOR] Configured Data Sources",
            {"data_sources": [source.name for source in target_data_sources]},
        )
        return target_data_sources

    def _get_validated_data_sources(
        self, target_sources: list[SourceSpec]
    ) -> list[SourceSpec]:
        validated_sources: list[SourceSpec] = []
        self.helper.connector_logger.debug(
            "[CONNECTOR] Validating sources...",
            {"data_sources": [source.name for source in target_sources]},
        )
        for source in target_sources:
            if self.client.is_source_available(source.name, source.api_prefix):
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
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        # INFO: Reset state for tracking memory usage during large volume data-processing
        reset_max_mem()

        try:
            # Get the current state
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            connector_state = self.helper.get_state()

            # Get the target data sources for this run
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

                collected_sources = self._collect_intelligence(
                    target_data_sources, connector_state
                )

            except Exception as e:
                self.helper.connector_logger.error(
                    "[CONNECTOR] Error in the collection of intelligence",
                    {"error": str(e)},
                )
                collected_sources = []

            # Advance state only for sources that completed successfully, so a
            # failed source re-pulls its missed window on the next run instead of
            # skipping it (critical for the incremental NVD2 sources).
            self.helper.connector_logger.debug(
                "[CONNECTOR] Updating connector state for collected data sources",
                {
                    "current_timestamp": current_timestamp,
                    "collected": [s.name for s in collected_sources],
                },
            )
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")

            new_state = self._get_updated_state(
                connector_state, collected_sources, current_state_datetime
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
        self,
        connector_state: dict | None,
        collected_sources: list[SourceSpec],
        current_state_datetime,
    ) -> dict:
        # Preserve prior state (so failed/un-run sources keep their last
        # successful timestamp) and only advance the sources that succeeded.
        new_state = dict(connector_state or {})
        for source in collected_sources:
            new_state[source.name] = current_state_datetime
        new_state["last_run"] = current_state_datetime
        return new_state

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        The `CONNECTOR_DURATION_PERIOD` config (ISO-8601, e.g. `PT5M` => every 5
        minutes) is parsed by settings into a `timedelta`; it is passed to
        `schedule_process` here as a number of seconds.
        :return: None
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
