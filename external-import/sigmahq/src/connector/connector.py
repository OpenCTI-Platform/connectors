import sys

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from sigmahq_client import SigmaHQClient


class SigmaHQConnector:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        :param config:
        :param helper:
        """
        self.config = config
        self.helper = helper

        self.client = SigmaHQClient(
            self.helper,
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level="clear",
        )

    def _collect_intelligence(self, release_metadata, rule_package) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        stix_objects = []
        # retrieve latest release version
        rules = None
        for asset in release_metadata["assets"]:
            if rule_package in asset["name"]:
                rules = self.client.download_and_convert_package(
                    asset["browser_download_url"]
                )

        for rule in rules:
            try:
                stix_entities = self.converter_to_stix.convert_sigma_rule(rule)
                stix_objects.extend(stix_entities)
            except Exception as err:
                self.helper.connector_logger.error(
                    f"An exception occurred while converting SigmaHQ rule: {rule.filename}",
                    err,
                )
                pass

        # Ensure consistent bundle by adding the author and TLP marking
        if len(stix_objects):
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state
            current_state = self.helper.get_state()

            rule_package_version = None
            if current_state and "rule_package_version" in current_state:
                rule_package_version = current_state["rule_package_version"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last ingested rule package version",
                    {"rule_package_version": rule_package_version},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Connector SigmaHQ"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # get latest rule package version
            release_metadata = self.client.get_lastest_published_version()
            latest_version = release_metadata.get("tag").lower()
            if (
                rule_package_version is None
                or latest_version.lower() != rule_package_version.lower()
            ):
                stix_objects = self._collect_intelligence(
                    release_metadata, self.config.sigmahq.rule_package
                )

                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )

                # Store the last rule package version as a last run of the connector
                self.helper.connector_logger.debug(
                    "Getting current state and update it with last rule package version",
                    {"rule_package_version": release_metadata.get("tag")},
                )
                current_state = self.helper.get_state()
                if current_state:
                    current_state["rule_package_version"] = latest_version
                else:
                    current_state = {"rule_package_version": latest_version}
                self.helper.set_state(current_state)

            else:
                self.helper.connector_logger.info(
                    "Nothing to do, latest rule package version already ingested"
                )

            message = f"{self.helper.connect_name} connector successfully run"

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Start the connector, schedule its runs and trigger the first run.
        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, and if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        Example:
            - If `CONNECTOR_DURATION_PERIOD=PT5M`, then the connector is running every 5 minutes.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
