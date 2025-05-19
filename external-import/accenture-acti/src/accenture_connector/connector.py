import datetime
import json
import sys

from html_to_markdown import convert_to_markdown
from pycti import OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .converter_to_stix import ConverterToStix


class ConnectorAccenture:

    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)

    def _collect_intelligence(self, since: str) -> any:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """

        # Get entities from external sources
        stix_bundle = self.client.get_reports(since)
        return stix_bundle

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
            now = datetime.datetime.now(tz=datetime.timezone.utc)
            current_timestamp = int(datetime.datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )
                last_run = (
                    datetime.datetime.now(tz=datetime.UTC)
                    - self.config.relative_import_start_date
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = self.helper.connect_name

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            stix_bundle = self._collect_intelligence(last_run)

            if stix_bundle.get("objects"):
                # stix bundle rework to align with openCTI
                stix_objects = stix_bundle.get("objects")
                author = self.converter_to_stix.create_author()
                stix_objects.append(json.loads(author.serialize()))
                marking = self.converter_to_stix.create_tlp_marking(
                    self.config.tlp_level
                )
                stix_objects.append(json.loads(marking.serialize()))
                for stix_object in stix_objects:

                    # add Accenture as report author
                    stix_object["created_by_ref"] = author.id

                    # add default connector marking
                    stix_object["object_marking_refs"] = [marking.id]

                    if stix_object.get("type") == "report":

                        # report description HTML to markdown
                        stix_object["description"] = convert_to_markdown(
                            stix_object.get("description")
                        )

                        # add custom extension 'x_severity' and 'x_threat_type' as report label
                        custom_extension_labels = []
                        if "x_severity" in stix_object and stix_object.get(
                            "x_severity"
                        ):
                            custom_extension_labels.append(
                                stix_object.get("x_severity")
                            )
                            del stix_object["x_severity"]

                        if "x_threat_type" in stix_object and stix_object.get(
                            "x_threat_type"
                        ):
                            for value in stix_object.get("x_threat_type"):
                                custom_extension_labels.append(value)
                            del stix_object["x_threat_type"]

                        if "labels" in stix_object:
                            stix_object["labels"].extend(custom_extension_labels)
                        else:
                            stix_object["labels"] = custom_extension_labels

                        # search for related-to relation for the report and convert them as object_refs
                        for item in stix_objects[:]:
                            if (
                                item.get("type") == "relationship"
                                and item.get("relationship_type") == "related-to"
                                and item.get("source_ref") == stix_object.get("id")
                            ):
                                stix_object["object_refs"].append(
                                    item.get("target_ref")
                                )
                                stix_objects.remove(item)

                bundles_sent = self.helper.send_stix2_bundle(
                    json.dumps(stix_bundle),
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": {str(len(bundles_sent))}},
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "Getting current state and update it with last run of the connector",
                {"current_timestamp": current_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
            last_run_datetime = datetime.datetime.fromtimestamp(
                current_timestamp, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )

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
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
