import sys
from datetime import datetime, timedelta, timezone

from pycti import OpenCTIConnectorHelper
from requests.exceptions import HTTPError
from taxii2client.exceptions import TAXIIServiceException

from .client_taxii import Taxii2
from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .process_objects import ProcessObjects


class Connector:

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """
        # Load configuration file and connection helper
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.converter_to_stix = ConverterToStix(self.helper, self.config)
        self.taxii2 = Taxii2(self.helper, self.config)
        self.process = ProcessObjects(self.helper, self.config, self.converter_to_stix)

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        stix_objects = []

        for collection in self.config.collections:
            try:
                root_path, coll_title = collection.split(".")
                if root_path == "*":
                    stix_objects = self.taxii2.poll_all_roots(coll_title)
                elif coll_title == "*":
                    root = self.taxii2._get_root(root_path)
                    stix_objects = self.taxii2.poll_entire_root(root)
                else:
                    root = self.taxii2._get_root(root_path)
                    coll = self.taxii2._get_collection(root, coll_title)
                    obj = self.taxii2.poll(coll)
                    if len(obj) > 0:
                        stix_objects.extend(iter(obj))
            except (TAXIIServiceException, HTTPError) as err:
                self.helper.log_error("Error connecting to TAXII server")
                self.helper.log_error(err)
                continue

        # If further processing of objects is needed
        if stix_objects is not None and len(stix_objects) > 0:
            stix_objects = self.process.objects(stix_objects)

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
            now = datetime.now(timezone.utc)
            current_timestamp = int(now.timestamp())
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

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Connector Taxii2 feed"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            # Convert last_run to RFC-3339
            dt_format = ""
            if current_state is not None and "last_run" in current_state:
                dt = datetime.fromtimestamp(last_run, tz=timezone.utc)
                dt_format = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            if self.config.enable_url_query_limit and self.config.taxii2v21:
                self.taxii2.filters["limit"] = self.config.url_query_limit
            # Set added_after to either last run or initial history
            if current_state is not None and "last_run" in current_state:
                self.taxii2.filters["added_after"] = dt_format
            else:
                added_after = datetime.now() - timedelta(
                    hours=self.config.initial_history
                )
                self.taxii2.filters["added_after"] = added_after

            stix_objects = self._collect_intelligence()

            if stix_objects is not None and len(stix_objects) != 0:
                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle, work_id=work_id
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
            current_state_datetime = int(now.timestamp())
            last_run_datetime = datetime.utcfromtimestamp(current_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )
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
        if self.config.duration_period:
            self.helper.schedule_iso(
                message_callback=self.process_message,
                duration_period=self.config.duration_period,
            )
        else:
            self.helper.schedule_unit(
                message_callback=self.process_message,
                duration_period=self.config.interval,
                time_unit=self.helper.TimeUnit.HOURS,
            )
