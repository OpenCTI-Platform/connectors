import sys
from datetime import datetime, timezone

import stix2
from pycti import Identity, MarkingDefinition, OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .indicators import IndicatorHandler
from .reports import ReportHandler


class TeamT5Connector:
    def __init__(self, config: ConfigConnector, helper: OpenCTIConnectorHelper):
        """
        Initialise the Connector.

        :param config: The connector configuration object.
        :param helper: The OpenCTI connector helper object.
        """

        self.config = config
        self.helper = helper
        self.client = ConnectorClient(self.helper, self.config)

        # Generate an author whose name is that of the connector's
        self.author = stix2.Identity(
            id=Identity.generate_id(self.config.name, "organization"),
            name=self.config.name,
            identity_class="organization",
        )

        self.tlp_ref = self._create_tlp_marking(self.config.tlp_level.lower())

        self.report_handler = ReportHandler(
            helper=helper,
            author=self.author,
            fcn_request_data=self.client._request_data,
            fcn_append_author_tlp=self.append_author_tlp,
            tlp_ref=self.tlp_ref,
            api_url=self.config.api_url,
        )

        self.indicator_handler = IndicatorHandler(
            helper=helper,
            author=self.author,
            fcn_request_data=self.client._request_data,
            fcn_append_author_tlp=self.append_author_tlp,
            tlp_ref=self.tlp_ref,
            api_url=self.config.api_url,
        )

    def append_author_tlp(self, objects: list) -> list:
        """
        Adds the required Author (this connector) and specified TLP
        Marking to each stix object in the parsed list, if they are able
        to receive these attributes.

        :param objects: A list of STIX objects.
        :return: A list of STIX objects with author and TLP information appended.
        """

        # SCOS cannot receive a created_by_ref attribute
        objects_without_author = {
            "artifact",
            "autonomous-system",
            "directory",
            "domain-name",
            "email-addr",
            "email-message",
            "file",
            "ipv4-addr",
            "ipv6-addr",
            "mac-addr",
            "mutex",
            "network-traffic",
            "process",
            "software",
            "url",
            "user-account",
            "windows-registry-key",
            "x509-certificate",
        }

        # Include the author and TLP ref first in the bundle
        new_objects = [self.author, self.tlp_ref]
        for obj in objects:
            obj_dict = dict(obj)
            obj_type = obj_dict.get("type")

            # Author
            if obj_type not in objects_without_author:
                obj_dict["created_by_ref"] = self.author.id

            # Markings
            existing_markings = obj_dict.get("object_marking_refs", [])
            obj_dict["object_marking_refs"] = existing_markings + [self.tlp_ref.id]

            # Rebuild
            new_obj = obj.__class__(**obj_dict)
            new_objects.append(new_obj)

        return new_objects

    def main(self) -> None:
        """
        The main execution loop of the connector follows such a structure:

        0. Determine the Connector's last run time / state
        1. Retrieve Reports from the Team T5 Platform
        2. Create corresponding Reports in the OpenCTI Platform
        3. Retrieve Indicator Bundles from the Team T5 Platform
        4. Push these Indicator Bundles to the OpenCTI Platform
        5. Update the last Run Time and Finish

        :return: None
        """

        self.helper.connector_logger.info(f"{self.config.name}: Starting Run")

        try:
            now = datetime.now(tz=timezone.utc)
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "Connector last run", {"last_run_datetime": last_run}
                )
                last_run_timestamp = int(
                    datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S").timestamp()
                )

            # If the connector has never run, we should retrieve from the timestamp specified in configs
            else:
                self.helper.connector_logger.info("Connector has never run...")
                last_run_timestamp = self.config.first_run_retrieval_timestamp

            # Retrieve Reports from TT5
            self.helper.connector_logger.info(
                f"Retrieving Reports From After: {datetime.fromtimestamp(last_run_timestamp)}"
            )
            self.report_handler.retrieve_reports(last_run_timestamp)
            self.helper.connector_logger.info("Finished retrieving reports")

            # Upload Reports via Worker
            if self.report_handler.reports:
                work_name = "Creating OpenCTI Reports"
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, work_name
                )
                num_pushed = self.report_handler.post_reports(work_id)
                push_message = f"Connector created {num_pushed} reports"
                self.helper.connector_logger.info(push_message)
                self.helper.api.work.to_processed(work_id, push_message)
            else:
                self.helper.connector_logger.info("No new Reports found")

            # Retrieve Indicators from TT5
            self.helper.connector_logger.info(
                f"Retrieving Indicator Bundles From After: {datetime.fromtimestamp(last_run_timestamp)}"
            )
            self.indicator_handler.retrieve_indicators(last_run_timestamp)
            self.helper.connector_logger.info("Finished retrieving Indicator Bundles")

            # Upload Indicators via Worker
            if self.indicator_handler.indicators:
                work_name = "Pushing Indicator Bundles to OpenCTI"
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, work_name
                )
                num_pushed = self.indicator_handler.post_indicators(work_id)
                push_message = f"Connector Pushed {num_pushed} indicator bundles"
                self.helper.connector_logger.info(push_message)
                self.helper.api.work.to_processed(work_id, push_message)
            else:
                self.helper.connector_logger.info("No new Indicator Bundles found")

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug("Updating Last Run")
            current_state = self.helper.get_state()
            current_state_datetime = now.isoformat(timespec="seconds")
            last_run_datetime = datetime.fromtimestamp(
                current_timestamp, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S")
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"{self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped...")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    @staticmethod
    def _create_tlp_marking(level) -> stix2.MarkingDefinition:
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        if level not in mapping:
            return mapping["clear"]
        return mapping[level]

    def run(self) -> None:
        """
        Run the connector on a scheduler.
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.main,
            duration_period=self.config.duration_period,
        )
