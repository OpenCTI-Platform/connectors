import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import stix2
from pycti import Identity, OpenCTIConnectorHelper

from .client_api import ConnectorClient
from .config_loader import ConfigConnector
from .indicators import IndicatorHandler
from .reports import ReportHandler


# When the connector runs for the first time, it will retrieve from the beginning of 2025.
# If there is a better / more customisable way to do this, such as an extra parameter to the connector
# I'd be happy to implement that instead.
FIRST_RUN_START_DATE = 1735689600  

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

        # Based on the format for inputting TLPS, we get the corresponding stix2 object
        if self.config.tlp_level.lower() == "clear":
            self.config.tlp_level = "white"
        normalised_tlp = self.config.tlp_level.lower().replace("+", "_")
        self.tlp_ref = getattr(stix2, f"TLP_{normalised_tlp}".upper(), None)

        if self.tlp_ref is None:
            self.helper.connector_logger.error(f"Error: Invalid TLP Level in Configuration. Please see the documentation and change it to one of the allowed values.")
            sys.exit(1)

        # Initialise the Report and Indicator Handler, of which are quite similar in nature, but have been differentiated so that they can be changed
        # separately in future.
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
        Marking to each stix object in the parsed list.

        :param objects: A list of STIX objects.
        :return: A list of STIX objects with author and TLP information appended.
        """

        new_objects = []
        for obj in objects:
            obj_dict = dict(obj)
            # append created_by_ref
            try:
                obj_dict["created_by_ref"] = self.author.id
            except:
                pass

            # append TLP marking
            try:
                if self.tlp_ref:
                    obj_dict["object_marking_refs"] = [self.tlp_ref.id]
            except:
                pass

            # Rebuild the object
            try:
                new_obj = obj.__class__(**obj_dict)
            except:
                new_obj = obj

            new_objects.append(new_obj)

        # Include the author and marking object in the bundle
        new_objects.append(self.author)
        if self.tlp_ref:
            new_objects.append(self.tlp_ref)

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

            # Template code for handling the last run time
            now = datetime.now()
            current_timestamp = int(datetime.timestamp(now))
            current_state = self.helper.get_state()

            last_run_timestamp = 0
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "Connector last run",
                    {"last_run_datetime": last_run},
                )
                try:
                    last_run_timestamp = int(datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S").timestamp())
                except Exception:
                     self.helper.connector_logger.error(f"Could not convert last run datetime {last_run} to timestamp, using 0.")
            else:
                self.helper.connector_logger.info("Connector has never run...")
                last_run_timestamp = FIRST_RUN_START_DATE

            # Attempt to Retrieve and Post Reports to OpenCTI
            try:

                #Retrieve Reports from TT5
                self.helper.connector_logger.info(f"Retrieving Reports From After: {datetime.fromtimestamp(last_run_timestamp)}")
                self.report_handler.retrieve_reports(last_run_timestamp)
                self.helper.connector_logger.info("Finished retrieving reports")


                #Upload Reports via Worker
                work_name = "Creating OpenCTI Reports"
                work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
                num_pushed = self.report_handler.post_reports(work_id)
                push_message = f"Connector created {num_pushed} reports"
                self.helper.connector_logger.info(push_message)
                self.helper.api.work.to_processed(work_id, push_message)


            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing Reports: {e}"
                )

            # Attempt to Retrieve and Push Indicator Bundles to OpenCTI
            try:
                #Retrieve Indicators from TT5
                self.helper.connector_logger.info(f"Retrieving Indicator Bundles From After: {datetime.fromtimestamp(last_run_timestamp)}")
                self.indicator_handler.retrieve_indicators(last_run_timestamp)
                self.helper.connector_logger.info( "Finished retrieving Indicator Bundles")


                #Upload Indicators via Worker
                work_name = "Pushing Indicator Bundles to OpenCTI"
                work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
                num_pushed = self.indicator_handler.post_indicators(work_id)
                push_message = f"Connector Pushed {num_pushed} indicator bundles"
                self.helper.connector_logger.info(push_message)
                self.helper.api.work.to_processed(work_id, push_message)

            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing Indicator Bundles: {e}"
                )

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug("Updating Last Run")
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
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

    def run(self) -> None:
        """
        Run the connector on a scheduler.
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.main,
            duration_period=self.config.duration_period,
        )
