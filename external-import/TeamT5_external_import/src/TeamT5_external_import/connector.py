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

STATE_FILE_NAME = "connector_state.json"


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
        normalised_tlp = self.config.tlp_level.lower().replace("+", "_")
        self.tlp_ref = getattr(stix2, f"TLP_{normalised_tlp}".upper(), None)

        # Attempt to open the state file, housing the timestamps of the last retrieved Report and Indicator Bundle.
        state_file = Path(__file__).resolve().parent.parent / STATE_FILE_NAME
        try:
            with open(state_file, "r") as f:
                timestamps = json.load(f)
            self.timestamps = {
                "last_report_ts": int(timestamps.get("last_report_ts", 0)),
                "last_indicator_ts": int(timestamps.get("last_indicator_ts", 0)),
            }

        except Exception as e:
            self.helper.connector_logger.error(f"Error loading connector state: {e}")
            raise

        # Store our timestamps as datetime objects for use in logging
        self.last_report_datetime = datetime.fromtimestamp(
            self.timestamps["last_report_ts"]
        )
        self.last_indicator_datetime = datetime.fromtimestamp(
            self.timestamps["last_indicator_ts"]
        )

        # Initialise the Report and Indicator Handler, of which are quite similar in nature, but have been differentiated so that they can be changed
        # separately in future.
        self.report_handler = ReportHandler(
            helper=helper,
            author=self.author,
            fcn_request_data=self.client._request_data,
            fcn_update_timestamps=self.update_timestamps,
            fcn_append_author_tlp=self.append_author_tlp,
            tlp_ref=self.tlp_ref,
            timestamps=self.timestamps,
            api_url=self.config.api_url,
        )

        self.indicator_handler = IndicatorHandler(
            helper=helper,
            author=self.author,
            fcn_request_data=self.client._request_data,
            fcn_update_timestamps=self.update_timestamps,
            fcn_append_author_tlp=self.append_author_tlp,
            tlp_ref=self.tlp_ref,
            timestamps=self.timestamps,
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

    def update_timestamps(self) -> None:
        """
        Update the Connector's State / storage of timestamps.
        :return: None
        """

        state_file = Path(__file__).resolve().parent.parent / STATE_FILE_NAME

        temp_file = state_file.with_suffix(".json.tmp")
        new_data = {
            "last_report_ts": self.timestamps["last_report_ts"],
            "last_indicator_ts": self.timestamps["last_indicator_ts"],
        }

        try:
            with open(temp_file, "w") as f:
                json.dump(new_data, f, indent=4)
            temp_file.replace(state_file)

        except Exception as e:
            self.helper.connector_logger.error(f"Failed to update timestamps file: {e}")
            if temp_file.exists():
                temp_file.unlink()
            raise

    def _init_work(self, work_name):
        """
        Initialise work within the platform, logging a message corresponding to its name

        :param work_name: The name/message of the work to be initiated.
        :return: The ID of the initiated work unit.
        """
        work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)
        self.helper.connector_logger.info(work_name)
        return work_id

    def _end_work(self, end_message, work_id):
        """
        Finish work within the platform, logging a message upon completion

        :param end_message: The message to record for the completed work.
        :param work_id: The ID of the work unit to be marked as processed.
        :return: None
        """
        self.helper.api.work.to_processed(work_id, end_message)
        self.helper.connector_logger.info(end_message)

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

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info("Connector has never run...")

            # Attempt to Retrieve and Post Reports to OpenCTI
            try:

                # Job 1: retrieve reports
                WORK_NAME = (
                    f"Retrieving Reports From After: {self.last_report_datetime}"
                )
                WORK_END = "Finished retrieving reports"

                work_id = self._init_work(WORK_NAME)
                self.report_handler.retrieve_reports()
                self._end_work(end_message=WORK_END, work_id=work_id)

                # Job 2: upload reports
                WORK_NAME = "Creating OpenCTI Reports"
                WORK_END = "Finished Creating Reports"

                work_id = self._init_work(WORK_NAME)
                num_pushed = self.report_handler.post_reports(work_id)
                self.helper.connector_logger.info(
                    f"Connector created {num_pushed} reports"
                )
                self._end_work(end_message=WORK_END, work_id=work_id)
                self.last_report_datetime = datetime.fromtimestamp(
                    self.timestamps["last_report_ts"]
                )

            except Exception as e:
                self.helper.connector_logger.error(
                    f"An Error Occurred Whilst Processing Reports: {e}"
                )

            # Attempt to Retrieve and Push Indicator Bundles to OpenCTI
            try:

                # Job 3: retrieve indicators
                WORK_NAME = f"Retrieving Indicator Bundles From After: {self.last_indicator_datetime}"
                WORK_END = "Finished retrieving Indicator Bundles"

                work_id = self._init_work(WORK_NAME)
                self.indicator_handler.retrieve_indicators()
                self._end_work(end_message=WORK_END, work_id=work_id)

                # Job 4: upload indicators
                WORK_NAME = "Pushing Indicator Bundles to OpenCTI"
                WORK_END = "Finished Pushing Indicator Bundles"

                work_id = self._init_work(WORK_NAME)
                num_pushed = self.indicator_handler.post_indicators(work_id)
                self.helper.connector_logger.info(
                    f"Connector Pushed {num_pushed} indicator bundles"
                )
                self._end_work(end_message=WORK_END, work_id=work_id)
                self.last_indicator_datetime = datetime.fromtimestamp(
                    self.timestamps["last_indicator_ts"]
                )

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
        Run the connector on a schedule.
        :return: None
        """
        self.helper.schedule_iso(
            message_callback=self.main,
            duration_period=self.config.duration_period,
        )
