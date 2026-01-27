"""MITRE ATLAS connector module."""

import ssl
import sys
import time
import urllib
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper


class MitreAtlas:
    """MITRE ATLAS connector."""

    def __init__(self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"):
        self.config = config
        self.helper = helper
        self.mitre_atlas_file_url = self.config.mitre_atlas.url
        self.update_existing_data = False

    def retrieve_data(self, url: str) -> Optional[str]:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        str
            A string with the content or None in case of failure.
        """
        try:
            return (
                urllib.request.urlopen(url, context=ssl.create_default_context())
                .read()
                .decode("utf-8")
            )
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
        return None

    def process_data(self):
        try:
            timestamp = int(time.time())
            current_state = self.helper.get_state()
            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                    "Connector last run: "
                    + datetime.fromtimestamp(last_run, tz=timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")

            now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            friendly_name = "MITRE ATLAS run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            if (
                self.mitre_atlas_file_url is not None
                and len(self.mitre_atlas_file_url) > 0
            ):
                atlas_data = self.retrieve_data(self.mitre_atlas_file_url)
                self.send_bundle(work_id, atlas_data)
            message = "Connector successfully run, storing last_run as " + str(
                timestamp
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            self.helper.log_info(
                f"Last_run stored, next run in: {self.config.connector.duration_period.days} days"
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

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
            message_callback=self.process_data,
            duration_period=self.config.connector.duration_period,
        )

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.helper.connect_scope,
                update=self.update_existing_data,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")
