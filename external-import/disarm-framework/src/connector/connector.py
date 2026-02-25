"""DISARM Framework connector module."""

import json
import ssl
import sys
import time
import urllib
from datetime import datetime, timezone
from typing import Optional

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


class DisarmFramework:
    """DISARM Framework connector."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

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

    def change_kill_chain_name(self, serialized_bundle: str) -> str:
        object_types_with_kill_chain = ["attack-pattern"]
        stix_bundle = json.loads(serialized_bundle)
        for obj in stix_bundle["objects"]:
            object_type = obj["type"]
            if object_type in object_types_with_kill_chain:
                phases = []
                if "kill_chain_phases" in obj:
                    for kill_chain_phase in obj["kill_chain_phases"]:
                        kill_chain_phase["kill_chain_name"] = "disarm"
                        phases.append(kill_chain_phase)
                obj["kill_chain_phases"] = phases
        return json.dumps(stix_bundle)

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

            self.helper.log_info("Connector will run!")
            now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            friendly_name = "DISARM Framework run @ " + now.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            if (
                self.config.disarm_framework.url is not None
                and len(self.config.disarm_framework.url) > 0
            ):
                disarm_data = self.retrieve_data(str(self.config.disarm_framework.url))
                disarm_data_with_proper_kill_chain = self.change_kill_chain_name(
                    disarm_data
                )
                self.send_bundle(work_id, disarm_data_with_proper_kill_chain)
            message = "Connector successfully run, storing last_run as " + str(
                timestamp
            )
            self.helper.log_info(message)
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stopped")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Fetching DISARM Framework datasets...")

        self.helper.schedule_process(
            message_callback=self.process_data,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )

    def send_bundle(self, work_id: str, serialized_bundle: str) -> None:
        try:
            self.helper.send_stix2_bundle(
                serialized_bundle,
                entities_types=self.config.connector.scope,
                update=False,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")
