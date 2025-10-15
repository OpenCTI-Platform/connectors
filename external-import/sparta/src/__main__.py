import json
import ssl
import sys
import time
import urllib

from datetime import datetime
from pycti import OpenCTIConnectorHelper
from src import ConfigLoader
from stix2 import Identity, TLP_WHITE
from typing import Optional


def time_from_unixtime(timestamp):
    if not timestamp:
        return None
    return datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")


def get_unixtime_now():
    return int(time.time())


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


class Sparta:
    """Sparta connector."""

    def __init__(self):
        # Load configuration file and connection helper
        # Instantiate the connector helper from config
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.model_dump_pycti())

        self.sparta_interval = self.config.sparta.interval
        urls = [
            self.config.sparta.sparta_file_url,
        ]
        self.sparta_urls = list(filter(lambda url: url is not False, urls))
        self.interval = days_to_seconds(self.sparta_interval)

    def add_author(self, stix_objects):
        author = Identity(
            id="identity--f1d84ed7-5417-42e7-a76f-bd91757f336a",
            name="The Aerospace Corporation",
            identity_class="organization",
            object_marking_refs=[TLP_WHITE],
            external_references=[
                {
                    "source_name": "Aerospace Sparta Main URL",
                    "url": "https://sparta.aerospace.org/",
                }
            ],
        )
        for stix_object in stix_objects:
            stix_object["created_by_ref"] = author["id"]
        stix_objects.append(json.loads(author.serialize()))
        return stix_objects

    def add_marking_definition(self, stix_objects):
        for stix_object in stix_objects:
            stix_object["object_marking_refs"] = [str(TLP_WHITE.id)]
        stix_objects.append(json.loads(TLP_WHITE.serialize()))
        return stix_objects

    def retrieve_data(self, url: str) -> Optional[dict]:
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
            # Fetch json bundle from SPARTA
            serialized_bundle = (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
            # Convert the data to python dictionary
            stix_bundle = json.loads(serialized_bundle)
            stix_objects = stix_bundle["objects"]
            stix_objects = self.add_author(stix_objects)
            stix_objects = self.add_marking_definition(stix_objects)
            stix_bundle["objects"] = stix_objects
            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
            self.helper.metric.inc("client_error_count")
        return None

    def process_data(self):
        unixtime_now = get_unixtime_now()
        time_now = time_from_unixtime(unixtime_now)

        current_state = self.helper.get_state()
        last_run = current_state.get("last_run", None) if current_state else None
        self.helper.log_debug(f"Connector last run: {time_from_unixtime(last_run)}")

        if last_run and self.interval > unixtime_now - last_run:
            self.helper.log_debug("Connector will not run this time.")
            return

        self.helper.log_info(f"Connector will run now {time_now}.")
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        friendly_name = f"SPARTA run @ {time_now}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self.helper.log_info("Fetching SPARTA dataset...")
        for url in self.sparta_urls:
            self.helper.log_debug(f"Fetching {url}...")
            data = self.retrieve_data(url)

            if not data:
                continue

            self.helper.send_stix2_bundle(
                json.dumps(data),
                entities_types=self.helper.connect_scope,
                work_id=work_id,
            )
            self.helper.metric.inc("record_send", len(data["objects"]))

        message = f"Connector successfully run, storing last_run as {time_now}"
        self.helper.log_info(message)
        self.helper.set_state({"last_run": unixtime_now})
        self.helper.api.work.to_processed(work_id, message)

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
            return

        while True:
            try:
                self.process_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            finally:
                self.helper.metric.state("idle")
                time.sleep(60)


if __name__ == "__main__":
    try:
        spartaConnector = Sparta()
        spartaConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
