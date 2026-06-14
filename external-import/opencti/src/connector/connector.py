import json
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone

from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


class OpenCTI:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.config_interval = self.config.config.interval
        self.remove_creator = self.config.config.remove_creator
        urls = [
            self.config.config.sectors_file_url,
            self.config.config.geography_file_url,
            self.config.config.companies_file_url,
        ]
        # Drop disabled-by-config entries. Disabled URLs land as the
        # empty string ``""`` after the Pydantic ``BeforeValidator`` in
        # ``settings.py`` normalises every documented disable sentinel
        # (real YAML ``false``, env-var ``"false"`` in any casing, an
        # explicit YAML null value - key present with no value, which
        # PyYAML surfaces as Python ``None`` - and any empty /
        # whitespace-only string), so a plain truthy filter is enough
        # here.
        self.urls = [url for url in urls if url]
        self.interval = days_to_seconds(self.config_interval)

    def retrieve_data(self, url: str) -> dict:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        dict
            A bundle in dict
        """
        try:
            return json.loads(
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

    def creator_removal(self, bundle: dict) -> dict:
        for obj in bundle["objects"]:
            if "created_by_ref" in obj:
                del obj["created_by_ref"]
        return bundle

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
            if last_run is None or timestamp - last_run > self.interval:
                now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                friendly_name = "OpenCTI datasets run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = None
                in_error = False
                # Default message in case the run is interrupted before either
                # the success or the error branch reassigns it.
                message = "Connector run interrupted"
                # Close the work in a finally block: with is_multipart=True the
                # work only completes on the explicit to_processed call, so an
                # exception after initiate_work (e.g. set_state failing) would
                # otherwise leave it stuck "in-progress" forever.
                try:
                    # is_multipart=True: each url pushes its own bundle (and
                    # send_stix2_bundle can split one), so the work must only
                    # complete on the to_processed call in the finally block.
                    work_id = self.helper.api.work.initiate_work(
                        self.helper.connect_id, friendly_name, is_multipart=True
                    )
                    for url in self.urls:
                        try:
                            data = self.retrieve_data(url)
                            if self.remove_creator:
                                data = self.creator_removal(data)
                            self.send_bundle(work_id, data)
                        except Exception as e:
                            self.helper.log_error(str(e))
                    message = (
                        f"Connector successfully run, storing last_run as {timestamp}"
                    )
                    self.helper.log_info(message)
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "Last_run stored, next run in: "
                        + str(round(self.interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                except (KeyboardInterrupt, SystemExit):
                    # The work is closed in the finally block, so flag the
                    # interrupted run as in_error before re-raising instead of
                    # letting it be reported as a successful run.
                    in_error = True
                    message = "Connector stopped"
                    self.helper.log_info(message)
                    raise
                except Exception as e:
                    in_error = True
                    message = str(e)
                    self.helper.log_error(message)
                finally:
                    if work_id is not None:
                        self.helper.api.work.to_processed(
                            work_id, message, in_error=in_error
                        )
            else:
                new_interval = self.interval - (timestamp - last_run)
                self.helper.log_info(
                    "Connector will not run, next run in: "
                    + str(round(new_interval / 60 / 60 / 24, 2))
                    + " days"
                )
        except (KeyboardInterrupt, SystemExit):
            self.helper.log_info("Connector stop")
            sys.exit(0)
        except Exception as e:
            self.helper.log_error(str(e))

    def send_bundle(self, work_id: str, data: dict) -> None:
        try:
            self.helper.send_stix2_bundle(
                json.dumps(data),
                entities_types=self.helper.connect_scope,
                update=True,
                work_id=work_id,
            )
        except Exception as e:
            self.helper.log_error(f"Error while sending bundle: {e}")

    def run(self):
        self.helper.log_info("Fetching OpenCTI datasets...")
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)
        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
        else:
            while True:
                self.process_data()
                time.sleep(60)
