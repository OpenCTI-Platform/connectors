import datetime
import os
import sys
import time
from gc import collect

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from recordedfuture import RecordedFutureClient
from stix2 import Bundle

CONFIG_FILE_PATH = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
DEFAULT_CHUNK_SIZE = 1000


def _format_time(utc_time):
    """
    Format the given UTC time to a specific string format.

    :param utc_time: A datetime object representing UTC time.
    :return: Formatted string representation of the datetime object.
    """
    return utc_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


class RecordedFutureConnector:
    """
    Connector class to interface with RecordedFuture and OpenCTI platforms.
    """

    FEEDS = [
        "DOMAINS_PREVENT",
        "DOMAINS_DETECT",
        "URLS_PREVENT",
        "C2_IPS_DETECT",
        "C2_IPS_PREVENT",
        "VULNS_PATCH",
        "HASHES_PREVENT",
        "TOR_IPS",
        "EMERGING_MALWARE_HASHES",
        "RAT_CONTROLLERS_IPS",
        "FFLUX_IPS",
        "DDNS_IPS",
        "LOW_DETECT_MALWARE_HASHES",
    ]

    def __init__(self):
        """
        Initialize the RecordedFutureConnector with necessary configurations.
        """

        # Load configuration file and connection helper.
        self.config = self._load_config()
        self.helper = OpenCTIConnectorHelper(self.config)
        self._initialize_configurations()
        self.rf_client = RecordedFutureClient(
            api_token=self.rf_api_key, labels=self.labels
        )

    def _initialize_configurations(self):
        self.config_interval = get_config_variable(
            "CONFIG_INTERVAL",
            ["recordedfuture", "interval"],
            self.config,
            isNumber=True,
        )
        self.update_existing_data = get_config_variable(
            "CONFIG_UPDATE_EXISTING_DATA",
            ["recordedfuture", "update_existing_data"],
            self.config,
            isNumber=True,
        )
        for feed in self.FEEDS:
            setattr(
                self,
                f"rf_enable_{feed.lower()}",
                get_config_variable(
                    f"ENABLE_{feed}",
                    ["recordedfuture", f"enable_{feed.lower()}"],
                    self.config,
                    False,
                ),
            )
        self.rf_api_key = get_config_variable(
            "RF_API_KEY", ["recordedfuture", "api_key"], self.config, False
        )
        self.labels = get_config_variable(
            "RF_LABELS",
            ["recordedfuture", "labels"],
            self.config,
            default="recordedfuture",
        ).split(",")
        self.rf_days_threshold = get_config_variable(
            "RF_DAYS_THRESHOLD",
            ["recordedfuture", "days_threshold"],
            self.config,
            default=None,
        )

    def _load_config(self) -> dict:
        """
        Load the configuration from the YAML file.

        :return: Configuration dictionary.
        """
        config = (
            yaml.load(open(CONFIG_FILE_PATH), Loader=yaml.FullLoader)
            if os.path.isfile(CONFIG_FILE_PATH)
            else {}
        )
        return config

    def _get_interval(self):
        """
        Get the interval of execution in seconds.

        :return: Interval in seconds.
        """
        return int(self.config_interval) * 60 * 60

    def _refresh_work_id(self, feed):
        """
        Refresh the work ID for the current process.
        """
        start_time = _format_time(datetime.datetime.utcnow())
        friendly_name = f"{feed} run @ {start_time}"
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.log_debug(f"{friendly_name}")

    def _process_in_chunks(self, feed, stix_objects, chunk_size=DEFAULT_CHUNK_SIZE):
        """Iterate through stix_objects and send Stix Bundles in chunks."""
        for i in range(0, len(stix_objects), chunk_size):
            data_chunk = stix_objects[i : i + chunk_size]
            self.helper.log_debug(
                "Sending Bundle of ({}) objects for dataset ({}), index {} through {}.".format(
                    len(data_chunk), feed, i, i + chunk_size
                )
            )
            stix_bundle = Bundle(objects=data_chunk, allow_custom=True)
            self.helper.send_stix2_bundle(
                stix_bundle.serialize(),
                update=self.update_existing_data,
                work_id=self.work_id,
            )
            del data_chunk
            collect()  # Run garbage collection

    def _collect_bundle_submit(self, feed):
        self._refresh_work_id(feed)
        stix_objects = self.rf_client.fetch_data_bundle_transform(
            dataset_key=feed,
            days_threshold=self.rf_days_threshold,
            connect_confidence_level=self.helper.connect_confidence_level,
        )
        if stix_objects is not None:
            self._process_in_chunks(feed, stix_objects)
        else:
            self.helper.log_info(f"No new updates for feed ({feed})")

    def _iterate_feeds(self):
        """
        Iterate through feeds from RecordedFuture, generate STIX bundles, and send them to OpenCTI.
        """
        for feed in self.FEEDS:
            if getattr(self, f"rf_enable_{feed.lower()}"):
                self.helper.log_info(f"Feed Enabled: {feed}")
        for feed in self.FEEDS:
            if getattr(self, f"rf_enable_{feed.lower()}"):
                self._collect_bundle_submit(feed)

    def run(self):
        """
        Main execution loop for the Recorded Future Connector.
        """
        self.helper.log_info(
            "Start Recorded Future Connector ({}).".format(
                _format_time(datetime.datetime.utcnow())
            )
        )

        self._iterate_feeds()

        if self.helper.connect_run_and_terminate:
            self.helper.log_info(
                "Connector stop: ({})".format(_format_time(datetime.datetime.utcnow()))
            )
            sys.exit(0)
        # Sleep for interval specified in Hours.
        self.helper.log_info(
            "Connector Sleeping for: ({}).".format(self._get_interval())
        )
        time.sleep(self._get_interval())


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    try:
        connector = RecordedFutureConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
