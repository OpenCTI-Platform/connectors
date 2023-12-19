""" Comlaude main integration.

   isort:skip_file
"""
import datetime
import os
import sys
import time

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, DomainName, Indicator

import comlaude

CONFIG_FILE_PATH = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
X_OPENCTI_PREFIX = "x_opencti_"


def _format_time(utc_time):
    """
    Format the given UTC time to a specific string format.

    :param utc_time: A datetime object representing UTC time.
    :return: Formatted string representation of the datetime object.
    """
    return utc_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


# Defines a time delta of 5 minutes.
TIME_DELTA = datetime.timedelta(minutes=5)
COMLAUDE_END_TIME = _format_time(datetime.datetime.utcnow() - TIME_DELTA)


def _convert_timestamp_to_zero_millisecond_format(timestamp: str) -> str:
    """
    Convert a timestamp from one format to another with zero milliseconds.

    :param timestamp: String representing the timestamp in "%Y-%m-%dT%H:%M:%SZ".
    :return: String timestamp with zero milliseconds in "%Y-%m-%dT%H:%M:%S.000000Z".
    """
    dt_object = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
    return dt_object.strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def _is_empty(value):
    """
    Check if a given value is empty or None.

    :param value: Value to be checked.
    :return: Boolean value, True if value is empty/None, otherwise False.
    """
    if value is None:
        return True
    if isinstance(value, (str, list, dict)) and not value:
        return True
    return False


def _generate_dynamic_custom_properties(helper, domain_object):
    """
    Generate custom properties for domain objects dynamically with a specific prefix.

    :param helper: OpenCTIConnectorHelper object.
    :param domain_object: Dictionary containing domain properties.
    :return: Tuple containing domain name and a dictionary of custom properties.
    """
    helper.log_debug(f"Generate Dynamic Properties with prefix ({X_OPENCTI_PREFIX})")
    custom_properties = {}
    for key, value in domain_object.items():
        if not _is_empty(value):
            custom_key = X_OPENCTI_PREFIX + key
            custom_properties[custom_key] = value
            helper.log_debug(f"Custom Key: {custom_key}")
    domain_name = custom_properties.pop(f"{X_OPENCTI_PREFIX}name", None)
    helper.log_debug(f"Pop domain_name: {domain_name}")
    return domain_name, custom_properties


def _create_stix_create_bundle(helper, domain_object, labels):
    """
    Create a STIX bundle containing domain and indicator objects.

    :param helper: OpenCTIConnectorHelper object.
    :param domain_object: Dictionary containing domain properties.
    :param labels: List of labels to be associated with the STIX objects.
    :return: Tuple containing domain name and a list of STIX objects.
    """
    domain_name, custom_properties = _generate_dynamic_custom_properties(
        helper, domain_object
    )
    helper.log_debug(f"Create STIX Domain Name object: {domain_name}")

    # Create DomainName object
    sco_domain_name = DomainName(
        value=domain_name,
        type="domain-name",
        allow_custom=True,
        custom_properties=custom_properties,
        labels=labels,
    )
    helper.log_debug(f"Create STIX Indicator object: {domain_name}")

    # Create Indicator object
    sdo_indicator = Indicator(
        created=_convert_timestamp_to_zero_millisecond_format(
            domain_object["created_at"]
        ),
        modified=_convert_timestamp_to_zero_millisecond_format(
            domain_object["updated_at"]
        ),
        name=domain_name,
        description="This domain is known infrastructure managed by Comlaude.",
        pattern_type="stix",
        pattern=f"[domain-name:value = '{domain_name}']",
        valid_from=_convert_timestamp_to_zero_millisecond_format(
            domain_object["created_at"]
        ),
        labels=labels,
    )

    helper.log_debug(f"Create relationships: {domain_name}")
    helper.log_debug(f"Bundle Objects: {domain_name}")
    return domain_name, [sco_domain_name, sdo_indicator]


class ComlaudeConnector:
    """
    Connector class to interface with Comlaude and OpenCTI platforms.
    """

    def __init__(self):
        """
        Initialize the ComlaudeConnector with necessary configurations.
        """

        # Load configuration file and connection helper.
        self.config = self._load_config()
        self.helper = OpenCTIConnectorHelper(self.config)

        # Get required configurations
        self.config_interval = get_config_variable(
            "CONFIG_INTERVAL", ["comlaude", "interval"], self.config, isNumber=True
        )
        self.update_existing_data = get_config_variable(
            "CONFIG_UPDATE_EXISTING_DATA",
            ["comlaude", "update_existing_data"],
            self.config,
            isNumber=True,
        )
        comlaude_username = get_config_variable(
            "COMLAUDE_USERNAME", ["comlaude", "username"], self.config, False
        )
        comlaude_password = get_config_variable(
            "COMLAUDE_PASSWORD", ["comlaude", "password"], self.config, False
        )
        comlaude_api_key = get_config_variable(
            "COMLAUDE_API_KEY", ["comlaude", "api_key"], self.config, False
        )
        comlaude_group_id = get_config_variable(
            "COMLAUDE_GROUP_ID", ["comlaude", "group_id"], self.config, False
        )
        comlaude_start_time = get_config_variable(
            "COMLAUDE_START_TIME", ["comlaude", "start_time"], self.config, False
        )

        comlaude_labels = get_config_variable(
            "COMLAUDE_LABELS", ["comlaude", "labels"], self.config, False
        )

        # Authenticate with Comlaude.
        comlaude_auth_token = comlaude.ComLaudeAuth(
            comlaude_username, comlaude_password, comlaude_api_key
        )

        self.comlaude_search = comlaude.ComLaudeSearch(
            comlaude_auth_token,
            comlaude_group_id,
            comlaude_start_time,
            COMLAUDE_END_TIME,
        )

        self.work_id = None
        self.labels = comlaude_labels.split(",")

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

    def _refresh_work_id(self):
        """
        Refresh the work ID for the current process.
        """
        update_end_time = _format_time(datetime.datetime.utcnow() - TIME_DELTA)
        friendly_name = f"Comlaude run @ {update_end_time}"
        self.work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )
        self.helper.log_info(f"{friendly_name}")

    def _iterate_events(self):
        """
        Iterate through events from Comlaude, generate STIX bundles, and send them to OpenCTI.
        """
        self.helper.log_info(
            "Process ({}) events.".format(len(self.comlaude_search.results["data"]))
        )
        if len(self.comlaude_search.results["data"]) > 0:
            self._refresh_work_id()
            stix_objects = []
            for event in self.comlaude_search.results["data"]:
                domain_name, objects = _create_stix_create_bundle(
                    self.helper, event, self.labels
                )
                self.helper.log_debug(f"Adding Stix Objects for ({domain_name}).")
                stix_objects.extend(objects)
            bundle = Bundle(objects=stix_objects, allow_custom=True)
            self.helper.log_info(
                "Sending Bundle of ({}) events.".format(
                    len(self.comlaude_search.results["data"])
                )
            )
            self.helper.send_stix2_bundle(
                bundle.serialize(),
                update=self.update_existing_data,
                work_id=self.work_id,
            )

    def run(self):
        """
        Main execution loop for the ComlaudeConnector.
        """
        self.helper.log_info(
            "Start Comluade Connector ({}).".format(
                _format_time(datetime.datetime.utcnow())
            )
        )
        self._iterate_events()
        while self.comlaude_search.has_next:
            # Get next events and send data.
            self.helper.log_info(
                "Starting to update Comlaude page: ({}).".format(
                    self.comlaude_search.parameters["page"]
                )
            )
            self.comlaude_search.get_next_page()
            self._iterate_events()

        if self.helper.connect_run_and_terminate:
            self.helper.log_info(
                "Connector stop: ({})".format(_format_time(datetime.datetime.utcnow()))
            )
            self.helper.force_ping()
            sys.exit(0)
        # Sleep for interval specified in Hours.
        time.sleep(self._get_interval())


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    try:
        connector = ComlaudeConnector()
        connector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
