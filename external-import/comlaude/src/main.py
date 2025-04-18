"""Comlaude main integration.

isort:skip_file
"""

import datetime
import os
import sys
import time
import threading
import json
import traceback

import stix2
import yaml
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    Identity,
    Indicator,
    StixCoreRelationship,
)
from stix2 import Bundle, DomainName, TLP_AMBER

import comlaude

CONFIG_FILE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "config.yml"
)
X_OPENCTI_PREFIX = "x_opencti_"


def _format_time(utc_time):
    """
    Format the given UTC time to a specific string format.
    """
    return utc_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


# Defines a time delta of 5 minutes.
TIME_DELTA = datetime.timedelta(minutes=5)
COMLAUDE_END_TIME = _format_time(
    datetime.datetime.now(datetime.timezone.utc) - TIME_DELTA
)


def _convert_timestamp_to_zero_millisecond_format(timestamp: str) -> str:
    """
    Convert a timestamp from one format to another with zero milliseconds.
    """
    if timestamp is None:
        return None
    try:
        dt_object = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        formatted_timestamp = dt_object.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        return formatted_timestamp
    except ValueError:
        return None


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


def _deserialize_json_string(value):
    """
    Attempt to deserialize a JSON string into a Python object.

    :param value: Potentially serialized JSON string.
    :return: Deserialized Python object or the original value if deserialization fails.
    """
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _validate_required_fields(domain_object, required_fields):
    """
    Validate that all required fields are present and not empty.

    :param domain_object: Dictionary representing the domain object.
    :param required_fields: List of required fields to validate.
    :return: Boolean indicating whether all required fields are present and non-empty.
    """
    missing_fields = [
        field
        for field in required_fields
        if field not in domain_object or _is_empty(domain_object[field])
    ]
    if missing_fields:
        print(f"Skipping domain due to missing fields: {missing_fields}")
        return False
    return True


def _generate_dynamic_custom_properties(helper, domain_object, score, author_identity):
    """
    Generate custom properties for domain objects dynamically with a specific prefix.

    :param domain_object: Dictionary containing domain properties.
    :param score: Score to be assigned.
    :param author_identity: Author identity to be added to custom properties.
    :return: Tuple containing domain name and a dictionary of custom properties.
    """
    helper.log_debug(f"Generate Dynamic Properties with prefix ({X_OPENCTI_PREFIX})")
    custom_properties = {
        "x_opencti_score": score,
        "x_opencti_description": "This domain is known infrastructure managed by Comlaude.",
        "created_by_ref": author_identity.id,
    }
    required_fields = ["id", "name", "created_at", "updated_at"]
    for key, value in domain_object.items():
        if not _is_empty(value) and key in required_fields:
            # Deserialize JSON values
            value = _deserialize_json_string(value)

            # Serialize complex values as JSON
            if isinstance(value, (dict, list)):
                try:
                    custom_properties[X_OPENCTI_PREFIX + key] = json.dumps(value)
                    helper.log_debug(f"Serialized Custom Key: {X_OPENCTI_PREFIX + key}")
                except Exception as e:
                    helper.connector_logger.error(
                        "Error serializing value for key",
                        {"key": key, "error": str(e)},
                    )
            else:
                custom_properties[X_OPENCTI_PREFIX + key] = value
                helper.log_debug(f"Custom Key: {X_OPENCTI_PREFIX + key}")
    domain_name = custom_properties.pop(f"{X_OPENCTI_PREFIX}name", None)
    helper.log_debug(f"Pop domain_name: {domain_name}")
    return domain_name, custom_properties


def _create_stix_create_bundle(helper, domain_object, labels, score, author_identity):
    """
    Create a STIX bundle containing domain and indicator objects.

    :param helper: OpenCTIConnectorHelper object.
    :param domain_object: Dictionary containing domain properties.
    :param labels: List of labels to be associated with the STIX objects.
    :param score: Score to be assigned.
    :param author_identity: Identity object representing the author.
    :return: Tuple containing domain name and a list of STIX objects.
    """
    domain_name, custom_properties = _generate_dynamic_custom_properties(
        helper, domain_object, score, author_identity
    )

    helper.log_debug(f"Create STIX Domain Name object: {domain_name}")

    sco_domain_name = DomainName(
        value=domain_name,
        allow_custom=True,
        custom_properties=custom_properties,
        labels=labels,
        object_marking_refs=[TLP_AMBER["id"]],
    )
    helper.log_debug(f"Create STIX Indicator object: {domain_name}")

    start_time = _convert_timestamp_to_zero_millisecond_format(
        domain_object["created_at"]
    )
    end_time = _convert_timestamp_to_zero_millisecond_format(
        domain_object["updated_at"]
    )
    expiration = _convert_timestamp_to_zero_millisecond_format(
        domain_object["expires_at"]
    )

    # Create Indicator object
    sdo_indicator = stix2.Indicator(
        id=Indicator.generate_id(f"[domain-name:value = '{domain_name}']"),
        created=start_time,
        modified=end_time,
        valid_until=expiration,
        name=domain_name,
        description="This domain is known infrastructure managed by Comlaude.",
        pattern_type="stix",
        pattern=f"[domain-name:value = '{domain_name}']",
        valid_from=start_time,
        labels=labels,
        custom_properties=custom_properties,
        object_marking_refs=[TLP_AMBER["id"]],
        created_by_ref=author_identity.id,
    )

    # Create relationships
    sro_object = stix2.Relationship(
        id=StixCoreRelationship.generate_id(
            "based-on", sdo_indicator.id, sco_domain_name.id
        ),
        relationship_type="based-on",
        source_ref=sdo_indicator.id,
        target_ref=sco_domain_name.id,
        start_time=start_time,
        created_by_ref=author_identity.id,
    )

    helper.log_debug(f"Create relationships: {domain_name}")
    helper.log_debug(f"Bundle Objects: {domain_name}")
    return domain_name, [sco_domain_name, sdo_indicator, sro_object]


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
        self.connector_name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], self.config
        )

        # Get required configurations
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
        comlaude_score = get_config_variable(
            "COMLAUDE_SCORE", ["comlaude", "score"], self.config, isNumber=True
        )
        comlaude_labels = get_config_variable(
            "COMLAUDE_LABELS", ["comlaude", "labels"], self.config, False
        )

        # Initialize the labels attribute
        if comlaude_labels:
            self.labels = [item.strip() for item in comlaude_labels.split(",")]
        else:
            self.labels = []

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
        self.score = comlaude_score if comlaude_score else 0
        # Duration of the period in seconds between each execution (here 300s = 5 minutes).
        self.duration_period = 300

        # Initialize the identity attribute
        self.identity = stix2.Identity(
            id=Identity.generate_id(self.connector_name, "organization"),
            name=self.connector_name,
            identity_class="organization",
        )

    def _load_config(self) -> dict:
        """
        Load the configuration from the YAML file.

        :return: Configuration dictionary.
        """

        try:
            config = (
                yaml.load(open(CONFIG_FILE_PATH), Loader=yaml.FullLoader)
                if os.path.isfile(CONFIG_FILE_PATH)
                else {}
            )
            return config
        except Exception as e:
            self.helper.connector_logger.error(
                "Error loading configuration", {"error": str(e)}
            )
            raise

    def _refresh_work_id(self):
        """
        Load the configuration from the YAML file.

        :return: Configuration dictionary.
        """
        try:
            update_end_time = _format_time(
                datetime.datetime.now(datetime.timezone.utc) - TIME_DELTA
            )
            friendly_name = f"Comlaude run @ {update_end_time}"
            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
        except Exception as e:
            self.helper.connector_logger.error(
                "Error refreshing work ID", {"error": str(e)}
            )
            raise

    def _iterate_events(self):
        """
        Iterate through events from Comlaude, generate STIX bundles, and send them to OpenCTI.
        """
        required_fields = ["name", "created_at", "updated_at", "expires_at"]
        data = self.comlaude_search.results.get("data", [])
        self.helper.log_info(f"Process ({len(data)}) events.")
        if data:
            self._refresh_work_id()
            stix_objects = [self.identity]
            last_event_time = None
            try:
                for event in data:
                    # Deserialize JSON fields before validating
                    for key in event.keys():
                        event[key] = _deserialize_json_string(event[key])
                    if not _validate_required_fields(event, required_fields):
                        continue

                    domain_name, objects = _create_stix_create_bundle(
                        self.helper, event, self.labels, self.score, self.identity
                    )
                    stix_objects.extend(objects)
                    last_event_time = event.get("updated_at", None)
                    bundle = Bundle(objects=stix_objects, allow_custom=True)

                    try:
                        self.helper.send_stix2_bundle(
                            bundle.serialize(),
                            cleanup_inconsistent_bundle=True,
                            work_id=self.work_id,
                        )
                    except Exception as e:
                        self.helper.connector_logger.error(
                            "Error sending STIX bundle", {"error": str(e)}
                        )

                    # Reset the list of STIX objects for the next event
                    stix_objects = [self.identity]

                if last_event_time:
                    try:
                        # Update the state with the current timestamp
                        current_timestamp = _format_time(
                            datetime.datetime.now(datetime.timezone.utc)
                        )
                        self.helper.set_state({"last_run": current_timestamp})
                        self.helper.log_info(
                            f"State updated with last_run: {current_timestamp}"
                        )
                    except Exception as e:
                        self.helper.connector_logger.error(
                            "Error updating last_run state", {"error": str(e)}
                        )

            finally:
                # Finalisation of the job (work_id) immediately for this page
                if self.work_id is not None:
                    try:
                        self.helper.api.work.to_processed(self.work_id, "Finished")
                    except Exception as e:
                        self.helper.connector_logger.error(
                            "Error finishing work ID", {"error": str(e)}
                        )
                    self.work_id = None

    def _process_events(self):
        """
        Process events and handle exceptions.
        :return: Boolean indicating if processing was successful.
        """
        self._iterate_events()
        while self.comlaude_search.has_next:
            self.helper.log_info(
                f"Fetching next Comlaude page: {self.comlaude_search.parameters['page']}"
            )
            self.comlaude_search.get_next_page()
            self._iterate_events()
        return True

    def _ping_connector(self):
        while True:
            try:
                self.helper.force_ping()
                self.helper.log_info("Connector ping successful.")
            except Exception as e:
                self.helper.connector_logger.error(
                    "Error during connector ping", {"error": str(e)}
                )
            time.sleep(300)

    def run(self):
        """
        Main execution loop for the ComlaudeConnector.
        """
        self.helper.log_info(
            "Start Comlaude Connector ({}).".format(
                _format_time(datetime.datetime.now(datetime.timezone.utc))
            )
        )

        # Start the ping thread to keep the connector alive
        ping_thread = threading.Thread(target=self._ping_connector)
        ping_thread.daemon = True
        ping_thread.start()

        # Continuous scheduled execution
        self.helper.schedule_iso(
            message_callback=self._process_events, duration_period=self.duration_period
        )


if __name__ == "__main__":

    try:
        connector = ComlaudeConnector()
        connector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
