import datetime
import json
import threading
import time

import stix2
from comlaude import ComLaudeAuth, ComLaudeSearch
from connector.settings import ConnectorSettings
from pycti import (
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from stix2 import TLP_AMBER, Bundle, DomainName

X_OPENCTI_PREFIX = "x_opencti_"
TIME_DELTA = datetime.timedelta(minutes=5)


def _format_time(utc_time):
    """Format the given UTC time to a specific string format."""
    return utc_time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _convert_timestamp_to_zero_millisecond_format(timestamp: str | None) -> str | None:
    """Convert a timestamp to a format with zero milliseconds."""
    if timestamp is None:
        return None
    try:
        dt_object = datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        return dt_object.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    except ValueError:
        return None


def _is_empty(value):
    """Check if a given value is empty or None."""
    if value is None:
        return True
    if isinstance(value, (str, list, dict)) and not value:
        return True
    return False


def _deserialize_json_string(value):
    """Attempt to deserialize a JSON string into a Python object."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _validate_required_fields(domain_object, required_fields):
    """Validate that all required fields are present and not empty."""
    missing_fields = [
        field
        for field in required_fields
        if field not in domain_object or _is_empty(domain_object[field])
    ]
    return not missing_fields


def _generate_dynamic_custom_properties(helper, domain_object, score, author_identity):
    """Generate custom properties for domain objects dynamically."""
    helper.log_debug(f"Generate Dynamic Properties with prefix ({X_OPENCTI_PREFIX})")
    custom_properties = {
        "x_opencti_score": score,
        "x_opencti_description": "This domain is known infrastructure managed by Comlaude.",
        "x_opencti_created_by_ref": author_identity.id,
    }
    required_fields = ["id", "name", "created_at", "updated_at"]
    for key, value in domain_object.items():
        if not _is_empty(value) and key in required_fields:
            value = _deserialize_json_string(value)

            if isinstance(value, (dict, list)):
                try:
                    custom_properties[X_OPENCTI_PREFIX + key] = json.dumps(value)
                    helper.log_debug(f"Serialized Custom Key: {X_OPENCTI_PREFIX + key}")
                except Exception as e:
                    helper.connector_logger.error(
                        "Error serializing value for key",
                        meta={"key": key, "error": str(e)},
                    )
            else:
                custom_properties[X_OPENCTI_PREFIX + key] = value
                helper.log_debug(f"Custom Key: {X_OPENCTI_PREFIX + key}")

    domain_name = custom_properties.pop(f"{X_OPENCTI_PREFIX}name", None)
    helper.log_debug(f"Pop domain_name: {domain_name}")
    return domain_name, custom_properties


def _create_stix_bundle(helper, domain_object, labels, score, author_identity):
    """Create a STIX bundle containing domain and indicator objects."""
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

    start_time = _convert_timestamp_to_zero_millisecond_format(
        domain_object["created_at"]
    )
    end_time = _convert_timestamp_to_zero_millisecond_format(
        domain_object["updated_at"]
    )
    expiration = _convert_timestamp_to_zero_millisecond_format(
        domain_object["expires_at"]
    )

    escaped_domain_name = domain_name.replace("\\", "\\\\").replace("'", "\\'")
    stix_pattern = f"[domain-name:value = '{escaped_domain_name}']"
    sdo_indicator = stix2.Indicator(
        id=Indicator.generate_id(stix_pattern),
        created=start_time,
        modified=end_time,
        valid_until=expiration,
        name=domain_name,
        description="This domain is known infrastructure managed by Comlaude.",
        pattern_type="stix",
        pattern=stix_pattern,
        valid_from=start_time,
        labels=labels,
        custom_properties=custom_properties,
        object_marking_refs=[TLP_AMBER["id"]],
        created_by_ref=author_identity.id,
    )

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
    return domain_name, [sco_domain_name, sdo_indicator, sro_object]


class ComlaudeConnector:
    """Connector class to interface with Comlaude and OpenCTI platforms."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.labels = list(self.config.comlaude.labels)
        self.score = self.config.comlaude.score
        self.work_id = None

        self.identity = stix2.Identity(
            id=Identity.generate_id(self.helper.connect_name, "organization"),
            name=self.helper.connect_name,
            identity_class="organization",
        )

    def _init_comlaude_search(self):
        """Initialize the ComLaude API search client."""

        end_time = _format_time(
            datetime.datetime.now(datetime.timezone.utc) - TIME_DELTA
        )

        comlaude_auth = ComLaudeAuth(
            self.config.comlaude.username,
            self.config.comlaude.password.get_secret_value(),
            self.config.comlaude.api_key.get_secret_value(),
        )
        return ComLaudeSearch(
            comlaude_auth,
            self.config.comlaude.group_id,
            self.config.comlaude.start_time,
            end_time,
        )

    def _refresh_work_id(self):
        """Refresh the work ID for the connector."""
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
                "Error refreshing work ID", meta={"error": str(e)}
            )
            raise

    def _iterate_events(self, comlaude_search):
        """Iterate through events, generate STIX bundles, and send them to OpenCTI."""
        required_fields = ["name", "created_at", "updated_at", "expires_at"]
        data = comlaude_search.results.get("data", [])
        self.helper.log_info(f"Process ({len(data)}) events.")
        if data:
            self._refresh_work_id()
            stix_objects = [self.identity, TLP_AMBER]
            last_event_time = None
            try:
                for event in data:
                    for key in event.keys():
                        event[key] = _deserialize_json_string(event[key])
                    if not _validate_required_fields(event, required_fields):
                        continue

                    domain_name, objects = _create_stix_bundle(
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

                    stix_objects = [self.identity, TLP_AMBER]

                if last_event_time:
                    try:
                        current_timestamp = _format_time(
                            datetime.datetime.now(datetime.timezone.utc)
                        )
                        self.helper.set_state({"last_run": current_timestamp})
                        self.helper.log_info(
                            f"State updated with last_run: {current_timestamp}"
                        )
                    except Exception as e:
                        self.helper.connector_logger.error(
                            "Error updating last_run state", meta={"error": str(e)}
                        )

            finally:
                if self.work_id is not None:
                    try:
                        self.helper.api.work.to_processed(self.work_id, "Finished")
                    except Exception as e:
                        self.helper.connector_logger.error(
                            "Error finishing work ID", {"error": str(e)}
                        )
                    self.work_id = None

    def _process_events(self):
        """Process events and handle pagination."""
        comlaude_search = self._init_comlaude_search()
        self._iterate_events(comlaude_search)
        while comlaude_search.has_next:
            self.helper.log_info(
                f"Fetching next Comlaude page: {comlaude_search.parameters['page']}"
            )
            comlaude_search.get_next_page()
            self._iterate_events(comlaude_search)
        return True

    def _ping_connector(self):
        while True:
            try:
                self.helper.force_ping()
                self.helper.log_info("Connector ping successful.")
            except Exception as e:
                self.helper.connector_logger.error(
                    "Error during connector ping", meta={"error": str(e)}
                )
            time.sleep(300)

    def run(self) -> None:
        """Main execution loop for the ComlaudeConnector."""
        self.helper.log_info(
            "Start Comlaude Connector ({}).".format(
                _format_time(datetime.datetime.now(datetime.timezone.utc))
            )
        )

        ping_thread = threading.Thread(target=self._ping_connector)
        ping_thread.daemon = True
        ping_thread.start()

        self.helper.schedule_iso(
            message_callback=self._process_events,
            duration_period=self.config.connector.duration_period,
        )
