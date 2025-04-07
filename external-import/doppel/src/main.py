import os
import time
import yaml
import json
import requests
from datetime import datetime, timedelta, timezone
from pycti import OpenCTIConnectorHelper
from stix2 import Bundle, Indicator, Identity
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type, before_sleep_log
import uuid

# Load configuration
CONFIG_PATH = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
config = yaml.safe_load(open(CONFIG_PATH, "r")) if os.path.isfile(CONFIG_PATH) else {}

# OpenCTI Helper Initialization
helper = OpenCTIConnectorHelper(config)


def get_config_variable(env_var, config_keys, config, required=False):
    value = os.getenv(env_var)
    if value is not None:
        return value

    temp = config
    for key in config_keys:
        temp = temp.get(key, None)
        if temp is None:
            break

    if temp is not None:
        return temp

    if required:
        raise ValueError(f"Missing required config variable: {env_var} or {'.'.join(config_keys)}")

    return None


# Retrieve configuration variables
API_URL = get_config_variable("DOPPEL_API_URL", ["doppel", "api_url"], config, True)
API_KEY = get_config_variable("DOPPEL_API_KEY", ["doppel", "api_key"], config, True)
HISTORICAL_POLLING_DAYS = int(get_config_variable("HISTORICAL_POLLING_DAYS", ["doppel", "historical_polling_days"], config, True))
POLLING_INTERVAL = int(get_config_variable("POLLING_INTERVAL", ["doppel", "polling_interval"], config, True))
MAX_RETRIES = int(get_config_variable("MAX_RETRIES", ["doppel", "max_retries"], config, True))
RETRY_DELAY = int(get_config_variable("RETRY_DELAY", ["doppel", "retry_delay"], config, True))
UPDATE_EXISTING_DATA = get_config_variable("UPDATE_EXISTING_DATA", ["doppel", "update_existing_data"], config, False)
UPDATE_EXISTING_DATA = UPDATE_EXISTING_DATA.lower() == "true" if isinstance(UPDATE_EXISTING_DATA, str) else bool(UPDATE_EXISTING_DATA)


def get_created_after_timestamp(days):
    past_time = datetime.now(timezone.utc) - timedelta(days=days)
    return past_time.strftime("%Y-%m-%dT%H:%M:%S")


def log_retry(retry_state):
    helper.log_info(
        f"Retrying fetch_alerts (attempt #{retry_state.attempt_number}) "
        f"after exception: {retry_state.outcome.exception()}. "
        f"Sleeping {retry_state.next_action.sleep} seconds..."
    )


@retry(
    stop=stop_after_attempt(MAX_RETRIES),
    wait=wait_exponential(multiplier=1, min=RETRY_DELAY, max=60),
    retry=retry_if_exception_type(requests.RequestException),
    before_sleep=log_retry,
    reraise=True
)
def fetch_alerts():
    headers = {"x-api-key": API_KEY, "accept": "application/json"}
    created_after = get_created_after_timestamp(HISTORICAL_POLLING_DAYS)
    params = {"created_after": created_after}

    helper.log_info(f"Fetching alerts from Doppel API with created_after={created_after}...")

    try:
        response = requests.get(API_URL, headers=headers, params=params)

        if response.status_code == 400:
            helper.log_error("Check for invalid API or token.")
            return []
        elif response.status_code == 401:
            helper.log_error("Authentication failed! Check your Doppel API key.")
            return []
        elif response.status_code == 403:
            helper.log_error("Access denied! Your Doppel API key might not have the right permissions.")
            return []

        response.raise_for_status()
        return response.json().get("alerts", [])

    except requests.RequestException as e:
        helper.log_error(f"Error fetching alerts: {str(e)}")
        raise  # Let Tenacity catch it and retry


DOPPEL_IDENTITY = Identity(
    id=f"identity--{str(uuid.uuid4())}",
    name="Doppel",
    identity_class="organization",
    description="Threat Intelligence Provider",
    allow_custom=True
)


def convert_to_stix(alerts):
    stix_objects = [DOPPEL_IDENTITY]
    created_by_ref = DOPPEL_IDENTITY.id

    for alert in alerts:
        alert_uuid = str(uuid.uuid4())
        helper.log_info(f"Processing alert ID: {alert.get('id', 'Unknown')}")

        created_at = alert.get("created_at", "")
        if created_at:
            try:
                created_at = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%f").isoformat(timespec='seconds') + "Z"
            except ValueError as e:
                helper.log_error(f"Failed to parse created_at for alert ID {alert.get('id', 'Unknown')}: {str(e)}")
                created_at = ""

        entity = alert.get("entity", "Unknown")
        pattern = f"[entity:value = '{entity}']"

        audit_logs = alert.get("audit_logs", [])
        audit_log_text = "\n".join([f"{log['timestamp']}: {log['type']} - {log['value']}" for log in audit_logs])

        entity_content = alert.get("entity_content", {})

        entity_state = alert.get("entity_state", "unknown")
        severity = alert.get("severity", "unknown")
        queue_state = alert.get("queue_state", "unknown")
        labels = [queue_state, entity_state, severity]

        indicator = Indicator(
            id=f"indicator--{alert_uuid}",
            name=entity,
            pattern=pattern,
            pattern_type="stix",
            confidence=50 if alert.get("queue_state") == "monitoring" else 80,
            labels=labels,
            created=created_at,
            created_by_ref=created_by_ref,
            external_references=[{
                "source_name": "Doppel",
                "url": alert.get("doppel_link"),
                "external_id": alert.get("id")
            }],
            custom_properties={
                "x_opencti_brand": alert.get("brand", "Unknown"),
                "x_opencti_product": alert.get("product", "Unknown"),
                "x_opencti_platform": alert.get("platform", "Unknown"),
                "x_opencti_source": alert.get("source", "Unknown"),
                "x_opencti_notes": alert.get("notes", ""),
                "x_opencti_last_activity": alert.get("last_activity_timestamp", ""),
                "x_opencti_audit_logs": audit_log_text,
                "x_opencti_entity_content": entity_content
            },
            allow_custom=True
        )
        stix_objects.append(indicator)

    return Bundle(objects=stix_objects, allow_custom=True).serialize() if stix_objects else None


def send_to_opencti(stix_bundle):
    try:
        if isinstance(stix_bundle, dict):
            stix_bundle = json.dumps(stix_bundle)

        if not stix_bundle:
            helper.log_error("STIX bundle is empty or invalid.")
            return

        bundle_dict = json.loads(stix_bundle)
        helper.log_info(f"Sending STIX bundle with {len(bundle_dict.get('objects', []))} objects to OpenCTI.")
        response = helper.send_stix2_bundle(
            stix_bundle,
            update=UPDATE_EXISTING_DATA
        )
        helper.log_info("STIX bundle sent successfully")

    except Exception as e:
        helper.log_error(f"Error sending STIX bundle: {str(e)}")


def main():
    while True:
        try:
            helper.log_info("Starting data fetch cycle...")
            alerts = fetch_alerts()
            if alerts:
                stix_bundle = convert_to_stix(alerts)
                if stix_bundle:
                    send_to_opencti(stix_bundle)
                else:
                    helper.log_error("Failed to create a valid STIX bundle.")

            helper.log_info(f"Sleeping for {POLLING_INTERVAL} seconds before next fetch...")
            time.sleep(POLLING_INTERVAL)
        except Exception as e:
            helper.log_error(f"Unexpected error in main loop: {str(e)}")


if __name__ == "__main__":
    helper.log_info("Starting Doppel OpenCTI Connector...")
    main()
