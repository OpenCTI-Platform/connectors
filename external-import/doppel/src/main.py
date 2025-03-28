import os
import time
import yaml
import json
import requests
from datetime import datetime, timedelta
from pycti import OpenCTIConnectorHelper
from stix2 import Bundle, Indicator, Identity, Note, DomainName
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import uuid

# Load configuration
CONFIG_PATH = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# OpenCTI Helper Initialization
helper = OpenCTIConnectorHelper(config["opencti"])

def get_created_after_timestamp(days):
    past_time = datetime.utcnow() - timedelta(days=days)
    return past_time.strftime("%Y-%m-%dT%H:%M:%S")

# Retry mechanism for recoverable errors
@retry(
    stop=stop_after_attempt(config["doppel"]["max_retries"]),
    wait=wait_exponential(multiplier=1, min=config["doppel"]["retry_delay"], max=60),
    retry=retry_if_exception_type(requests.RequestException),
    reraise=True
)
def fetch_alerts():
    headers = {"x-api-key": config["doppel"]["api_key"], "accept": "application/json"}
    created_after = get_created_after_timestamp(config["doppel"]["historical_polling_days"])
    params = {"created_after": created_after}
    
    helper.log_info(f"Fetching alerts from Doppel API with created_after={created_after}...")

    try:
        response = requests.get(config["doppel"]["api_url"], headers=headers, params=params)

        # Handle API key errors separately (no retry)
        if response.status_code == 401:
            helper.log_error("Authentication failed! Check your Doppel API key.")
            return []
        elif response.status_code == 403:
            helper.log_error("Access denied! Your Doppel API key might not have the right permissions.")
            return []

        response.raise_for_status()  # Raises error for 4xx/5xx except handled ones

        return response.json().get("alerts", [])

    except requests.RequestException as e:
        helper.log_error(f"Error fetching alerts: {str(e)}")
        return []

# def convert_to_stix(alerts):
#     stix_objects = []
#     for alert in alerts:
#         alert_uuid = str(uuid.uuid4())
#         identity_uuid = str(uuid.uuid4())

#         created_at = alert.get("created_at", "")
#         if created_at:
#             created_at = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%f").isoformat(timespec='seconds') + "Z"

#         entity = alert.get("entity", "Unknown")
#         pattern = f"[entity:value = '{entity}']"
        
#         indicator = Indicator(
#             id=f"indicator--{alert_uuid}",
#             name=entity,
#             pattern=pattern,
#             pattern_type="stix",
#             confidence=50 if alert.get("queue_state") == "monitoring" else 80,
#             labels=[alert.get("entity_state", "unknown"), alert.get("severity", "unknown")],
#             created=created_at,
#             external_references=[{"source_name": "Doppel", "url": alert.get("doppel_link"), "external_id": alert.get("id") }]
#         )
        
#         # identity = Identity(
#         #     id=f"identity--{identity_uuid}",
#         #     name=alert.get("brand", "Unknown"),
#         #     identity_class="organization",
#         #     description=alert.get("platform", "No platform info provided")
#         # )
        
#         note = Note(
#             id=f"note--{uuid.uuid4()}",
#             content=alert.get("audit_logs", "No audit logs available."),
#             object_refs=[indicator.id]
#         )
        
#         stix_objects.extend([indicator, identity, note])
    
#     return Bundle(objects=stix_objects).serialize() if stix_objects else None


# Define Doppel as a static identity
DOPPEL_IDENTITY = Identity(
    id=f"identity--{str(uuid.uuid4())}",  # Generate a valid UUID
    name="Doppel",
    identity_class="organization",
    description="Threat Intelligence Provider",
    allow_custom=True  # Allow custom fields in Identity
)

def convert_to_stix(alerts):
    stix_objects = [DOPPEL_IDENTITY]  # Start with Doppel identity
    created_by_ref = DOPPEL_IDENTITY.id  # Use the correct ID format

    for alert in alerts:
        alert_uuid = str(uuid.uuid4())

        created_at = alert.get("created_at", "")
        if created_at:
            created_at = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%f").isoformat(timespec='seconds') + "Z"

        entity = alert.get("entity", "Unknown")
        pattern = f"[url:value = '{entity}']" if entity.startswith("http") else f"[domain-name:value = '{entity}']"

        # Convert audit logs into a string to store in custom properties
        audit_logs = alert.get("audit_logs", [])
        audit_log_text = "\n".join([f"{log['timestamp']}: {log['type']} - {log['value']}" for log in audit_logs])

        indicator = Indicator(
            id=f"indicator--{alert_uuid}",
            name=entity,
            pattern=pattern,
            pattern_type="stix",
            confidence=50 if alert.get("queue_state") == "monitoring" else 80,
            labels=[alert.get("entity_state", "unknown"), alert.get("severity", "unknown")],
            created=created_at,
            created_by_ref=created_by_ref,  # Reference Doppel Identity
            external_references=[{
                "source_name": "Doppel",
                "url": alert.get("doppel_link"),
                "external_id": alert.get("id")
            }],
            custom_properties={  # Store additional alert details as custom properties
                "x_opencti_brand": alert.get("brand", "Unknown"),
                "x_opencti_product": alert.get("product", "Unknown"),
                "x_opencti_platform": alert.get("platform", "Unknown"),
                "x_opencti_source": alert.get("source", "Unknown"),
                "x_opencti_notes": alert.get("notes", ""),
                "x_opencti_last_activity": alert.get("last_activity_timestamp", ""),
                "x_opencti_audit_logs": audit_log_text
            },
            allow_custom=True  # Allow custom fields in Indicator
        )

        stix_objects.append(indicator)

    # ✅ Fix: Allow custom properties in Bundle
    return Bundle(objects=stix_objects, allow_custom=True).serialize() if stix_objects else None



def send_to_opencti(stix_bundle):
    try:
        print("Received STIX bundle for sending...")
        
        # Ensure the STIX bundle is a dictionary, not a JSON string
        if isinstance(stix_bundle, str):  
            print("STIX bundle is a string, attempting to parse JSON...")
            try:
                stix_bundle = json.loads(stix_bundle)  # Convert string to dict
                print("Successfully parsed STIX bundle JSON")
            except json.JSONDecodeError as e:
                print(f"JSON parsing error: {e}")
                helper.log_error(f"Failed to parse STIX bundle JSON: {str(e)}")
                return
        
        print("Checking STIX bundle structure...")
        if not stix_bundle or "type" not in stix_bundle or stix_bundle["type"] != "bundle":
            print("Invalid STIX bundle format detected!")
            helper.log_error("Invalid STIX bundle format")
            return

        print("Sending STIX bundle to OpenCTI...")
        response = helper.api.stix2.import_bundle(stix_bundle)
        print("STIX bundle sent successfully")
        helper.log_info("STIX bundle sent successfully")

        return response

    except Exception as e:
        print(f"Unexpected error while sending STIX bundle: {e}")
        helper.log_error(f"Error sending STIX bundle: {str(e)}")

# def send_to_opencti(stix_bundle):
#     try:
#         # Ensure the STIX bundle is a dictionary, not a JSON string
#         if isinstance(stix_bundle, str):  
#             stix_bundle = json.loads(stix_bundle)  # Convert string to dict

#         if "type" not in stix_bundle or stix_bundle["type"] != "bundle":
#             helper.log_error("Invalid STIX bundle format")
#             return

#         response = helper.api.stix2.import_bundle(stix_bundle)
#         helper.log_info("STIX bundle sent successfully")
#         return response
#     except json.JSONDecodeError as e:
#         helper.log_error(f"Failed to parse STIX bundle JSON: {str(e)}")
#     except Exception as e:
#         helper.log_error(f"Error sending STIX bundle: {str(e)}")


def main():
    while True:
        try:
            helper.log_info("Starting data fetch cycle...")
            print("Fetching alerts from Doppel API...")

            alerts = fetch_alerts()
            print(f"Fetched {len(alerts)} alerts from Doppel API.")

            if alerts:
                helper.log_info(f"Fetched {len(alerts)} alerts from Doppel API.")

                print("Converting alerts to STIX format...")
                stix_bundle = convert_to_stix(alerts)
                
                if stix_bundle:
                    print("STIX bundle successfully created. Sending to OpenCTI...")
                    send_to_opencti(stix_bundle)
                else:
                    print("STIX bundle creation failed, skipping sending to OpenCTI.")
                    helper.log_error("Failed to create a valid STIX bundle.")
            else:
                helper.log_info("No new alerts retrieved.")
                print("No new alerts retrieved. Sleeping until next cycle.")

            print(f"Sleeping for {config['doppel']['polling_interval']} seconds...")
            time.sleep(config["doppel"]["polling_interval"])

        except Exception as e:
            print(f"Unexpected error in main loop: {e}")
            helper.log_error(f"Unexpected error in main loop: {str(e)}")


# def main():
#     while True:
#         helper.log_info("Starting data fetch cycle...")
#         alerts = fetch_alerts()
#         print(f"Fetched {len(alerts)} alerts from Doppel API.")
        
#         if alerts:
#             helper.log_info(f"Fetched {len(alerts)} alerts from Doppel API.")
#             stix_bundle = convert_to_stix(alerts)
#             send_to_opencti(stix_bundle)
#         else:
#             helper.log_info("No new alerts retrieved.")
        
#         time.sleep(config["doppel"]["polling_interval"])

if __name__ == "__main__":
    helper.log_info("Starting Doppel OpenCTI Connector...")
    main()
