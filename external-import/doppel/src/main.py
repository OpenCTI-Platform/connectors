import time
import yaml
from doppel_api import fetch_alerts
from stix_converter import convert_to_stix
# from opencti_client import send_to_opencti

# Load configuration from config.yaml
with open("config/config.yaml", "r") as f:
    config = yaml.safe_load(f)

POLLING_INTERVAL = config.get("polling_interval", 3600)  # Default to 3600s (60 min) if not set

def main():
    while True:
        print("\n📡 Fetching alerts from Doppel API...")
        alerts = fetch_alerts()

        if alerts:
            print(f"Retrieved {len(alerts.get('alerts', []))} alerts.\n")
            
            for alert in alerts.get("alerts", []):
                print(f"Processing Alert ID: {alert.get('id', 'Unknown')} - {alert.get('entity', 'No Entity')}")
                print(f"Raw Alert Data: {alert}\n")  # Prints full alert JSON for debugging

                # Convert alert to STIX
                stix_bundle = convert_to_stix(alert)
                if stix_bundle:
                    print(f"STIX Bundle Generated: {stix_bundle}\n")

                    # Send to OpenCTI
                    print(f"🚀 Sending Alert ID {alert.get('id')} to OpenCTI...")
                    # send_to_opencti(stix_bundle)
                    print(f"Successfully sent Alert ID {alert.get('id')} to OpenCTI.\n")
                else:
                    print(f"STIX Bundle conversion failed for Alert ID {alert.get('id')}.")

        else:
            print("No new alerts retrieved.")

        print(f"Sleeping for {POLLING_INTERVAL} seconds before next fetch...\n")
        time.sleep(POLLING_INTERVAL)

if __name__ == "__main__":
    print("Starting Doppel OpenCTI Connector...")
    main()
