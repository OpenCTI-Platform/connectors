import time
import requests
from datetime import datetime
from pycti import OpenCTIConnectorHelper, get_config_variable


class RansomFeedConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper()
        self.api_url = get_config_variable("RANSOMFEED_API_URL", ["ransomfeed", "api_url"])
        self.interval = int(get_config_variable("CONNECTOR_INTERVAL", ["connector", "interval"], default=3600))

    def get_location_id(self, country_code):
        if not country_code:
            return None
        location = self.helper.api.location.read(
            filters=[{"key": "x_opencti_aliases", "values": [country_code]}]
        )
        return location["id"] if location else None

    def process_claim(self, item):
        # External ID to avoid duplicates
        external_id = f"ransomfeed:{item['id']}"
        existing_incident = self.helper.api.stix_domain_object.read(
            filters=[{"key": "external_id", "values": [external_id]}]
        )
        if existing_incident:
            self.helper.log_info(f"Incident {external_id} already exists, skipping.")
            return

        victim = self.helper.api.identity.create(
            type="Organization",
            name=item["victim"],
            description=f"Victim of {item['gang']}",
            external_references=[{"source_name": "ransomfeed", "url": item.get("website")}],
            x_opencti_location=self.get_location_id(item.get("country"))
        )

        group = self.helper.api.intrusion_set.create(
            name=item["gang"],
            description="Ransomware group",
            aliases=[item["gang"]],
            confidence=80
        )

        incident = self.helper.api.incident.create(
            name=f"Ransomware attack on {item['victim']}",
            description=f"Claimed by {item['gang']} on {item['date']}",
            first_seen=item["date"],
            created=item["date"],
            confidence=70,
            external_id=external_id
        )

        self.helper.api.stix_core_relationship.create(
            relationship_type="targets", source_ref=incident["id"], target_ref=victim["id"]
        )
        self.helper.api.stix_core_relationship.create(
            relationship_type="attributed-to", source_ref=incident["id"], target_ref=group["id"]
        )
        self.helper.api.stix_core_relationship.create(
            relationship_type="targets", source_ref=group["id"], target_ref=victim["id"]
        )

        if item.get("hash"):
            indicator = self.helper.api.indicator.create(
                name=f"Hash of ransomware related to {item['victim']}",
                pattern_type="stix",
                pattern=f"[file:hashes.'SHA-256' = '{item['hash']}']",
                confidence=60
            )
            self.helper.api.stix_core_relationship.create(
                relationship_type="indicates", source_ref=indicator["id"], target_ref=incident["id"]
            )

    def run(self):
        self.helper.log_info("Starting RansomFeed connector...")
        while True:
            try:
                state = self.helper.get_state()
                last_run = state.get("last_run") if state else None
                self.helper.log_info(f"Last run at {last_run}")

                url = self.api_url
                if last_run:
                    url += f"?since={last_run}"

                response = requests.get(url)
                response.raise_for_status()
                data = response.json()

                if not data:
                    self.helper.log_info("No new data.")
                else:
                    for item in data:
                        self.process_claim(item)

                    latest_date = max([item["date"] for item in data])
                    self.helper.set_state({"last_run": latest_date})
                    self.helper.save_state()
                    self.helper.log_info(f"Saved last_run as {latest_date}")

            except Exception as e:
                self.helper.log_error(f"Error: {e}")

            self.helper.log_info(f"Sleeping for {self.interval} seconds...")
            time.sleep(self.interval)


if __name__ == "__main__":
    connector = RansomFeedConnector()
    connector.run()
