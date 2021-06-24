import yaml
import os
import requests

from pycti import OpenCTIConnectorHelper, get_config_variable


class AbuseIPDBConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.api_key = get_config_variable(
            "ABUSEIPDB_API_KEY", ["abuseipdb", "api_key"], config
        )
        self.max_tlp = get_config_variable(
            "ABUSEIPDB_MAX_TLP", ["abuseipdb", "max_tlp"], config
        )
        self.whitelist_label = self.helper.api.label.create(
            value="whitelist", color="#4caf50"
        )

    @staticmethod
    def extract_abuse_ipdb_category(category_number):
        # Reference: https://www.abuseipdb.com/categories
        mapping = {
            "3": "Fraud Orders",
            "4": "DDOS Attack",
            "5": "FTP Brute-Force",
            "6": "Ping of Death",
            "7": "Phishing",
            "8": "Fraud VOIP",
            "9": "Open Proxy",
            "10": "Web Spam",
            "11": "Email Spam",
            "12": "Blog Spam",
            "13": "VPN IP",
            "14": "Port Scan",
            "15": "Hacking",
            "16": "SQL Injection",
            "17": "Spoofing",
            "18": "Brute Force",
            "19": "Bad Web Bot",
            "20": "Exploited Host",
            "21": "Web App Attack",
            "22": "SSH",
            "23": "IoT Targeted",
        }
        return mapping.get(str(category_number), "unknown category")

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        # Extract TLP
        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        # Extract IP from entity data
        observable_id = observable["standard_id"]
        observable_value = observable["value"]
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Key": "%s" % self.api_key,
        }
        params = {"maxAgeInDays": 365, "verbose": "True", "ipAddress": observable_value}
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()
        data = data["data"]
        self.helper.api.stix_cyber_observable.update_field(
            id=observable_id,
            key="x_opencti_score",
            value=str(data["abuseConfidenceScore"]),
        )
        if data["isWhitelisted"]:
            external_reference = self.helper.api.external_reference.create(
                source_name="AbuseIPDB (whitelist)",
                url="https://www.abuseipdb.com/check/" + observable_value,
                description="This IP address is from within our whitelist.",
            )
            self.helper.api.stix_cyber_observable.add_external_reference(
                id=observable_id, external_reference_id=external_reference["id"]
            )
            self.helper.api.stix_cyber_observable.add_label(
                id=observable_id, label_id=self.whitelist_label["id"]
            )
            return "IP found in AbuseIPDB WHITELIST."
        if len(data["reports"]) > 0:
            for report in data["reports"]:
                country = self.helper.api.location.read(
                    filters=[
                        {
                            "key": "x_opencti_aliases",
                            "values": [report["reporterCountryCode"]],
                        }
                    ],
                    getAll=True,
                )
                if country is None:
                    self.helper.log_warning(
                        f"No country found with Alpha 2 code {report['reporterCountryCode']}"
                    )
                else:
                    self.helper.api.stix_sighting_relationship.create(
                        fromId=observable_id,
                        toId=country["id"],
                        count=1,
                        first_seen=report["reportedAt"],
                        last_seen=report["reportedAt"],
                    )
                for category in report["categories"]:
                    category_text = self.extract_abuse_ipdb_category(category)
                    label = self.helper.api.label.create(value=category_text)
                    self.helper.api.stix_cyber_observable.add_label(
                        id=observable_id, label_id=label["id"]
                    )
            return "IP found in AbuseIPDB with reports, knowledge attached."

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    abuseIPDBInstance = AbuseIPDBConnector()
    abuseIPDBInstance.start()
