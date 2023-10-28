import os
from collections import defaultdict

import requests
import stix2
import yaml
from dateutil.parser import parse
from pycti import (
    STIX_EXT_OCTI_SCO,
    Location,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixSightingRelationship,
    get_config_variable,
)


class AbuseIPDBConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config, True)
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
        opencti_entity = self.helper.api.stix_cyber_observable.read(
            id=data["entity_id"]
        )
        if opencti_entity is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )
        result = self.helper.get_data_from_enrichment(data, opencti_entity)
        stix_objects = result["stix_objects"]
        stix_entity = result["stix_entity"]

        # Extract TLP
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        # Extract IP from entity data
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Key": "%s" % self.api_key,
        }
        params = {
            "maxAgeInDays": 365,
            "verbose": "True",
            "ipAddress": stix_entity["value"],
        }
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        data = r.json()
        data = data["data"]

        if data["isWhitelisted"]:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", data["abuseConfidenceScore"]
            )
            # External references
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "external_references",
                {
                    "source_name": "AbuseIPDB (whitelist)",
                    "url": "https://www.abuseipdb.com/check/"
                    + opencti_entity["observable_value"],
                    "description": "This IP address is from within our whitelist.",
                },
                True,
            )
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                self.whitelist_label["value"],
                True,
            )
        elif len(data["reports"]) > 0:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", data["abuseConfidenceScore"]
            )
            found = []
            cl = defaultdict(dict)
            for report in data["reports"]:
                countryN = report["reporterCountryCode"]
                if countryN in cl:
                    cl[countryN]["count"] += 1
                    cl[countryN]["firstseen"] = report["reportedAt"]
                else:
                    cl[countryN]["count"] = 1
                    cl[countryN]["firstseen"] = report["reportedAt"]
                    cl[countryN]["lastseen"] = report["reportedAt"]

                for category in report["categories"]:
                    if category not in found:
                        found.append(category)
                        category_text = self.extract_abuse_ipdb_category(category)
                        OpenCTIStix2.put_attribute_in_extension(
                            stix_entity,
                            STIX_EXT_OCTI_SCO,
                            "labels",
                            category_text,
                            True,
                        )

            for ckey in list(cl.keys()):
                country_location = stix2.Location(
                    id=Location.generate_id(ckey, "Country"),
                    name=ckey,
                    country=ckey,
                    custom_properties={
                        "x_opencti_location_type": "Country",
                        "x_opencti_aliases": [ckey],
                    },
                )
                stix_objects.append(country_location)
                fake_indicator_id = "indicator--c1034564-a9fb-429b-a1c1-c80116cc8e1e"
                sighting = stix2.Sighting(
                    id=StixSightingRelationship.generate_id(
                        stix_entity["id"],
                        country_location.id,
                        parse(cl[ckey]["firstseen"]),
                        parse(cl[ckey]["lastseen"]),
                    ),
                    sighting_of_ref=fake_indicator_id,
                    custom_properties={"x_opencti_sighting_of_ref": stix_entity["id"]},
                    where_sighted_refs=[country_location.id],
                    count=cl[ckey]["count"],
                    first_seen=parse(cl[ckey]["firstseen"]),
                    last_seen=parse(cl[ckey]["lastseen"]),
                )
                stix_objects.append(sighting)
        serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(serialized_bundle)
        return "IP found in AbuseIPDB, knowledge attached."

    # Start the main loop
    def start(self):
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    abuseIPDBInstance = AbuseIPDBConnector()
    abuseIPDBInstance.start()
