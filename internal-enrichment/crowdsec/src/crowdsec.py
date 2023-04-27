import itertools
import os
import re
from time import sleep
from typing import Dict
from urllib.parse import urljoin

import pycountry
import requests
import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
find_all_cve = CVE_REGEX.findall


class QuotaExceedException(Exception):
    pass


class CrowdSecConnector:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.crowdsec_cti_key = get_config_variable(
            "CROWDSEC_KEY", ["crowdsec", "key"], config
        )
        self.crowdsec_api_version = get_config_variable(
            "CROWDSEC_VERSION", ["crowdsec", "api_version"], config, default="v1"
        )
        self.crowdsec_ent_name = get_config_variable(
            "CROWDSEC_NAME", ["crowdsec", "name"], config
        )
        self.crowdsec_ent_desc = get_config_variable(
            "CROWDSEC_DESCRIPTION", ["crowdsec", "description"], config
        )
        self.max_tlp = get_config_variable(
            "CROWDSEC_MAX_TLP", ["crowdsec", "max_tlp"], config
        )

        if self.crowdsec_api_version != "v2":
            raise Exception(
                f"crowdsec api version '{self.crowdsec_api_version}' is not supported "
            )
        else:
            self.api_base_url = (
                f"https://cti.api.crowdsec.net/{self.crowdsec_api_version}/"
            )

    def get_crowdsec_cti_for_ip(self, ip):
        for i in itertools.count(1, 1):
            resp = requests.get(
                urljoin(self.api_base_url, f"smoke/{ip}"),
                headers={
                    "x-api-key": self.crowdsec_cti_key,
                    "User-Agent": "crowdsec-opencti/v1.0.0",
                },
            )
            if resp.status_code == 404:
                return {}
            elif resp.status_code == 429:
                raise QuotaExceedException(
                    "Quota exceeded for CrowdSec CTI API. Please visit https://www.crowdsec.net/pricing to upgrade your plan."
                )
            elif resp.status_code == 200:
                return resp.json()
            else:
                self.helper.log_info(f"CrowdSec CTI response {resp.text}")
                self.helper.log_warning(
                    f"CrowdSec CTI returned {resp.status_code} response status code. Retrying.."
                )
            sleep(2**i)

    def get_or_create_crowdsec_ent_id(self) -> int:
        if getattr(self, "crowdsec_id", None) is not None:
            return self.crowdsec_id
        crowdsec_ent = self.helper.api.stix_domain_object.get_by_stix_id_or_name(
            name=self.crowdsec_ent_name
        )
        if not crowdsec_ent:
            self.crowdsec_id = self.helper.api.identity.create(
                type="Organization",
                name=self.crowdsec_ent_name,
                description=self.crowdsec_ent_desc,
            )["id"]
        else:
            self.crowdsec_id = crowdsec_ent["id"]
        return self.crowdsec_id

    def enrich_observable_with_crowdsec(self, observable):
        observable_id = observable["standard_id"]
        ip = observable["value"]

        try:
            cti_data = self.get_crowdsec_cti_for_ip(ip)
        except QuotaExceedException as e:
            raise e

        if not cti_data:
            return

        external_reference = self.helper.api.external_reference.create(
            source_name="CrowdSec CTI",
            url=urljoin(self.api_base_url, f"smoke/{ip}"),
            description="This IP address is from within CrowdSec CTI",
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=observable_id, external_reference_id=external_reference["id"]
        )
        self.helper.api.stix_sighting_relationship.create(
            fromId=observable["id"],
            toId=self.get_or_create_crowdsec_ent_id(),
            createdBy=self.get_or_create_crowdsec_ent_id(),
            description=self.crowdsec_ent_desc,
            first_seen=cti_data["history"]["first_seen"],
            last_seen=cti_data["history"]["last_seen"],
            confidence=self.helper.connect_confidence_level,
            externalReferences=[external_reference["id"]],
            count=1,
        )
        labels = [attack["label"] for attack in cti_data["attack_details"]]
        scenarios = [attack["name"] for attack in cti_data["attack_details"]]
        labels.extend(scenarios)
        for label in labels:
            label_id = self.helper.api.label.create(value=label)["id"]
            self.helper.api.stix_cyber_observable.add_label(
                id=observable_id, label_id=label_id
            )

        for scenario in scenarios:
            cves = find_all_cve(scenario)
            for cve in cves:
                vuln = self.helper.api.vulnerability.create(name=cve.upper())
                self.helper.api.stix_core_relationship.create(
                    fromId=observable["id"],
                    toId=vuln["id"],
                    relationship_type="related-to",
                    update=True,
                    first_seen=cti_data["history"]["first_seen"],
                    last_seen=cti_data["history"]["last_seen"],
                    confidence=self.helper.connect_confidence_level,
                )
        for country_alpha_2, val in cti_data["target_countries"].items():
            country_info = pycountry.countries.get(alpha_2=country_alpha_2)
            country = self.helper.api.location.create(
                name=country_info.name,
                type="Country",
                country=country_info.official_name
                if hasattr(country_info, "official_name")
                else country_info.name,
                custom_properties={
                    "x_opencti_location_type": "Country",
                    "x_opencti_aliases": [
                        country_info.official_name
                        if hasattr(country_info, "official_name")
                        else country_info.name
                    ],
                },
            )
            self.helper.api.stix_sighting_relationship.create(
                fromId=observable_id,
                toId=country["id"],
                count=val,
                confidence=self.helper.connect_confidence_level,
            )
        return f"{ip} found in CrowdSec CTI. Enrichment complete"

    def _process_message(self, data: Dict) -> str:
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_cyber_observable.read(id=entity_id)
        if observable is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )

        tlp = "TLP:WHITE"
        for marking_definition in observable["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )
        self.enrich_observable_with_crowdsec(observable)

    def start(self) -> None:
        self.helper.log_info("CrowdSec connector started")
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        crowdsec_connector = CrowdSecConnector()
        crowdsec_connector.start()
    except Exception as e:
        print(e)
        sleep(10)
        exit(0)
